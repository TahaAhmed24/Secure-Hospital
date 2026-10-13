#!/bin/sh
set -e

# HSM Configuration
TOKEN_LABEL="${TOKEN_LABEL:-security-server}"
SO_PIN="1234"
USER_PIN="${HSM_PIN:-5678}"
KEY_LABEL="signing-key"
KEY_SIZE=2048
SOFTHSM_MODULE="${SOFTHSM_MODULE:-/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so}"

# Ensure SOFTHSM2_CONF is set
export SOFTHSM2_CONF="${SOFTHSM2_CONF:-/etc/softhsm/softhsm2.conf}"

echo "Waiting for MySQL to be ready..."
while ! nc -z db 3306; do
  sleep 1
done
echo "MySQL is ready!"

echo "=== SoftHSM Setup ==="
echo "SOFTHSM2_CONF: $SOFTHSM2_CONF"
echo "Checking if config file exists..."

if [ ! -f "$SOFTHSM2_CONF" ]; then
  echo "Creating SoftHSM config file..."
  mkdir -p $(dirname "$SOFTHSM2_CONF")
  cat > "$SOFTHSM2_CONF" << EOF
directories.tokendir = /var/lib/softhsm/tokens
objectstore.backend = file
log.level = INFO
EOF
  echo "Config file created at: $SOFTHSM2_CONF"
fi

echo "Config file contents:"
cat "$SOFTHSM2_CONF"

# Verify token directory exists
if [ ! -d /var/lib/softhsm/tokens ]; then
  echo "Creating token directory..."
  mkdir -p /var/lib/softhsm/tokens
  chmod 755 /var/lib/softhsm/tokens
fi

# List current slots
echo "Current slots:"
softhsm2-util --show-slots || echo "No slots yet"

# Check if token already exists
if softhsm2-util --show-slots | grep -q "$TOKEN_LABEL"; then
  echo "Token '$TOKEN_LABEL' already exists"
  SLOT=$(softhsm2-util --show-slots | grep -B 15 "Label:.*$TOKEN_LABEL" | grep "^Slot " | head -1 | awk '{print $2}')
  echo "Using existing token in slot: $SLOT"
else
  echo "Initializing new token '$TOKEN_LABEL'..."
  
  # Initialize token
  INIT_OUTPUT=$(softhsm2-util --init-token --free --label "$TOKEN_LABEL" --so-pin "$SO_PIN" --pin "$USER_PIN" 2>&1)
  echo "$INIT_OUTPUT"
  
  # Extract slot number
  SLOT=$(echo "$INIT_OUTPUT" | grep -oP 'slot \K[0-9]+')
  
  if [ -z "$SLOT" ]; then
    sleep 1
    SLOT=$(softhsm2-util --show-slots | grep -B 15 "Label:.*$TOKEN_LABEL" | grep "^Slot " | head -1 | awk '{print $2}')
  fi
  
  if [ -z "$SLOT" ]; then
    echo "ERROR: Could not find slot!"
    softhsm2-util --show-slots
    exit 1
  fi
  
  echo "Token created in slot: $SLOT"
fi

# Check if key already exists (moved outside the token creation block)
if pkcs11-tool --module "$SOFTHSM_MODULE" \
    --slot "$SLOT" \
    --login --pin "$USER_PIN" \
    --list-objects | grep -q "$KEY_LABEL"; then
  echo "Key '$KEY_LABEL' already exists in token"
else
  echo "Generating RSA-$KEY_SIZE key pair..."
  pkcs11-tool --module "$SOFTHSM_MODULE" \
    --slot "$SLOT" \
    --login --pin "$USER_PIN" \
    --keypairgen \
    --key-type rsa:$KEY_SIZE \
    --label "$KEY_LABEL" \
    --id 01
  
  if [ $? -ne 0 ]; then
    echo "ERROR: Key generation failed!"
    exit 1
  fi
  echo "Key pair generated successfully"
fi

# Export public key if it doesn't exist (moved outside the token creation block)
if [ ! -f /app/server_public_key.pem ]; then
  echo "Exporting public key..."
  
  # Export to DER
  pkcs11-tool --module "$SOFTHSM_MODULE" \
    --slot "$SLOT" \
    --login --pin "$USER_PIN" \
    --read-object --type pubkey --label "$KEY_LABEL" \
    --output-file /app/server_public_key.der
  
  if [ ! -f /app/server_public_key.der ]; then
    echo "ERROR: Failed to export public key!"
    exit 1
  fi
  
  # Convert to PEM
  openssl rsa -pubin -inform DER -in /app/server_public_key.der -outform PEM -out /app/server_public_key.pem
  
  if [ ! -f /app/server_public_key.pem ]; then
    echo "ERROR: Failed to convert to PEM!"
    exit 1
  fi
  
  echo "Public key exported to /app/server_public_key.pem"
  
  # Display the public key
  echo ""
  echo "=== Public Key ==="
  cat /app/server_public_key.pem
else
  echo "Public key already exists at /app/server_public_key.pem"
fi

echo ""
echo "=== HSM Setup Complete ==="
echo "Token Label: $TOKEN_LABEL"
echo "Slot: $SLOT"
echo "Key Label: $KEY_LABEL"
echo ""

# Copy public key to shared volume (always do this, even if key already exists)
if [ -f /app/server_public_key.pem ]; then
  mkdir -p /shared_keys
  cp /app/server_public_key.pem /shared_keys/server_public_key.pem
  chmod 644 /shared_keys/server_public_key.pem
  echo "Public key copied to shared volume"
fi

# Run Django setup
echo "Running database migrations..."
python manage.py makemigrations --noinput
python manage.py migrate --noinput

echo "Collecting static files..."
python manage.py collectstatic --noinput --clear

# Start Django
if [ "$DEBUG" = "True" ]; then
  echo "Starting Django development server..."
  exec python manage.py runserver 0.0.0.0:8000
else
  echo "Starting Gunicorn server..."
  exec gunicorn SecurityLogger.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 4 \
    --threads 2 \
    --timeout 60 \
    --access-logfile - \
    --error-logfile - \
    --log-level info
fi