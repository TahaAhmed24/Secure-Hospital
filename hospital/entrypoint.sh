#!/bin/sh
# Exit on error
set -e

echo "Waiting for MySQL to be ready..."
# Wait for MySQL to be ready
while ! nc -z db 3306; do
  sleep 1
done
echo "MySQL is ready!"

# Set up shared keys directory and move public key
echo "Setting up encryption keys..."
mkdir -p /shared_keys

# Check if public key exists in app directory and copy to shared_keys
if [ -f /app/public_key.pem ]; then
  echo "Copying public key to shared directory..."
  cp /app/public_key.pem /shared_keys/public_key.pem
  chmod 644 /shared_keys/public_key.pem
  echo "Public key ready at /shared_keys/public_key.pem"
else
  echo "Warning: /app/public_key.pem not found"
fi

python manage.py makemigrations --noinput

echo "Running database migrations..."
python manage.py migrate --noinput

echo "Collecting static files..."
python manage.py collectstatic --noinput --clear

# Check if we're in development mode
if [ "$DEBUG" = "True" ]; then
  echo "Starting Django development server with auto-reload..."
  exec python manage.py runserver 0.0.0.0:8000
else
  echo "Starting Gunicorn server..."
  exec gunicorn hospital.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 4 \
    --threads 2 \
    --timeout 60 \
    --access-logfile - \
    --error-logfile - \
    --log-level info
fi