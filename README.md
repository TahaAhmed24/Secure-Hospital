# Hospital Management System

A secure hospital management platform with encrypted logging and PKI certificate management.

By William Lecky-Thompson (000613648) and Taha Ahmed (000613520)
## Running with Docker Compose

### 1. Set up environment files

Create `hospital.env`:
```env
# Django Settings
SECRET_KEY=your-very-secret-django-key-here
DEBUG=True

# Database Configuration
MYSQL_DATABASE=hospital
MYSQL_USER=hospital_user
MYSQL_PASSWORD=hospital_pass
MYSQL_HOST=db
MYSQL_PORT=3306

# Django Static Files
DJANGO_STATIC_URL=/static/

# Allowed Hosts (comma-separated)
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,web

# PKI Certificate Paths (for issuing doctor certificates)
INTERMEDIATE_CERTIFICATE=/app/pki/intermediate/intermediate.crt
INTERMEDIATE_KEY=/app/pki/intermediate/intermediate.key
INTERMEDIATE_KEY_PASSPHRASE=mysecretpassphrase
ROOT_KEY_PASSPHRASE=myrootpassphrase
```

Create `securitylogger.env`:
```env
# Django Settings
SECRET_KEY=your-very-secret-django-key-here
DEBUG=True

# Database Configuration
MYSQL_DATABASE=securityLogger
MYSQL_USER=security_user
MYSQL_PASSWORD=security_pass
MYSQL_HOST=db
MYSQL_PORT=3306

# Django Static Files
DJANGO_STATIC_URL=/static/

# Allowed Hosts (comma-separated)
DJANGO_ALLOWED_HOSTS=securitylogger,localhost,127.0.0.1,nginx

# HSM Configuration
HSM_PIN=5678
SOFTHSM_MODULE=/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so
TOKEN_LABEL=security-server
SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
```

### 2. Build and start services

```bash
docker compose build
docker compose up -d
```

### 3. Access the application

- Hospital App: https://localhost

## Environment Variables

### Hospital Container (`hospital.env`)

| Variable | Description | Required |
|----------|-------------|----------|
| `SECRET_KEY` | Django secret key for cryptographic signing | Yes |
| `DEBUG` | Enable Django debug mode (True/False) | No |
| `MYSQL_DATABASE` | MySQL database name | Yes |
| `MYSQL_USER` | MySQL username | Yes |
| `MYSQL_PASSWORD` | MySQL password | Yes |
| `MYSQL_HOST` | MySQL host address | Yes |
| `MYSQL_PORT` | MySQL port | No |
| `DJANGO_STATIC_URL` | URL path for static files | No |
| `DJANGO_ALLOWED_HOSTS` | Comma-separated list of allowed hosts | Yes |
| `INTERMEDIATE_CERTIFICATE` | Path to intermediate CA certificate | Yes |
| `INTERMEDIATE_KEY` | Path to intermediate CA private key | Yes |
| `INTERMEDIATE_KEY_PASSPHRASE` | Passphrase for intermediate key | Yes |
| `ROOT_KEY_PASSPHRASE` | Passphrase for root CA key | Yes |

### Security Logger Container (`securitylogger.env`)

| Variable | Description | Required |
|----------|-------------|----------|
| `SECRET_KEY` | Django secret key for cryptographic signing | Yes |
| `DEBUG` | Enable Django debug mode (True/False) | No |
| `MYSQL_DATABASE` | MySQL database name | Yes |
| `MYSQL_USER` | MySQL username | Yes |
| `MYSQL_PASSWORD` | MySQL password | Yes |
| `MYSQL_HOST` | MySQL host address | Yes |
| `MYSQL_PORT` | MySQL port | No |
| `DJANGO_STATIC_URL` | URL path for static files | No |
| `DJANGO_ALLOWED_HOSTS` | Comma-separated list of allowed hosts | Yes |
| `HSM_PIN` | PIN for Hardware Security Module | Yes |
| `SOFTHSM_MODULE` | Path to SoftHSM library | Yes |
| `TOKEN_LABEL` | HSM token label | Yes |
| `SOFTHSM2_CONF` | Path to SoftHSM configuration file | Yes |

## Common Commands

```bash
# Start services
docker compose up -d

# Stop services
docker compose down

# View logs
docker compose logs -f

# Restart a service
docker compose restart web
```