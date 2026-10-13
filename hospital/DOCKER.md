# Docker Setup for Hospital Management System

This guide explains how to run the Hospital Management System using Docker with Django, Nginx, and MySQL.

## Prerequisites

- Docker Engine (20.10+)
- Docker Compose (1.29+)

## Architecture

The application consists of three services:
- **web**: Django application running with Gunicorn
- **nginx**: Nginx reverse proxy with SSL/TLS support
- **db**: MySQL 8.0 database

## Quick Start

### 1. Environment Configuration

Review and update the environment variables in `.env.docker`:

```bash
# Django Settings
SECRET_KEY=your-very-secret-django-key-here-change-in-production
DEBUG=False

# Database Configuration
MYSQL_DATABASE=ssd_dev
MYSQL_USER=root
MYSQL_PASSWORD=K@takuri24
MYSQL_HOST=db
MYSQL_PORT=3306
```

**Important**: Change the `SECRET_KEY` and `MYSQL_PASSWORD` in production!

### 2. Build and Start Services

```bash
# Build the images
docker-compose build

# Start all services
docker-compose up -d

# Check service status
docker-compose ps
```

### 3. Create Django Superuser (First Time Only)

```bash
docker-compose exec web python manage.py createsuperuser
```

### 4. Access the Application

- **HTTPS**: https://localhost (redirects from HTTP)
- **HTTP**: http://localhost (auto-redirects to HTTPS)
- **Admin Panel**: https://localhost/admin

## SSL/TLS Configuration

The application uses your existing PKI certificates located in the `pki/` directory:
- Root CA: `pki/root/root-ca.crt`
- Intermediate CA: `pki/intermediate/intermediate-ca.crt`
- Server Certificate: `pki/server/localhost.crt`
- Server Key: `pki/server/localhost.key`

These certificates are mounted into the Nginx container at `/etc/nginx/ssl/`.

## WebAuthn Configuration

WebAuthn is configured to work with `https://localhost:8000` by default. If you need to change this:

1. Update `WEBAUTH_RP_ID` and `WEBAUTH_ORIGIN` in `hospital/settings.py`
2. Update `DJANGO_ALLOWED_HOSTS` in `.env.docker`
3. Update Nginx server_name in `nginx/conf.d/hospital.conf`
4. Rebuild and restart: `docker-compose up -d --build`

## Common Commands

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f web
docker-compose logs -f nginx
docker-compose logs -f db
```

### Run Django Management Commands

```bash
# Migrations
docker-compose exec web python manage.py migrate

# Create superuser
docker-compose exec web python manage.py createsuperuser

# Collect static files
docker-compose exec web python manage.py collectstatic --noinput

# Django shell
docker-compose exec web python manage.py shell
```

### Database Access

```bash
# MySQL shell
docker-compose exec db mysql -u root -p

# Backup database
docker-compose exec db mysqldump -u root -p ssd_dev > backup.sql

# Restore database
docker-compose exec -T db mysql -u root -p ssd_dev < backup.sql
```

### Stop and Remove Services

```bash
# Stop services
docker-compose stop

# Stop and remove containers
docker-compose down

# Remove containers and volumes (WARNING: deletes database!)
docker-compose down -v
```

## Development Mode

To run in development mode with live code reloading:

1. Update `.env.docker`:
   ```
   DEBUG=True
   ```

2. Modify `docker-compose.yml` to use Django's development server:
   ```yaml
   web:
     command: python manage.py runserver 0.0.0.0:8000
   ```

3. Restart:
   ```bash
   docker-compose up -d
   ```

## Troubleshooting

### Cannot connect to database

```bash
# Check if MySQL is healthy
docker-compose ps

# Check MySQL logs
docker-compose logs db

# Restart services
docker-compose restart
```

### Static files not loading

```bash
# Collect static files
docker-compose exec web python manage.py collectstatic --noinput

# Restart Nginx
docker-compose restart nginx
```

### Permission denied errors

```bash
# Make entrypoint executable
chmod +x entrypoint.sh

# Rebuild
docker-compose up -d --build
```

### SSL certificate errors

Ensure your PKI certificates are valid and located in the correct paths:
- Check certificate validity: `openssl x509 -in pki/server/localhost.crt -text -noout`
- Verify certificate chain: `openssl verify -CAfile pki/root/root-ca.crt pki/server/localhost.crt`

## Production Deployment

For production deployment:

1. **Update environment variables**:
   - Generate a strong `SECRET_KEY`
   - Use strong database passwords
   - Set `DEBUG=False`

2. **Configure domain name**:
   - Update `server_name` in `nginx/conf.d/hospital.conf`
   - Update SSL certificates for your domain
   - Update `DJANGO_ALLOWED_HOSTS`

3. **Enable HTTPS security headers** (already configured in Nginx)

4. **Set up backups** for the MySQL database volume

5. **Monitor logs** and set up log aggregation

6. **Scale workers** if needed:
   ```yaml
   web:
     deploy:
       replicas: 3
   ```

## File Structure

```
.
├── docker-compose.yml       # Docker Compose configuration
├── Dockerfile               # Django application image
├── entrypoint.sh            # Container startup script
├── .env.docker              # Environment variables
├── .dockerignore            # Files to exclude from Docker build
├── nginx/
│   ├── nginx.conf           # Main Nginx configuration
│   └── conf.d/
│       └── hospital.conf    # Site-specific configuration
└── pki/                     # SSL/TLS certificates
    ├── root/
    ├── intermediate/
    └── server/
```

## Volumes

- `mysql_data`: Persistent MySQL database storage
- `static_volume`: Django static files (CSS, JS, images)
- `media_volume`: User-uploaded media files

Data persists across container restarts unless explicitly removed with `docker-compose down -v`.
