-- init-db.sql
CREATE DATABASE IF NOT EXISTS hospital;
CREATE DATABASE IF NOT EXISTS securityLogger;

CREATE USER IF NOT EXISTS 'hospital_user'@'%' IDENTIFIED BY 'hospital_pass';
CREATE USER IF NOT EXISTS 'security_user'@'%' IDENTIFIED BY 'security_pass';

GRANT ALL PRIVILEGES ON hospital.* TO 'hospital_user'@'%';
GRANT ALL PRIVILEGES ON securityLogger.* TO 'security_user'@'%';

FLUSH PRIVILEGES;