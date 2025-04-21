#!/bin/bash

# PostgreSQL database setup script for DarkuBots IRC Services
# Created: April 21, 2025
# Author: reverse
#
# This script creates the necessary PostgreSQL database, user, and tables
# for DarkuBots IRC Services.

# Configuration - change these settings as needed
DB_NAME="darkubots"
DB_USER="darkubots"
DB_PASS="YOUR_SECURE_PASSWORD_HERE" # Remember to change this!
DB_HOST="localhost"
DB_PORT="5432"

# Check if script is being run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script should be run as root or with sudo privileges."
  exit 1
fi

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null; then
  echo "PostgreSQL is not installed. Please install PostgreSQL first."
  echo "On Debian/Ubuntu: sudo apt install postgresql postgresql-contrib"
  echo "On CentOS/RHEL: sudo yum install postgresql-server postgresql-contrib"
  exit 1
fi

# Create PostgreSQL user and database (as postgres user)
echo "Creating PostgreSQL user and database..."
su - postgres << EOF
psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"
psql -c "CREATE DATABASE $DB_NAME WITH OWNER = $DB_USER ENCODING = 'UTF8';"
psql -c "GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;"
EOF

# Connect to the database and create tables
echo "Creating tables in $DB_NAME database..."
psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME << EOF
-- Create versions table to track file versions
CREATE TABLE IF NOT EXISTS versions (
    filename VARCHAR(255) PRIMARY KEY,
    version INTEGER NOT NULL
);

-- Create main data table for storing binary data
CREATE TABLE IF NOT EXISTS dbfiles (
    filename VARCHAR(255) PRIMARY KEY,
    data BYTEA NOT NULL,
    last_modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create settings table for configuration
CREATE TABLE IF NOT EXISTS settings (
    setting_name VARCHAR(255) PRIMARY KEY,
    setting_value TEXT NOT NULL,
    description TEXT
);

-- Insert basic configuration settings
INSERT INTO settings (setting_name, setting_value, description)
VALUES
    ('db_version', '1', 'Database schema version'),
    ('last_maintenance', NOW()::TEXT, 'Last time maintenance was performed');

-- Create logs table for logging service events
CREATE TABLE IF NOT EXISTS service_logs (
    log_id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    service VARCHAR(50) NOT NULL,
    level VARCHAR(20) NOT NULL,
    message TEXT NOT NULL
);

EOF

# Verify creation was successful
echo "Checking database setup..."
if psql -h $DB_HOST -p $DB_PORT -U $DB_USER -d $DB_NAME -c "\dt" | grep -q "dbfiles"; then
  echo "Database setup successful!"
  echo ""
  echo "To complete the setup, update the PostgreSQL connection parameters in datafiles.c:"
  echo "  - DB_Host = \"$DB_HOST\";"
  echo "  - DB_Port = \"$DB_PORT\";"
  echo "  - DB_Name = \"$DB_NAME\";"
  echo "  - DB_User = \"$DB_USER\";"
  echo "  - DB_Pass = \"$DB_PASS\";"
  echo ""
  echo "You may need to update your pg_hba.conf file to allow password authentication."
else
  echo "Database setup failed. Please check the error messages above."
fi

# Additional security notes
echo ""
echo "SECURITY NOTES:"
echo "1. Make sure to use a strong, unique password"
echo "2. Configure PostgreSQL for network security if running on a remote server"
echo "3. Regularly backup your database"
echo ""