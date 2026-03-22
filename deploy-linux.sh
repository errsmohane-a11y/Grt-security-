#!/bin/bash

# GRT Security Platform Deployment Script for Linux
# This script sets up the application as a systemd service

APP_NAME="grt-security"
APP_DIR="/opt/$APP_NAME"
SERVICE_FILE="/etc/systemd/system/$APP_NAME.service"
USER="www-data"

echo "Deploying GRT Security Platform..."

# Create application directory
sudo mkdir -p $APP_DIR
sudo chown $USER:$USER $APP_DIR

# Copy application files (assuming built in current directory)
sudo cp -r . $APP_DIR/
sudo chown -R $USER:$USER $APP_DIR

# Create systemd service file
sudo tee $SERVICE_FILE > /dev/null <<EOF
[Unit]
Description=GRT Security Platform
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/GRT.Security.Platform
Restart=always
RestartSec=10
Environment=ASPNETCORE_ENVIRONMENT=Production
Environment=ASPNETCORE_URLS=http://0.0.0.0:5000

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable $APP_NAME
sudo systemctl start $APP_NAME

echo "Deployment complete. Service status:"
sudo systemctl status $APP_NAME --no-pager

echo "Application should be running on http://localhost:5000"
echo "Admin interface: http://localhost:5000/admin"