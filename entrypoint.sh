#!/bin/bash

Collect static files
echo "Collect static files"
python manage.py collectstatic --noinput

# Apply database migrations
echo "Apply database migrations"
python manage.py migrate

# Start server
echo "Starting server"
gunicorn AuthorizationProject.wsgi:application -w 4 -b 0.0.0.0:8080