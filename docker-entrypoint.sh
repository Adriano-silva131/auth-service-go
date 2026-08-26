#!/bin/sh
set -eu

echo "running migrations..."
migrate -path /app/migrations -database "$DATABASE_URL" up

echo "starting auth-service..."
exec auth-service
