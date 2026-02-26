#!/bin/bash

# DocuSeal Local Deployment Script
# This script deploys DocuSeal locally to analyze template maker functionality

set -e

echo "=== DocuSeal Local Deployment ==="

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    exit 1
fi

# Create deployment directory
DEPLOY_DIR="./docuseal-local"
mkdir -p $DEPLOY_DIR
cd $DEPLOY_DIR

# Download docker-compose.yml if not present
if [ ! -f docker-compose.yml ]; then
    echo "Downloading DocuSeal docker-compose.yml..."
    curl -sL https://raw.githubusercontent.com/docusealco/docuseal/master/docker-compose.yml -o docker-compose.yml
fi

# Create environment file
cat > .env << EOF
HOST=localhost
EOF

# Create required directories
mkdir -p docuseal pg_data caddy

# Start deployment
echo "Starting DocuSeal deployment..."
docker compose up -d

# Wait for services to be healthy
echo "Waiting for services to start..."
sleep 10

# Check service health
echo "Checking service health..."
docker compose ps

# Report access information
echo ""
echo "=== Deployment Complete ==="
echo "DocuSeal should be accessible at: http://localhost:3000"
echo ""
echo "Note: First startup may take a few minutes as the database is initialized."
echo "Check logs with: docker compose logs -f"
