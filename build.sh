#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}Starting optimized build process...${NC}"

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker is not installed. Please install Docker first.${NC}"
    exit 1
fi

# Check if docker-compose is installed
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}docker-compose is not installed. Please install docker-compose first.${NC}"
    exit 1
fi

# Configure Docker for 8GB RAM
echo -e "${YELLOW}Configuring Docker for 8GB RAM...${NC}"
sudo mkdir -p /etc/docker
echo '{
    "memory": "6g",
    "memory-swap": "8g",
    "storage-driver": "overlay2",
    "max-concurrent-downloads": 3,
    "max-concurrent-uploads": 2
}' | sudo tee /etc/docker/daemon.json

# Restart Docker
sudo systemctl restart docker

# Create necessary directories
echo -e "${YELLOW}Creating necessary directories...${NC}"
mkdir -p data/uploads
mkdir -p data/results

# Clean up Docker
echo -e "${YELLOW}Cleaning up Docker...${NC}"
docker system prune -f
docker builder prune -f

# Download Ghidra if not present
if [ ! -f "ghidra_11.3.2_PUBLIC_20250415.zip" ]; then
    echo -e "${YELLOW}Downloading Ghidra...${NC}"
    wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip
fi

# Set build arguments for optimization
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1
export DOCKER_CLI_EXPERIMENTAL=enabled

# Build the Docker image with optimized settings
echo -e "${YELLOW}Building Docker image...${NC}"
docker-compose build --no-cache --parallel 2 --memory 6g

# Check if build was successful
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Build completed successfully!${NC}"
    echo -e "${YELLOW}You can now start the services with:${NC}"
    echo -e "docker-compose up -d"
else
    echo -e "${RED}Build failed. Please check the error messages above.${NC}"
    exit 1
fi 