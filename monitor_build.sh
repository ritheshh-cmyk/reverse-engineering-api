#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Function to get current timestamp
timestamp() {
    date "+%Y-%m-%d %H:%M:%S"
}

# Function to get system resources
get_system_resources() {
    # CPU Usage
    CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print $2 + $4}')
    
    # Memory Usage
    MEMORY_USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    
    # Disk Usage
    DISK_USAGE=$(df -h / | tail -1 | awk '{print $5}' | sed 's/%//')
    
    # Docker disk usage
    DOCKER_USAGE=$(docker system df -v | grep "Total Space" | awk '{print $3}')
    
    echo "CPU: ${CPU_USAGE}% | Memory: ${MEMORY_USAGE}% | Disk: ${DISK_USAGE}% | Docker: ${DOCKER_USAGE}"
}

# Function to get Docker build progress
get_build_progress() {
    # Get current build stage
    CURRENT_STAGE=$(docker-compose logs --tail=50 | grep "Step" | tail -1)
    
    # Get build time
    BUILD_TIME=$(ps -p $(pgrep -f "docker-compose build") -o etime= 2>/dev/null || echo "N/A")
    
    echo "Current Stage: ${CURRENT_STAGE} | Build Time: ${BUILD_TIME}"
}

# Function to check for errors
check_errors() {
    # Check Docker logs for errors
    ERRORS=$(docker-compose logs --tail=100 | grep -i "error\|fail\|exception" | tail -5)
    
    if [ ! -z "$ERRORS" ]; then
        echo -e "${RED}Recent Errors:${NC}"
        echo "$ERRORS"
    fi
}

# Function to display progress bar
progress_bar() {
    local duration=$1
    local width=50
    local progress=0
    local step=$((100 / width))
    
    while [ $progress -le 100 ]; do
        local completed=$((progress * width / 100))
        local remaining=$((width - completed))
        printf "\r[%${completed}s%${remaining}s] %d%%" | tr ' ' '#' | tr ' ' '-'
        progress=$((progress + step))
        sleep $duration
    done
    echo
}

# Main monitoring loop
echo -e "${BLUE}Starting build monitoring at $(timestamp)${NC}"
echo -e "${YELLOW}Press Ctrl+C to stop monitoring${NC}"

# Create log file
LOG_FILE="build_monitor_$(date +%Y%m%d_%H%M%S).log"
echo "Build Monitor Log - Started at $(timestamp)" > "$LOG_FILE"

while true; do
    # Clear screen
    clear
    
    # Display header
    echo -e "${BLUE}=== Build Process Monitor ===${NC}"
    echo -e "Time: $(timestamp)"
    echo -e "Log File: $LOG_FILE"
    echo
    
    # Get and display system resources
    echo -e "${YELLOW}System Resources:${NC}"
    RESOURCES=$(get_system_resources)
    echo -e "$RESOURCES"
    echo "$(timestamp) - Resources: $RESOURCES" >> "$LOG_FILE"
    
    # Get and display build progress
    echo -e "\n${YELLOW}Build Progress:${NC}"
    PROGRESS=$(get_build_progress)
    echo -e "$PROGRESS"
    echo "$(timestamp) - Progress: $PROGRESS" >> "$LOG_FILE"
    
    # Check for errors
    echo -e "\n${YELLOW}Error Check:${NC}"
    check_errors >> "$LOG_FILE"
    
    # Display Docker container status
    echo -e "\n${YELLOW}Docker Status:${NC}"
    docker ps -a --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | tail -n +2
    
    # Display disk space warning if needed
    DISK_USAGE=$(df -h / | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$DISK_USAGE" -gt 80 ]; then
        echo -e "\n${RED}Warning: Disk usage is above 80% (${DISK_USAGE}%)${NC}"
        echo "$(timestamp) - Warning: High disk usage: ${DISK_USAGE}%" >> "$LOG_FILE"
    fi
    
    # Display memory warning if needed
    MEMORY_USAGE=$(free | grep Mem | awk '{print $3/$2 * 100.0}')
    if (( $(echo "$MEMORY_USAGE > 80" | bc -l) )); then
        echo -e "\n${RED}Warning: Memory usage is above 80% (${MEMORY_USAGE}%)${NC}"
        echo "$(timestamp) - Warning: High memory usage: ${MEMORY_USAGE}%" >> "$LOG_FILE"
    fi
    
    # Wait for 5 seconds before next update
    sleep 5
done 