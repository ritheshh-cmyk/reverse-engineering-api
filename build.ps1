# PowerShell build script for Windows

# Function to write colored output
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) {
        Write-Output $args
    }
    else {
        $input | Write-Output
    }
    $host.UI.RawUI.ForegroundColor = $fc
}

# Check if Docker is installed
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-ColorOutput Red "Docker is not installed. Please install Docker Desktop for Windows first."
    exit 1
}

# Check if docker-compose is installed
if (-not (Get-Command docker-compose -ErrorAction SilentlyContinue)) {
    Write-ColorOutput Red "docker-compose is not installed. Please install Docker Desktop for Windows first."
    exit 1
}

# Create necessary directories
Write-ColorOutput Yellow "Creating necessary directories..."
New-Item -ItemType Directory -Force -Path "data\uploads" | Out-Null
New-Item -ItemType Directory -Force -Path "data\results" | Out-Null

# Download Ghidra if not present
if (-not (Test-Path "ghidra_11.3.2_PUBLIC_20250415.zip")) {
    Write-ColorOutput Yellow "Downloading Ghidra..."
    Invoke-WebRequest -Uri "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.2_build/ghidra_11.3.2_PUBLIC_20250415.zip" -OutFile "ghidra_11.3.2_PUBLIC_20250415.zip"
}

# Clean up Docker
Write-ColorOutput Yellow "Cleaning up Docker..."
docker system prune -f
docker builder prune -f

# Set build arguments for optimization
$env:DOCKER_BUILDKIT = "1"
$env:COMPOSE_DOCKER_CLI_BUILD = "1"
$env:DOCKER_CLI_EXPERIMENTAL = "enabled"

# Build the Docker image with optimized settings
Write-ColorOutput Yellow "Building Docker image..."
docker-compose build --no-cache --parallel 2 --memory 6g

# Check if build was successful
if ($LASTEXITCODE -eq 0) {
    Write-ColorOutput Green "Build completed successfully!"
    Write-ColorOutput Yellow "You can now start the services with:"
    Write-ColorOutput Yellow "docker-compose up -d"
}
else {
    Write-ColorOutput Red "Build failed. Please check the error messages above."
    exit 1
} 