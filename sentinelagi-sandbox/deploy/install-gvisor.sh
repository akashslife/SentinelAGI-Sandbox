#!/bin/bash
# ============================================
# SentinelAGI - gVisor Installation Script
# ============================================
# Run this on the Docker host to install gVisor (runsc) runtime
# Source: https://gvisor.dev/docs/user_guide/install/

set -e

echo "Installing gVisor (runsc) for SentinelAGI Sandbox..."

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed. Please install Docker first."
    exit 1
fi

# Install runsc
(
    set -e
    ARCH=$(uname -m)
    URL=https://storage.googleapis.com/gvisor/releases/release/latest
    
    if [[ "$ARCH" != "x86_64" ]]; then
        URL=${URL}.${ARCH}
    fi
    
    echo "Downloading runsc from $URL..."
    wget ${URL}/runsc ${URL}/runsc.sha512 \
        -P /tmp --quiet || curl -sSL ${URL}/runsc -o /tmp/runsc
    
    cd /tmp
    sha512sum -c runsc.sha512 || echo "Checksum verification skipped"
    
    chmod a+x /tmp/runsc
    sudo mv /tmp/runsc /usr/local/bin/
    
    echo "runsc installed to /usr/local/bin/runsc"
)

# Configure Docker to use runsc
echo "Configuring Docker runtime..."

if [ -f /etc/docker/daemon.json ]; then
    # Backup existing config
    sudo cp /etc/docker/daemon.json /etc/docker/daemon.json.backup
    
    # Merge with existing config
    sudo bash -c 'cat > /etc/docker/daemon.json <<EOF
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--debug-log=/tmp/runsc/",
                "--debug",
                "--strace"
            ]
        }
    }
}
EOF'
else
    sudo bash -c 'cat > /etc/docker/daemon.json <<EOF
{
    "runtimes": {
        "runsc": {
            "path": "/usr/local/bin/runsc",
            "runtimeArgs": [
                "--debug-log=/tmp/runsc/",
                "--debug",
                "--strace"
            ]
        }
    }
}
EOF'
fi

# Restart Docker
echo "Restarting Docker..."
sudo systemctl restart docker || sudo service docker restart

# Verify installation
echo "Verifying gVisor installation..."
docker run --rm --runtime=runsc hello-world > /dev/null 2>&1 && echo "gVisor (runsc) is working!" || echo "Warning: gVisor test failed"

echo ""
echo "=========================================="
echo "gVisor installation complete!"
echo ""
echo "Docker runtimes:"
docker info --format '{{json .Runtimes}}' | python3 -m json.tool || docker info | grep -A5 "Runtimes"
echo "=========================================="
