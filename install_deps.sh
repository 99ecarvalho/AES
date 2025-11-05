#!/bin/bash
# Install Python dependencies for benchmark analysis using virtual environment

echo "Setting up Python virtual environment for AES benchmark analysis..."

# Check if python3 is available
if ! command -v python3 &> /dev/null; then
    echo "python3 not found. Please install Python3 first."
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    if [ $? -ne 0 ]; then
        echo "Failed to create virtual environment. Make sure python3-venv is installed:"
        echo "  sudo apt install python3-full python3-venv"
        exit 1
    fi
fi

# Activate virtual environment and install packages
echo "Activating virtual environment and installing packages..."
source venv/bin/activate

# Upgrade pip first
pip install --upgrade pip

# Install required packages
pip install matplotlib seaborn pandas numpy

echo "Dependencies installed successfully in virtual environment!"
echo ""
echo "To run the analysis, use one of these methods:"
echo "  1. make analysis    (automatically uses venv)"
echo "  2. source venv/bin/activate && python3 benchmark_analysis.py"