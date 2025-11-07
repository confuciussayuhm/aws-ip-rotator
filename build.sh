#!/bin/bash

echo "Building Burp FireProx Extension..."
echo "===================================="

# Check if Maven is installed
if ! command -v mvn &> /dev/null; then
    echo "Error: Maven is not installed. Please install Maven first."
    exit 1
fi

# Clean and build
mvn clean package

if [ $? -eq 0 ]; then
    echo ""
    echo "===================================="
    echo "Build successful!"
    echo "JAR location: target/fireprox-extension-1.0.0.jar"
    echo ""
    echo "To install in Burp Suite:"
    echo "1. Go to Extensions → Installed"
    echo "2. Click 'Add'"
    echo "3. Select Extension type: Java"
    echo "4. Select file: target/fireprox-extension-1.0.0.jar"
    echo "5. Click 'Next'"
    echo "===================================="
else
    echo ""
    echo "Build failed. Please check the error messages above."
    exit 1
fi
