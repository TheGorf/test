#!/bin/bash
# Build Lambda@Edge deployment package

set -e

echo "Building Lambda@Edge deployment package..."

# Clean previous build
rm -rf build/
mkdir -p build/package

# Copy source files
echo "Copying source files..."
cp -r src/* build/package/

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt -t build/package/ --platform manylinux2014_x86_64 --only-binary=:all:

# Remove unnecessary files to reduce package size
echo "Optimizing package size..."
cd build/package

# Remove test files and documentation
find . -type d -name "tests" -exec rm -rf {} + 2>/dev/null || true
find . -type d -name "*.dist-info" -exec rm -rf {} + 2>/dev/null || true
find . -name "*.pyc" -delete
find . -name "*.pyo" -delete
find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Create deployment package
echo "Creating deployment zip..."
zip -r9 ../lambda-edge-signature-validation.zip . -x "*.git*" "*.DS_Store"

cd ../..

# Check package size
PACKAGE_SIZE=$(du -h build/lambda-edge-signature-validation.zip | cut -f1)
echo "Package size: $PACKAGE_SIZE"
echo "Deployment package created: build/lambda-edge-signature-validation.zip"

# Warn if package is too large for Lambda@Edge
PACKAGE_SIZE_BYTES=$(stat -f%z build/lambda-edge-signature-validation.zip 2>/dev/null || stat -c%s build/lambda-edge-signature-validation.zip)
if [ $PACKAGE_SIZE_BYTES -gt 1048576 ]; then
    echo "WARNING: Package size exceeds 1MB limit for Lambda@Edge viewer requests"
    echo "Consider using a Lambda Layer for the cryptography library"
fi
