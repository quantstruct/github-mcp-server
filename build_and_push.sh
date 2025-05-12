#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Error: Image name is required"
    echo "Usage: $0 <image-name> [tag]"
    exit 1
fi

IMAGE_NAME=$1
TAG=${2:-latest}

gcloud auth configure-docker us-west1-docker.pkg.dev

docker build --build-arg PLATFORM=linux/amd64 -t us-west1-docker.pkg.dev/quantstruct/mcp/${IMAGE_NAME}:${TAG} .

docker push us-west1-docker.pkg.dev/quantstruct/mcp/${IMAGE_NAME}:${TAG} 