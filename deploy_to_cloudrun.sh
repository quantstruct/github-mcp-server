#!/bin/bash
set -e

if [ -z "$1" ]; then
    echo "Error: Service name is required"
    echo "Usage: $0 <service-name> [image-name] [tag]"
    exit 1
fi

SERVICE_NAME=$1
IMAGE_NAME=${2:-$1}  # Default to service name if image name not provided
TAG=${3:-latest}

# Set the project
gcloud config set project quantstruct

# Build the secret references
# Format: --set-secrets=ENV_VAR_NAME=SECRET_NAME:VERSION
SECRETS=""
if [ -f ".env.secrets" ]; then
    while IFS='=' read -r key value; do
        # Skip empty lines and comments
        [[ -z "$key" || "$key" =~ ^# ]] && continue
        # Remove any quotes from the value
        value=$(echo "$value" | tr -d '"' | tr -d "'")
        SECRETS="$SECRETS --set-secrets=$key=$value:latest"
    done < .env.secrets
fi

# Build the environment variables
ENV_VARS=""
if [ -f ".env" ]; then
    while IFS='=' read -r key value; do
        # Skip empty lines and comments
        [[ -z "$key" || "$key" =~ ^# ]] && continue
        # Remove any quotes from the value
        value=$(echo "$value" | tr -d '"' | tr -d "'")
        ENV_VARS="$ENV_VARS --set-env-vars=$key=$value"
    done < .env
fi

# Construct the deployment command
DEPLOY_CMD="gcloud run deploy ${SERVICE_NAME} \
    --image us-west1-docker.pkg.dev/quantstruct/mcp/${IMAGE_NAME}:${TAG} \
    --platform managed \
    --region us-west1 \
    --allow-unauthenticated \
    --port 8000 \
    --memory 512Mi \
    --cpu 1 \
    --min-instances 1 \
    --max-instances 10 \
    --set-secrets=GITHUB_PERSONAL_ACCESS_TOKEN=qsbot_github_pat:latest \
    ${SECRETS} \
    ${ENV_VARS}"

# Echo the command for testing
echo "Deployment command:"
echo "$DEPLOY_CMD"
echo ""

# Execute the deployment
eval "$DEPLOY_CMD"

echo "Deployment completed successfully!"
echo "You can view your service at: https://console.cloud.google.com/run/detail/us-west1/${SERVICE_NAME}/overview" 