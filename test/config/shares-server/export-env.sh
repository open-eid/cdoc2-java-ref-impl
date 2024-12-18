#!/bin/bash
# Export .env file as environment variables
# Must be executed as `source export-env.sh .env`

ENV_FILE="${1:-.env}"  # Default to .env if no file is provided
if [ ! -f "$ENV_FILE" ]; then
    echo "Error: Environment file '$ENV_FILE' not found."
    return 1  # Use 'return' so it works when sourced
fi

# Export variables from the .env file
echo "Loading environment variables from $ENV_FILE..."
set -a                # Automatically export all variables
source "$ENV_FILE"    # Source the .env file
set +a                # Stop automatic export

echo "Environment variables loaded successfully."