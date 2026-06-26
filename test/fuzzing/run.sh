#!/bin/bash

set -e

# Run the Docker Compose setup for Restler fuzzing
docker compose up --abort-on-container-exit --no-attach backend
docker compose down

# Copy the bug_buckets directory to the report folder so that parser can find it
mkdir ./reports
cp -r ./restler_workspace/Fuzz/RestlerResults/*/bug_buckets ./reports/bug_buckets
mkdir -p ./reports/dist

# Run the parser to generate the final report
# restler report parser: https://github.com/yukicoder0509/restler-report-parser
docker run --rm -v ./reports/dist:/app/dist -v ./reports/bug_buckets:/app/src/assets/bug_buckets -p 4321:4321 yukicoder/restler-report-parser:latest

# Print the location of the final report
echo "Final report is located at ./reports/dist/index.html"
printf 'You can open it in a browser: file://%s\n' "$(pwd)/reports/dist/index.html"