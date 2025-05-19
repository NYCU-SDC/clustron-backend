#!/usr/bin/env bash

set -e

# Default values
OUTPUT_FILE="./internal/casbin/full_policy.csv"

# Print help message
print_help() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  --output-file PATH     Path to the merged CSV output file (default: ./full_policy.csv)"
    echo "  --help                 Show this help message and exit"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-file)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --help)
            print_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            print_help
            exit 1
            ;;
    esac
done

CSV_FILES=()

# Automatically find all policy.csv files under current directory and subdirectories
mapfile -t CSV_FILES < <(find . -type f -name "policy.csv")

# Check if any files found
if [ ${#CSV_FILES[@]} -eq 0 ]; then
    echo "No policy.csv files found."
    exit 1
fi

# Clear and initialize the output file with the header from the first file
head -n 1 "${CSV_FILES[0]}" > "$OUTPUT_FILE"

# Append all CSV data (excluding header from each file)
for CSV in "${CSV_FILES[@]}"; do
    echo >> "$OUTPUT_FILE"
    tail -n +2 "$CSV" >> "$OUTPUT_FILE"
done

echo "Merged ${#CSV_FILES[@]} files into $OUTPUT_FILE"