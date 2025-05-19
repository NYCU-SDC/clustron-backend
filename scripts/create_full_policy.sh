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

# Clear the output file
> "$OUTPUT_FILE"

# Append all CSV data with newlines between files, except after the last one
for ((i = 0; i < ${#CSV_FILES[@]}; i++)); do
    cat "${CSV_FILES[i]}" >> "$OUTPUT_FILE"

    # Add newline if not the last file
    if [ $i -lt $((${#CSV_FILES[@]} - 1)) ]; then
        echo >> "$OUTPUT_FILE"
    fi
done

echo "Merged ${#CSV_FILES[@]} files into $OUTPUT_FILE"