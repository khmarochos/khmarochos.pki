#!/bin/bash
set -e

# Docker entrypoint script for khmarochos.pki container
# This script runs ansible-playbook with the mounted configuration
# and tracks PKI state changes before and after execution

# Check if playbook.yaml exists, create symlink to default if missing or empty
if [ ! -f "./playbook.yaml" ] || [ ! -s "./playbook.yaml" ]; then
    echo "WARNING: playbook.yaml not found or empty - using default playbook"
    echo "To use a custom playbook, mount it as ./playbook.yaml in the container"
    ln -sf /app/playbook-default.yaml ./playbook.yaml
fi

if [ ! -f "./vars/ca-tree.yaml" ]; then
    echo "Error: vars/ca-tree.yaml not found"
    echo "Please mount your CA hierarchy configuration as ./vars/ca-tree.yaml in the container"
    exit 1
fi

if [ ! -f "./vars/certificates.yaml" ]; then
    echo "Error: vars/certificates.yaml not found"
    echo "Please mount your certificate definitions as ./vars/certificates.yaml in the container"
    exit 1
fi

# Function to dump PKI state
dump_pki_state() {
    local output_file="$1"
    local description="$2"
    
    echo "Dumping PKI state: $description"
    
    # Determine PKI root directory (look for common locations)
    local pki_root_dir=""
    
    if [ -d "./pki" ]; then
        pki_root_dir="./pki"
    elif [ -d "/tmp/pki" ]; then
        pki_root_dir="/tmp/pki"
    elif [ -d "/app/pki" ]; then
        pki_root_dir="/app/pki"
    else
        # Try to find any directory containing CA structure
        for dir in $(find . -maxdepth 3 -type d -name "private" 2>/dev/null | head -5); do
            parent_dir=$(dirname "$dir")
            if [ -d "$parent_dir/certs" ] && [ -d "$parent_dir/private" ]; then
                pki_root_dir=$(dirname "$parent_dir")
                break
            fi
        done
    fi
    
    if [ -n "$pki_root_dir" ] && [ -d "$pki_root_dir" ]; then
        echo "Found PKI directory: $pki_root_dir"
        python3 /app/scripts/state_dump.py "$pki_root_dir" -o "$output_file" 2>/dev/null || {
            echo "Warning: Failed to dump PKI state from $pki_root_dir"
            echo '{"authorities": {}}' > "$output_file"
        }
    else
        echo "Warning: No PKI directory found, creating empty state"
        echo '{"authorities": {}}' > "$output_file"
    fi
}

# Function to compare PKI states
compare_pki_states() {
    local old_state="$1"
    local new_state="$2"
    
    if [ -f "$old_state" ] && [ -f "$new_state" ]; then
        python3 /app/scripts/state_compare.py "$old_state" "$new_state" 2>/dev/null || {
            echo "Warning: Failed to compare PKI states"
            echo "Old state: $old_state"
            echo "New state: $new_state"
        }
    else
        echo "Warning: State files not found for comparison"
        [ ! -f "$old_state" ] && echo "Missing: $old_state"
        [ ! -f "$new_state" ] && echo "Missing: $new_state"
    fi
    
    echo ""
}

# Run ansible-playbook with the provided arguments
# If no arguments provided, use the default playbook
if [ $# -eq 0 ]; then
    # Define state file paths
    STATE_DIR="/tmp/pki_states"
    mkdir -p "$STATE_DIR"
    OLD_STATE="$STATE_DIR/pki_state_before.json"
    NEW_STATE="$STATE_DIR/pki_state_after.json"
    
    # Dump PKI state before running Ansible
    dump_pki_state "$OLD_STATE" "before Ansible execution"
    
    echo ""
    echo "Running Ansible playbook..."
    ansible-playbook ./playbook.yaml
    
    echo ""
    echo "Ansible playbook completed."
    
    # Dump PKI state after running Ansible
    dump_pki_state "$NEW_STATE" "after Ansible execution"
    
    # Compare states and show changes
    compare_pki_states "$OLD_STATE" "$NEW_STATE"
    
else
    exec "$@"
fi