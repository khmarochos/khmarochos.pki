#!/bin/bash
#
# Copyright 2023 Volodymyr Melnyk
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Docker entrypoint script for khmarochos.pki container.
# This script runs ansible-playbook with the mounted configuration
# and tracks PKI state changes before and after execution.
#
# Environment variables:
#   PLAYBOOK_FILE     - Path to the Ansible playbook (default: ./playbook.yaml)
#   CA_TREE_FILE      - Path to the CA hierarchy configuration (default: ./vars/ca-tree.yaml)
#   CERTIFICATES_FILE - Path to the certificates configuration (default: ./vars/certificates.yaml)
#   ARTIFACTS_DIRECTORY - Path to the PKI artifacts directory (default: ./pki)
#   PKI_STATE_DIR     - Path to the state snapshots' directory (create a new temporary one by default)

set -euo pipefail

# Constants
readonly SCRIPT_NAME="$(basename "${0}")"
readonly DEFAULT_PLAYBOOK="/app/playbook-default.yaml"
readonly STATE_DUMP_SCRIPT="/app/scripts/state_dump.py"
readonly STATE_COMPARE_SCRIPT="/app/scripts/state_compare.py"

# Global variables (configurable via environment variables)
PLAYBOOK_FILE="${PLAYBOOK_FILE:-./playbook.yaml}"
CA_TREE_FILE="${CA_TREE_FILE:-./vars/ca-tree.yaml}"
CERTIFICATES_FILE="${CERTIFICATES_FILE:-./vars/certificates.yaml}"
ARTIFACTS_DIRECTORY="${ARTIFACTS_DIRECTORY:-./pki}"
PKI_STATE_DIR="${PKI_STATE_DIR:-"$(mktemp -d)"}"

# Print error message and exit.
# Arguments:
#   $1: Error message
err() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] ${SCRIPT_NAME}: ERROR: $*" >&2
}

# Print warning message.
# Arguments:
#   $1: Warning message
warn() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] ${SCRIPT_NAME}: WARNING: $*" >&2
}

# Print info message.
# Arguments:
#   $1: Info message
info() {
  echo "[$(date +'%Y-%m-%dT%H:%M:%S%z')] ${SCRIPT_NAME}: $*"
}

# Display current configuration.
show_configuration() {
  info "Configuration:"
  info "  PLAYBOOK_FILE:     ${PLAYBOOK_FILE}"
  info "  CA_TREE_FILE:      ${CA_TREE_FILE}"
  info "  CERTIFICATES_FILE: ${CERTIFICATES_FILE}"
  info "  ARTIFACTS_DIRECTORY: ${ARTIFACTS_DIRECTORY}"
  info "  PKI_STATE_DIR:     ${PKI_STATE_DIR}"
}

# Check if required configuration files exist and set up defaults if needed.
check_configuration_files() {
  # Check if playbook.yaml exists, create symlink to default if missing or empty
  if [[ ! -f "${PLAYBOOK_FILE}" || ! -s "${PLAYBOOK_FILE}" ]]; then
    warn "playbook.yaml not found or empty - using default playbook"
    info "To use a custom playbook, mount it as ${PLAYBOOK_FILE} in the container"
    ln -sf "${DEFAULT_PLAYBOOK}" "${PLAYBOOK_FILE}"
  fi

  # Check for required CA tree configuration
  if [[ ! -f "${CA_TREE_FILE}" ]]; then
    err "${CA_TREE_FILE} not found"
    err "Please mount your CA hierarchy configuration as ${CA_TREE_FILE} in the container"
    exit 1
  fi

  # Check for required certificates configuration
  if [[ ! -f "${CERTIFICATES_FILE}" ]]; then
    err "${CERTIFICATES_FILE} not found"
    err "Please mount your certificate definitions as ${CERTIFICATES_FILE} in the container"
    exit 1
  fi

  # Check for the state snapshots' directory
  if [[ ! -d "${PKI_STATE_DIR}" ]]; then
    err "${PKI_STATE_DIR} not found"
    err "Please mount your state snapshots' directory as ${PKI_STATE_DIR} in the container or unset the PKI_STATE_DIR variable"
    exit 1
  fi
}

# Dump PKI state to a JSON file.
# Arguments:
#   $1: Output file path
#   $2: Description for logging
dump_pki_state() {
  local output_file="$1"
  local description="$2"
  local pki_root_dir=""
  local dir
  local parent_dir

  info "Dumping PKI state: ${description}"

  # Determine PKI root directory (use ARTIFACTS_DIRECTORY first, then look for common locations)
  if [[ -d "${ARTIFACTS_DIRECTORY}" ]]; then
    pki_root_dir="${ARTIFACTS_DIRECTORY}"
  else
    # Try to find any directory containing CA structure
    while IFS= read -r -d '' dir; do
      parent_dir="$(dirname "${dir}")"
      if [[ -d "${parent_dir}/certs" && -d "${parent_dir}/private" ]]; then
        pki_root_dir="$(dirname "${parent_dir}")"
        break
      fi
    done < <(find . -maxdepth 3 -type d -name "private" -print0 2>/dev/null | head -z -5)
  fi

  if [[ -n "${pki_root_dir}" && -d "${pki_root_dir}" ]]; then
    info "Found PKI directory: ${pki_root_dir}"
    if ! python3 "${STATE_DUMP_SCRIPT}" "${pki_root_dir}" -o "${output_file}" 2>/dev/null; then
      warn "Failed to dump PKI state from ${pki_root_dir}"
      echo '{"authorities": {}}' > "${output_file}"
    fi
  else
    warn "No PKI directory found, creating empty state"
    echo '{"authorities": {}}' > "${output_file}"
  fi
}

# Compare PKI states and display differences.
# Arguments:
#   $1: Path to old state file
#   $2: Path to new state file
compare_pki_states() {
  local old_state="$1"
  local new_state="$2"
  local force_color=""

  if [[ "$(echo "${FORCE_COLOR}" | tr '[:upper:]' '[:lower:]')" == "true" ]]; then
    force_color="--color"
  else
    force_color="--"
  fi

  if [[ -f "${old_state}" && -f "${new_state}" ]]; then
    if ! python3 "${STATE_COMPARE_SCRIPT}" "${force_color}" "${old_state}" "${new_state}" 2>/dev/null; then
      warn "Failed to compare PKI states"
      warn "Old state: ${old_state}"
      warn "New state: ${new_state}"
    fi
  else
    warn "State files not found for comparison"
    [[ ! -f "${old_state}" ]] && warn "Missing: ${old_state}"
    [[ ! -f "${new_state}" ]] && warn "Missing: ${new_state}"
  fi

  echo ""
}

# Run Ansible playbook with PKI state tracking.
run_ansible_with_state_tracking() {
  local -r old_state="${PKI_STATE_DIR}/pki_state_before.json"
  local -r new_state="${PKI_STATE_DIR}/pki_state_after.json"

  # Dump PKI state before running Ansible
  dump_pki_state "${old_state}" "before Ansible execution"

  echo ""
  info "Running Ansible playbook..."
  ansible-playbook "${PLAYBOOK_FILE}"

  echo ""
  info "Ansible playbook completed."

  # Dump PKI state after running Ansible
  dump_pki_state "${new_state}" "after Ansible execution"

  # Compare states and show changes
  compare_pki_states "${old_state}" "${new_state}"
}

# Main execution logic
main() {
  # Display current configuration
  show_configuration
  echo ""

  # Check configuration files first
  check_configuration_files

  # If no arguments provided, run with state tracking
  if [[ $# -eq 0 ]]; then
    run_ansible_with_state_tracking
  else
    # Execute provided command
    exec "$@"
  fi
}

# Call main function with all arguments
main "$@"