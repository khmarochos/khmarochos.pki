#!/usr/bin/env bash

#
# Constants
#

declare -r LOGGER_OUT="1"
declare -r LOGGER_ERR="2"

#
# Logging functions
#

_log_file() {
    if [[ -z ${LOG_FILE} ]]; then
        warn "The LOG_FILE variable is unset, won't write to the log file."
        return
    fi
    local tag
    local output="${1}"
    case "${output}" in
        "${LOGGER_OUT}")
            tag='OUT'
            shift
            ;;
        "${LOGGER_ERR}")
            tag='ERR'
            shift
            ;;
        *)
            warn "The _log_file() function requires the output stream's number, got '${output}' instead."
            tag='???'
            ;;
    esac
    echo "${LOG_TIME_FORMAT:-+%Y-%m-%d %H:%M:%S} [${tag}] ${*}" >>"${LOG_FILE}"
}

_log_output() {
    local output="${1}"
    if [[ "${output}" -ne "${LOGGER_OUT}" && "${output}" -ne "${LOGGER_ERR}" ]]; then
        warn "The _log_output() function requires the output stream's number, got '${output}' instead, exiting."
        output="${LOGGER_OUT}"
    else
        shift
    fi
    echo "${*}" >&"${output}"
    test -n "${LOG_FILE}" && _log_file "${output}" "${*}"
}

log() {
    _log_output "${LOGGER_OUT}" "${@}"
}

warn() {
    _log_output "${LOGGER_ERR}" "${@}"
}

#
# Shutdown functions
#

die() {
    local exit_code="${1}"
    if [[ ! "${exit_code}" =~ ^[0-9]+$ ]]; then
        warn "The die() function requires the exit code, got '${exit_code}' instead."
        exit_code=-1
    else
        shift
    fi
    warn "${*} (EXIT CODE: ${exit_code})"
    exit "${exit_code}"
}

cleanup() {
    if [[ -v __TO_BE_REMOVED[@] && ${#TO_BE_REMOVED[@]} -ne 0 ]]; then
        local entity_to_remove
        for entity_to_remove in "${!__TO_BE_REMOVED[@]}"; do
            log "Removing ${__TO_BE_REMOVED[${entity_to_remove}]}..."
            rm -rf "${__TO_BE_REMOVED[${entity_to_remove}]}"
            if [[ ${?} -ne 0 ]]; then
                warn "Can't remove ${__TO_BE_REMOVED[${entity_to_remove}]}."
            fi
        done
    fi
}

# Set trap to ensure cleanup happens even on error
trap cleanup EXIT INT TERM

#
# Usage function
#

usage() {
    cat >&2 <<EOF
Usage: $(basename "${0}") [OPTIONS] <certificate_path>

Generate a Kubernetes secret from PKI certificates.

ARGUMENTS:

  certificate_path    Path in format: ca_nickname/certificate_nickname or
                      just certificate_nickname. If certificate_nickname
                      starts with '^' after /, it's an intermediate sub-CA.

OPTIONS:

  -c, --ca-nickname <name>
        CA nickname (if not specified in certificate_path)

      --pki-base <path>
        PKI base directory (default: ${HOME}/pki)

      --ca-no-chain
        Use CA certificate without chain

      --ca-with-chain
        Use CA certificate with chain (default behaviour)

      --certificate-no-chain
        Use certificate without chain

      --certificate-with-chain
        Use certificate with chain (default behaviour)

      --opaque
        Create Opaque type secret (default: kubernetes.io/tls)

      --no-ca
        Don't include CA certificate in the secret

      --log-file <path>
        Log file path (overrides LOG_FILE env var)

      --log-time-format <format>
        Log time format (overrides LOG_TIME_FORMAT env var)

  -h, --help
        Show this help message

EOF
}

#
# Main script
#

# Variables
pki_base=""
ca_nickname=""
ca_with_chain=1
certificate_with_chain=1
opaque=0
no_ca=0
certificate_path=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -c|--ca-nickname)
            ca_nickname="$2"
            shift 2
            ;;
        --pki-base)
            pki_base="$2"
            shift 2
            ;;
        --ca-no-chain)
            ca_with_chain=0
            shift
            ;;
        --ca-with-chain)
            ca_with_chain=1
            shift
            ;;
        --certificate-no-chain)
            certificate_with_chain=0
            shift
            ;;
        --certificate-with-chain)
            certificate_with_chain=1
            shift
            ;;
        --opaque)
            opaque=1
            shift
            ;;
        --no-ca)
            no_ca=1
            shift
            ;;
        --log-file)
            LOG_FILE="$2"
            shift 2
            ;;
        --log-time-format)
            LOG_TIME_FORMAT="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            usage
            die 1 "Unknown option: $1"
            ;;
        *)
            # Positional argument
            if [[ -z "${certificate_path}" ]]; then
                certificate_path="$1"
            else
                usage
                die 1 "Too many positional arguments"
            fi
            shift
            ;;
    esac
done

# Check if certificate path is provided
if [[ -z "${certificate_path}" ]]; then
    usage
    die 1 "Certificate path is required"
fi

# Determine PKI base directory
if [[ -z "${pki_base}" ]]; then
    pki_base="${HOME}/pki"
fi

# Check if PKI base exists
if [[ ! -d "${pki_base}" ]]; then
    die 2 "PKI base directory does not exist: ${pki_base}"
fi

# Extract CA nickname and certificate nickname from path
if [[ "${certificate_path}" == */* ]]; then
    # Format: ca_nickname/certificate_nickname
    ca_nickname_from_path="${certificate_path%%/*}"
    certificate_nickname="${certificate_path#*/}"
    
    # If CA nickname not set via parameter, use the one from path
    if [[ -z "${ca_nickname}" ]]; then
        ca_nickname="${ca_nickname_from_path}"
    fi
else
    # Format: just certificate_nickname
    certificate_nickname="${certificate_path}"
    
    # CA nickname must be set via parameter
    if [[ -z "${ca_nickname}" ]]; then
        usage
        die 3 "CA nickname must be specified with -c/--ca-nickname when certificate path doesn't include it"
    fi
fi

# Set CA directory
ca_directory="${pki_base}/${ca_nickname}"

# Check if CA directory exists
if [[ ! -d "${ca_directory}" ]]; then
    die 4 "CA directory does not exist: ${ca_directory}"
fi

# Check if this is an intermediate sub-CA certificate
is_intermediate_ca=0
if [[ "${certificate_nickname}" == ^* ]]; then
    is_intermediate_ca=1
    # Remove the ^ prefix for actual file operations
    certificate_nickname="${certificate_nickname#^}"
fi

# Determine where to look for certificate and key
if [[ ${is_intermediate_ca} -eq 1 ]]; then
    # For intermediate sub-CAs, look in their own directories
    certificate_base_dir="${pki_base}/${certificate_nickname}"
    certificate_dir="${certificate_base_dir}/certs/CA"
    private_key_dir="${certificate_base_dir}/private/CA"
else
    # For regular certificates, look in the CA's directories
    certificate_dir="${ca_directory}/certs"
    private_key_dir="${ca_directory}/private"
fi

# Find CA certificate
if [[ ${ca_with_chain} -eq 1 ]]; then
    ca_certificate_file="${ca_directory}/certs/CA/${ca_nickname}.chain.crt"
else
    ca_certificate_file="${ca_directory}/certs/CA/${ca_nickname}.crt"
fi

if [[ ! -f "${ca_certificate_file}" ]]; then
    die 5 "CA certificate file not found: ${ca_certificate_file}"
fi

ca_certificate_encoded_file="$(mktemp -t ca_certificate.XXXXXX)"
__TO_BE_REMOVED+=("${ca_certificate_encoded_file}")
base64 -w 0 "${ca_certificate_file}" > "${ca_certificate_encoded_file}"

# Find certificate
if [[ ${certificate_with_chain} -eq 1 ]]; then
    certificate_file="${certificate_dir}/${certificate_nickname}.chain.crt"
else
    certificate_file="${certificate_dir}/${certificate_nickname}.crt"
fi

if [[ ! -f "${certificate_file}" ]]; then
    die 6 "Certificate file not found: ${certificate_file}"
fi

certificate_encoded_file="$(mktemp -t certificate.XXXXXX)"
__TO_BE_REMOVED+=("${certificate_encoded_file}")
base64 -w 0 "${certificate_file}" > "${certificate_encoded_file}"

# Find private key
private_key_file="${private_key_dir}/${certificate_nickname}.key"

if [[ ! -f "${private_key_file}" ]]; then
    die 7 "Private key file not found: ${private_key_file}"
fi

private_key_encoded_file="$(mktemp -t private_key.XXXXXX)"
__TO_BE_REMOVED+=("${private_key_encoded_file}")
chmod 600 "${private_key_encoded_file}"
# Check if key is encrypted
if grep -q "ENCRYPTED" "${private_key_file}" 2>/dev/null; then
    # Look for passphrase file
    passphrase_file="${private_key_file}_passphrase"
    if [[ -f "${passphrase_file}" ]]; then
        passphrase="$(<"${passphrase_file}")"
        # Decrypt the key
	openssl rsa -in "${private_key_file}" -passin "pass:${passphrase}" 2>/dev/null | base64 -w 0 > "${private_key_encoded_file}"
        if [[ $? -ne 0 ]]; then
            die 8 "Failed to decrypt private key: ${private_key_file}"
        fi
    else
        die 9 "Private key is encrypted but passphrase file not found: ${passphrase_file}"
    fi
else
    # Key is not encrypted
    base64 -w 0 "${private_key_file}" > "${private_key_encoded_file}"
fi

# Generate Kubernetes secret
if [[ ${opaque} -eq 1 ]]; then
    secret_type="Opaque"
else
    secret_type="kubernetes.io/tls"
fi
cat <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${certificate_nickname}-tls
type: ${secret_type}
data:
  tls.crt: $(<"${certificate_encoded_file}")
  tls.key: $(<"${private_key_encoded_file}")
EOF
if [[ ${no_ca} -ne 1 ]]; then
    cat <<EOF   
  ca.crt: $(<"${ca_certificate_encoded_file}")
EOF
fi
