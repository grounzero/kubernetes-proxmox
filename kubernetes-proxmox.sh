#!/usr/bin/env bash
set -euo pipefail

############################################
# COMMAND LINE ARGUMENT PARSING
############################################

MENU_MODE=true
CHOSEN_ACTION=""

show_help() {
    cat <<EOF
Usage: $0 [OPTIONS]

Kubernetes on Proxmox - Cluster Management Script

OPTIONS:
    -a ACTION    Run in non-interactive mode with specified action
                 Actions: install, reconfigure, scale, reset, destroy, status, cleanup, update-deps, export-kubeconfig
    -h           Show this help message

EXAMPLES:
    # Interactive mode (default)
    $0

    # Non-interactive mode
    $0 -a install       # Fresh install from scratch
    $0 -a reconfigure   # Update existing cluster
    $0 -a status        # View cluster status
    $0 -a cleanup       # Kill stuck processes
    $0 -a update-deps   # Update packages on all nodes
    $0 -a export-kubeconfig  # Export kubeconfig for Lens/external access

EOF
}

while getopts "a:h" opt; do
    case $opt in
        a) MENU_MODE=false; CHOSEN_ACTION="${OPTARG}" ;;
        h) show_help; exit 0 ;;
        *) show_help; exit 1 ;;
    esac
done

############################################
# CLEANUP PREVIOUS RUNS
############################################

cleanup_previous_run() {
    # Ensure network config is initialized if not already done
    if [[ -z "${CP_IP}" ]]; then
        detect_network_config
        apply_network_defaults
    fi

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Cleaning up previous runs..."

    # Kill any running ansible-playbook processes
    pkill -f ansible-playbook 2>/dev/null || true

    # Clean up SSH control sockets
    rm -rf /root/.ansible/cp/* 2>/dev/null || true

    # Kill old wait loops and stuck processes on VMs if they're accessible
    # Build target IPs without using ip_add_octet (avoid function ordering dependency)
    local targets=()
    [[ -n "${CP_IP}" ]] && targets=("${CP_IP}")
    for ((i=0; i<10; i++)); do
        targets+=("${WORKER_IP_BASE}$((WORKER_IP_START_OCTET + i))")
    done

    # Only proceed if SSH key exists
    if [[ ! -f "${VM_SSH_KEY_PATH}" ]]; then
        echo "  Skipping VM cleanup (SSH key not found)"
        return 0
    fi

    for ip in "${targets[@]}"; do
        # Skip if IP is empty
        [[ -z "${ip}" ]] && continue

        # Quick ping check to avoid slow SSH timeouts
        if ! ping -c1 -W1 "${ip}" >/dev/null 2>&1; then
            continue
        fi

        # SSH in and kill helper processes
        ssh_vm_opts "${ip}" "-o ConnectTimeout=2" \
            "sudo pkill -f 'while fuser' 2>/dev/null || true; sudo pkill -f apt_news.py 2>/dev/null || true; sudo pkill -f esm_cache.py 2>/dev/null || true" \
            2>/dev/null || true
    done

    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Cleanup complete"
    sleep 2
}

############################################
# USER CONFIGURABLE VARIABLES
############################################

# Proxmox storage and networking
PM_STORAGE="local-lvm"
PM_BRIDGE="vmbr0"

# Auto-detect network configuration from Proxmox host
detect_network_config() {
    local bridge="${PM_BRIDGE}"
    
    # Get bridge IP and calculate network
    local bridge_info=$(ip -4 addr show "${bridge}" 2>/dev/null | grep "inet ")
    
    if [[ -z "${bridge_info}" ]]; then
        echo "ERROR: Could not detect IP configuration on bridge ${bridge}" >&2
        echo "Please ensure ${bridge} exists and has an IP address configured" >&2
        exit 1
    fi
    
    # Extract IP address and CIDR
    local host_ip=$(echo "${bridge_info}" | awk '{print $2}' | cut -d'/' -f1)
    local host_cidr=$(echo "${bridge_info}" | awk '{print $2}' | cut -d'/' -f2)
    
    # Extract network prefix (assumes /24 - warn if not)
    local network_prefix=$(echo "${host_ip}" | cut -d'.' -f1-3)
    
    # Warn if not /24
    if [[ "${host_cidr}" != "24" ]]; then
        echo "WARNING: Detected CIDR /${host_cidr}. Default VM IP allocation assumes /24." >&2
        echo "         Override CP_IP and WORKER_IP_BASE if needed, or implement proper CIDR math." >&2
    fi
    
    # Detect gateway from default route (more reliable than ping)
    local detected_gateway=$(ip route show default 0.0.0.0/0 | awk '{print $3}' | head -n1)
    
    # Fallback to .1 if no default route
    if [[ -z "${detected_gateway}" ]]; then
        detected_gateway="${network_prefix}.1"
        echo "WARNING: No default route found, using ${detected_gateway} as gateway" >&2
    fi
    
    # Export detected values
    AUTO_DETECTED_NETWORK_PREFIX="${network_prefix}"
    AUTO_DETECTED_CIDR="${host_cidr}"
    AUTO_DETECTED_GATEWAY="${detected_gateway}"
    AUTO_DETECTED_HOST_IP="${host_ip}"
}

# Network configuration - will be set after detect_network_config() runs
# You can override these by setting them as environment variables before running
# Example: CP_IP=10.0.0.60 ./kubernetes-proxmox.sh
NET_CIDR_PREFIX="${NET_CIDR_PREFIX:-}"
NET_GATEWAY="${NET_GATEWAY:-}"
NET_DNS="${NET_DNS:-1.1.1.1}"
CP_IP="${CP_IP:-}"
WORKER_IP_BASE="${WORKER_IP_BASE:-}"
WORKER_IP_START_OCTET="${WORKER_IP_START_OCTET:-61}"

# Function to apply detected network config (called after detection)
apply_network_defaults() {
    NET_CIDR_PREFIX="${NET_CIDR_PREFIX:-${AUTO_DETECTED_CIDR}}"
    NET_GATEWAY="${NET_GATEWAY:-${AUTO_DETECTED_GATEWAY}}"
    CP_IP="${CP_IP:-${AUTO_DETECTED_NETWORK_PREFIX}.60}"
    WORKER_IP_BASE="${WORKER_IP_BASE:-${AUTO_DETECTED_NETWORK_PREFIX}.}"
}

# Ubuntu cloud image
UBUNTU_RELEASE="24.04"
UBUNTU_IMAGE_DIR="/var/lib/vz/template/iso"
UBUNTU_IMAGE_FILE=""

# Template and VM IDs
TEMPLATE_VMID="9000"
CP_VMID="9100"
WORKER_VMID_START="9101"
WORKER_COUNT="3"

# VM sizing (separate settings for template, control plane, and workers)
TEMPLATE_CORES="2"
TEMPLATE_MEMORY_MB="2048"
TEMPLATE_DISK_GB="30"
CP_CORES="2"
CP_MEMORY_MB="2048"
CP_DISK_GB="50"
WORKER_CORES="2"
WORKER_MEMORY_MB="4096"
WORKER_DISK_GB="50"

# Cloud-init and SSH
VM_USER="ubuntu"
VM_SSH_KEY_PATH="/root/.ssh/id_ed25519"
VM_SSH_PUBKEY_PATH="/root/.ssh/id_ed25519.pub"

# Kubernetes configuration (latest stable versions as of Jan 2026)
K8S_CHANNEL="v1.35"
K8S_SEMVER="1.35.0"
K8S_PKG_VERSION="1.35.0-1.1"
POD_CIDR="192.168.0.0/16"
SERVICE_CIDR="10.96.0.0/12"
CALICO_VERSION="v3.31.3"
CALICO_MANIFEST_URL="https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"

# Miscellaneous
ANSIBLE_DIR="/root/proxmox-k8s-ansible"
ANSIBLE_INVENTORY="${ANSIBLE_DIR}/inventory.ini"
ANSIBLE_CFG="${ANSIBLE_DIR}/ansible.cfg"
ANSIBLE_PLAYBOOK="${ANSIBLE_DIR}/site.yml"
VM_NAME_PREFIX="k8s"
STARTUP_WAIT_SECONDS="10"
# Configurable via environment variable (default: 600 seconds for SSH, 300 for cloud-init)
SSH_WAIT_TIMEOUT_SECONDS="${SSH_WAIT_TIMEOUT_SECONDS:-600}"
CLOUD_INIT_TIMEOUT_SECONDS="${CLOUD_INIT_TIMEOUT_SECONDS:-300}"

# Resource validation settings
MIN_REQUIRED_MEMORY_MB="8192"  # Minimum 8GB for control plane + 2 workers
MIN_REQUIRED_DISK_GB="100"     # Minimum 100GB free space
RESOURCE_CHECK_ENABLED="${RESOURCE_CHECK_ENABLED:-true}"  # Set to false to skip checks

# Fresh install flag (internal - set by action_fresh_install to skip IP conflict checks)
SKIP_IP_CONFLICT_CHECK="${SKIP_IP_CONFLICT_CHECK:-false}"

# Kubeconfig export settings
KUBECONFIG_EXPORT_DIR="${KUBECONFIG_EXPORT_DIR:-/root/kubeconfigs}"

############################################
# INTERNAL HELPERS
############################################

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

pve_has_vmid() {
    qm status "$1" >/dev/null 2>&1
}

ensure_root() {
    if [[ "${EUID:-0}" -ne 0 ]]; then
        log "ERROR: This script must be run as root."
        exit 1
    fi
}

ensure_dirs() {
    mkdir -p "${UBUNTU_IMAGE_DIR}"
    mkdir -p "${ANSIBLE_DIR}"
}

ubuntu_image_url() {
    local rel="$1"
    case "$rel" in
        "22.04") echo "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img" ;;
        "24.04") echo "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img" ;;
        *)
            log "ERROR: Unsupported UBUNTU_RELEASE: ${rel} (use 22.04 or 24.04)"
            exit 1
            ;;
    esac
}

ubuntu_image_filename() {
    local rel="$1"
    case "$rel" in
        "22.04") echo "jammy-server-cloudimg-amd64.img" ;;
        "24.04") echo "noble-server-cloudimg-amd64.img" ;;
        *) echo "" ;;
    esac
}

wait_for_ssh() {
    local ip="$1"
    local start_ts now_ts elapsed
    start_ts="$(date +%s)"
    log "Waiting for SSH on ${ip}..."
    
    local retry_count=0
    while true; do
        retry_count=$((retry_count + 1))
        
        if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
               -i "${VM_SSH_KEY_PATH}" "${VM_USER}@${ip}" "echo ok" >/dev/null 2>&1; then
            log "SSH ready on ${ip}"
            return 0
        fi
        
        now_ts="$(date +%s)"
        elapsed=$((now_ts - start_ts))
        
        # Log progress every 30 seconds
        if (( retry_count % 6 == 0 )); then
            log "Still waiting for SSH on ${ip} (${elapsed}s)..."
            
            # Check if we can at least ping the host
            if ping -c 1 -W 2 "${ip}" >/dev/null 2>&1; then
                log "  Host reachable via ping, SSH not ready"
            else
                log "  WARNING: Host not responding to ping - check VM status"
            fi
        fi
        
        if (( elapsed > SSH_WAIT_TIMEOUT_SECONDS )); then
            log "ERROR: SSH timeout on ${ip} after ${elapsed}s"
            log "Troubleshooting steps:"
            log "  1. Check VM console: qm terminal <vmid>"
            log "  2. Check cloud-init status inside VM"
            log "  3. Verify network configuration: qm config <vmid>"
            log "  4. Check if qemu-guest-agent is running"
            exit 1
        fi
        sleep 5
    done
}

ip_add_octet() {
    local base="$1" start_octet="$2" index="$3"
    local octet=$(( start_octet + index ))
    echo "${base}${octet}"
}

# Extract a package section from Debian package info (Packages file format)
# Usage: extract_package_section "package-name" "${package_data}"
extract_package_section() {
    local package_name="$1"
    local package_data="$2"
    awk -v target_pkg="$package_name" '
        $0 == "Package: " target_pkg { in_pkg = 1; print; next }
        /^Package:/ && in_pkg { exit }
        in_pkg { print }
    ' <<< "${package_data}"
}

# Extract VG name from Proxmox storage configuration
# Usage: get_storage_vgname "storage-name"
# Returns: VG name string, or empty string if not found/not LVM storage
get_storage_vgname() {
    local storage_name="$1"

    # Try pvesm config first
    local vg_name
    vg_name=$(pvesm config "${storage_name}" 2>/dev/null | awk '
        $1 == "vgname" {
            for (i = 2; i <= NF; i++) {
                gsub(/:/, "", $i)
                if ($i != "") {
                    print $i
                    exit
                }
            }
        }
    ')

    # If that fails, try parsing /etc/pve/storage.cfg directly
    if [[ -z "${vg_name}" ]] && [[ -f "/etc/pve/storage.cfg" ]]; then
        vg_name=$(awk -v storage="${storage_name}" '
            $0 ~ "^(lvmthin|lvm): " storage "$" { in_storage=1; next }
            in_storage && /^$/ { exit }
            in_storage && /^\t?vgname/ { print $2; exit }
        ' /etc/pve/storage.cfg)
    fi

    echo "${vg_name}"
}

# Helper function to run SSH commands with standard options
# Usage: ssh_vm <ip> [command...]
# For custom SSH options, use: ssh_vm_opts <ip> "<ssh_options>" [command...]
ssh_vm() {
    local target="$1"
    shift
    ssh -i "${VM_SSH_KEY_PATH}" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "${VM_USER}@${target}" "$@"
}

# Helper function with custom SSH options
ssh_vm_opts() {
    local target="$1"
    local custom_opts_str="$2"
    local -a custom_opts=()

    # Split custom options string into an array so multiple options are passed correctly
    if [[ -n "${custom_opts_str}" ]]; then
        read -r -a custom_opts <<< "${custom_opts_str}"
    fi

    shift 2
    ssh -i "${VM_SSH_KEY_PATH}" \
        "${custom_opts[@]}" \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "${VM_USER}@${target}" "$@"
}

############################################
# SECURITY & VALIDATION FUNCTIONS
############################################

# Check and create SSH keys with security warnings
ensure_ssh_keys() {
    log "Checking SSH key configuration..."

    if [[ ! -f "${VM_SSH_KEY_PATH}" ]]; then
        log "WARNING: SSH key not found at ${VM_SSH_KEY_PATH}"
        log "WARNING: Creating new SSH key WITHOUT passphrase protection"
        log "WARNING: This key will be used for VM access and stored unencrypted"
        log ""

        if [[ "${MENU_MODE}" == "true" ]]; then
            echo "SECURITY NOTICE:"
            echo "  - The SSH key will be created at: ${VM_SSH_KEY_PATH}"
            echo "  - It will NOT have passphrase protection (required for automation)"
            echo "  - The key will be stored in /root/.ssh/ (only accessible to root)"
            echo "  - This key grants full access to all cluster VMs"
            echo ""

            if ! confirm_action "Continue with SSH key creation?"; then
                log "SSH key creation cancelled by user"
                exit 1
            fi
        fi

        log "Creating SSH key pair..."
        ssh-keygen -t ed25519 -f "${VM_SSH_KEY_PATH}" -N "" -C "proxmox-k8s-automation" || {
            local exit_code=$?
            log "ERROR: Failed to create SSH key at ${VM_SSH_KEY_PATH} (ssh-keygen exit code: ${exit_code})"
            log "       Common causes include:"
            log "         - ssh-keygen is not installed or not found in \$PATH"
            log "         - Insufficient permissions to write to $(dirname "${VM_SSH_KEY_PATH}")"
            log "         - The target directory does not exist"
            log "         - Low or exhausted disk space on the filesystem"
            log "       Troubleshooting steps:"
            log "         - Verify ssh-keygen is installed (e.g., 'ssh-keygen -h' or 'which ssh-keygen')"
            log "         - Check that $(dirname "${VM_SSH_KEY_PATH}") exists and is writable by the current user"
            log "         - Ensure there is sufficient free disk space"
            exit ${exit_code}
        }

        log "SSH key created successfully"
        log "Public key: ${VM_SSH_PUBKEY_PATH}"

        # Set restrictive permissions
        chmod 600 "${VM_SSH_KEY_PATH}"
        chmod 644 "${VM_SSH_PUBKEY_PATH}"
    else
        log "SSH key found at ${VM_SSH_KEY_PATH}"

        # Verify key permissions (cross-platform stat command)
        local key_perms=""
        if key_perms=$(stat -c '%a' "${VM_SSH_KEY_PATH}" 2>/dev/null); then
            # GNU stat format (Linux)
            :
        elif key_perms=$(stat -f '%OLp' "${VM_SSH_KEY_PATH}" 2>/dev/null); then
            # BSD stat format (macOS)
            :
        else
            log "WARNING: Unable to determine SSH key permissions. Forcing permissions to 600..."
            chmod 600 "${VM_SSH_KEY_PATH}"
            return
        fi
        if [[ "${key_perms}" != "600" ]]; then
            log "WARNING: SSH key has insecure permissions (${key_perms}). Setting to 600..."
            chmod 600 "${VM_SSH_KEY_PATH}"
        fi
    fi
}

# Validate network configuration
validate_network_config() {
    log "Validating network configuration..."
    local errors=0

    # Check if CIDR is actually /24
    if [[ "${NET_CIDR_PREFIX}" != "24" ]]; then
        log "WARNING: Network CIDR is /${NET_CIDR_PREFIX}, not /24"
        log "WARNING: IP allocation logic assumes /24 networks"
        log "WARNING: This may cause IP conflicts or connectivity issues"
        ((errors++))
    fi

    # Validate gateway is reachable
    if ! ping -c1 -W2 "${NET_GATEWAY}" >/dev/null 2>&1; then
        log "WARNING: Gateway ${NET_GATEWAY} is not responding to ping"
        log "WARNING: This may indicate network misconfiguration"
        ((errors++))
    fi

    # Check for IP conflicts (skip if requested, e.g., during fresh install after VM destruction)
    local conflict_found=false
    if [[ "${SKIP_IP_CONFLICT_CHECK}" == "false" ]]; then
        log "Checking for IP conflicts on planned VM addresses..."

        # Check control plane IP
        if ping -c1 -W1 "${CP_IP}" >/dev/null 2>&1; then
            if ! pve_has_vmid "${CP_VMID}"; then
                log "WARNING: IP ${CP_IP} is responding but VM ${CP_VMID} doesn't exist"
                log "WARNING: This may indicate an IP conflict"
                conflict_found=true
                ((errors++))
            fi
        fi

        # Check worker IPs
        for ((i=0; i<WORKER_COUNT; i++)); do
            local worker_ip="$(ip_add_octet "${WORKER_IP_BASE}" "${WORKER_IP_START_OCTET}" "${i}")"
            local worker_vmid=$((WORKER_VMID_START + i))

            if ping -c1 -W1 "${worker_ip}" >/dev/null 2>&1; then
                if ! pve_has_vmid "${worker_vmid}"; then
                    log "WARNING: IP ${worker_ip} is responding but VM ${worker_vmid} doesn't exist"
                    log "WARNING: This may indicate an IP conflict"
                    conflict_found=true
                    ((errors++))
                fi
            fi
        done

        if [[ "${conflict_found}" == "true" && "${MENU_MODE}" == "true" ]]; then
            echo ""
            echo "NETWORK WARNING: Potential IP conflicts detected!"
            echo "Continuing may cause network connectivity issues."
            echo ""
            if ! confirm_action "Continue anyway?"; then
                log "Deployment cancelled due to network conflicts"
                exit 1
            fi
        fi
    else
        log "Skipping IP conflict checks (fresh install mode)"
    fi

    if [[ "${errors}" -gt 0 ]]; then
        log "Network validation completed with ${errors} warning(s)"
    else
        log "Network validation passed"
    fi
}

# Check Proxmox host has sufficient resources
check_host_resources() {
    if [[ "${RESOURCE_CHECK_ENABLED}" != "true" ]]; then
        log "Resource checking disabled (RESOURCE_CHECK_ENABLED=false)"
        return 0
    fi

    log "Checking Proxmox host resources..."
    local warnings=0
    local errors=0

    # Calculate required resources
    local required_memory_mb=$((CP_MEMORY_MB + (WORKER_COUNT * WORKER_MEMORY_MB)))
    local required_disk_gb=$((CP_DISK_GB + (WORKER_COUNT * WORKER_DISK_GB) + TEMPLATE_DISK_GB))

    # Check available memory
    local total_memory_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    local available_memory_kb=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
    local total_memory_mb=$((total_memory_kb / 1024))
    local available_memory_mb=$((available_memory_kb / 1024))

    log "  Memory: ${available_memory_mb}MB available / ${total_memory_mb}MB total"
    log "  Required: ${required_memory_mb}MB for cluster VMs"

    if [[ "${available_memory_mb}" -lt "${required_memory_mb}" ]]; then
        log "ERROR: Insufficient memory!"
        log "ERROR: Available: ${available_memory_mb}MB, Required: ${required_memory_mb}MB"
        ((errors++))
    elif [[ "${available_memory_mb}" -lt $((required_memory_mb + 2048)) ]]; then
        log "WARNING: Low memory margin (less than 2GB free after allocation)"
        ((warnings++))
    fi

    # Check available disk space on storage
    local storage_path
    case "${PM_STORAGE}" in
        "local-lvm"|"lvmthin")
            # LVM thin storage - use pvesm status (not VG free space)
            # Thin pools are pre-allocated, so VG free space is misleading
            local avail_gb=0
            local avail_kb

            # Get available space from pvesm status
            avail_kb=$(pvesm status -storage "${PM_STORAGE}" 2>/dev/null | grep "${PM_STORAGE}" | awk '{print $6}')
            if [[ -n "${avail_kb}" ]] && [[ "${avail_kb}" =~ ^[0-9]+$ ]]; then
                avail_gb=$((avail_kb / 1024 / 1024))
            fi

            log "  Disk: ${avail_gb}GB available on ${PM_STORAGE}"

            if [[ "${avail_gb}" -eq 0 ]]; then
                log "WARNING: Could not determine disk space for ${PM_STORAGE}"
                log "WARNING: Skipping disk space check (continuing anyway)"
                ((warnings++))
            elif [[ "${avail_gb}" -lt "${required_disk_gb}" ]]; then
                log "ERROR: Insufficient disk space!"
                log "ERROR: Available: ${avail_gb}GB, Required: ${required_disk_gb}GB"
                ((errors++))
            elif [[ "${avail_gb}" -lt $((required_disk_gb + 20)) ]]; then
                log "WARNING: Low disk space margin (less than 20GB free after allocation)"
                ((warnings++))
            fi
            ;;
        "local"|"local-zfs")
            # Directory or ZFS storage - check filesystem
            storage_path=$(pvesm path "${PM_STORAGE}:0" 2>/dev/null | xargs dirname || echo "/var/lib/vz")
            local avail_gb=$(df -BG "${storage_path}" | tail -1 | awk '{print $4}' | tr -d 'G')
            log "  Disk: ${avail_gb}GB available on ${PM_STORAGE} (${storage_path})"

            if [[ "${avail_gb}" -lt "${required_disk_gb}" ]]; then
                log "ERROR: Insufficient disk space!"
                log "ERROR: Available: ${avail_gb}GB, Required: ${required_disk_gb}GB"
                ((errors++))
            elif [[ "${avail_gb}" -lt $((required_disk_gb + 20)) ]]; then
                log "WARNING: Low disk space margin (less than 20GB free after allocation)"
                ((warnings++))
            fi
            ;;
        *)
            log "WARNING: Unknown storage type ${PM_STORAGE}, skipping disk check"
            ((warnings++))
            ;;
    esac

    # Check CPU cores (informational only)
    local cpu_cores=$(nproc)
    local required_cores=$((CP_CORES + (WORKER_COUNT * WORKER_CORES)))
    log "  CPU: ${cpu_cores} cores available, ${required_cores} cores will be allocated"

    if [[ "${cpu_cores}" -lt "${required_cores}" ]]; then
        log "WARNING: Allocated vCPUs (${required_cores}) exceed physical cores (${cpu_cores})"
        log "WARNING: This will cause CPU overcommitment (may impact performance)"
        ((warnings++))
    fi

    # Report results
    if [[ "${errors}" -gt 0 ]]; then
        log "ERROR: Resource check failed with ${errors} error(s) and ${warnings} warning(s)"
        log "ERROR: Cannot proceed with deployment"

        if [[ "${MENU_MODE}" == "true" ]]; then
            echo ""
            echo "INSUFFICIENT RESOURCES!"
            echo "Please free up resources or reduce VM sizing in the script variables:"
            echo "  - CP_MEMORY_MB (currently: ${CP_MEMORY_MB})"
            echo "  - WORKER_MEMORY_MB (currently: ${WORKER_MEMORY_MB})"
            echo "  - WORKER_COUNT (currently: ${WORKER_COUNT})"
            echo ""
            echo "Or set RESOURCE_CHECK_ENABLED=false to bypass this check (not recommended)"
            echo ""
            read -p "Press Enter to continue..."
        fi
        exit 1
    elif [[ "${warnings}" -gt 0 ]]; then
        log "WARNING: Resource check completed with ${warnings} warning(s)"

        if [[ "${MENU_MODE}" == "true" ]]; then
            echo ""
            echo "RESOURCE WARNINGS DETECTED!"
            echo "The system may experience performance issues or instability."
            echo ""
            if ! confirm_action "Continue anyway?"; then
                log "Deployment cancelled due to resource warnings"
                exit 1
            fi
        fi
    else
        log "Resource check passed"
    fi
}

# Validate worker count is reasonable
validate_worker_count() {
    if [[ ! "${WORKER_COUNT}" =~ ^[0-9]+$ ]]; then
        log "ERROR: WORKER_COUNT must be a number (got: ${WORKER_COUNT})"
        exit 1
    fi

    if [[ "${WORKER_COUNT}" -lt 0 ]]; then
        log "ERROR: WORKER_COUNT must be >= 0 (got: ${WORKER_COUNT})"
        exit 1
    fi

    if [[ "${WORKER_COUNT}" -gt 50 ]]; then
        log "ERROR: WORKER_COUNT is unreasonably high (${WORKER_COUNT})"
        log "ERROR: This script supports maximum 50 workers"
        log "ERROR: For larger clusters, consider using a proper orchestration tool"
        exit 1
    fi

    if [[ "${WORKER_COUNT}" -gt 10 ]]; then
        log "WARNING: High worker count (${WORKER_COUNT})"

        if [[ "${MENU_MODE}" == "true" ]]; then
            echo ""
            echo "You have configured ${WORKER_COUNT} worker nodes."
            echo "This will require significant resources and may take a long time to deploy."
            echo ""
            if ! confirm_action "Continue with ${WORKER_COUNT} workers?"; then
                log "Deployment cancelled due to high worker count"
                exit 1
            fi
        fi
    fi
}

# Validate Kubernetes version availability
validate_k8s_version() {
    log "Validating Kubernetes version ${K8S_SEMVER}..."

    # Check if we can reach the Kubernetes package repository
    local k8s_repo_url="https://pkgs.k8s.io/core:/stable:/${K8S_CHANNEL}/deb"
    local packages_url="${k8s_repo_url}/Packages"

    # Try to fetch the Packages file to verify repository accessibility
    if ! curl -fsSL --connect-timeout 10 "${packages_url}" >/dev/null 2>&1; then
        log "ERROR: Cannot reach Kubernetes package repository"
        log "ERROR: URL: ${packages_url}"
        log "ERROR: Check your internet connection and firewall settings"

        if [[ "${MENU_MODE}" == "true" ]]; then
            echo ""
            echo "KUBERNETES REPOSITORY UNREACHABLE!"
            echo "Cannot verify if Kubernetes ${K8S_SEMVER} is available."
            echo ""
            if ! confirm_action "Continue without version validation?"; then
                log "Deployment cancelled due to repository access failure"
                exit 1
            fi
        fi
        return 0
    fi

    # Fetch the Packages file and check if our version exists
    local package_info=$(curl -fsSL --connect-timeout 10 "${packages_url}" 2>/dev/null)

    if [[ -z "${package_info}" ]]; then
        log "WARNING: Could not fetch package information from repository"
        log "WARNING: Cannot validate if Kubernetes ${K8S_SEMVER} is available"
        return 0
    fi

    # Check if kubeadm package with our version exists
    # Package version format is typically: 1.35.0-1.1
    # Normalize K8S_SEMVER to handle both "v1.35.0" and "1.35.0" formats
    local normalized_k8s_version="${K8S_SEMVER#v}"

    # Basic validation: expect a semantic version like X.Y.Z, optionally with a pre-release suffix
    # Supported formats (after stripping optional leading 'v'):
    #   - 1.35.0
    #   - 1.35.0-rc.1
    #   - 1.35.0-alpha.2
    #   - 1.35.0-alpha.2.3
    #   - 1.35.0-rc.1.commit.abc123
    # Pattern: pre-release section starts with '-' followed by dot-separated alphanumeric identifiers
    # Each identifier contains only alphanumerics (0-9, A-Z, a-z); no underscores or hyphens within
    local k8s_version_pattern='^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$'

    if [[ ! "${normalized_k8s_version}" =~ $k8s_version_pattern ]]; then
        log "ERROR: Invalid Kubernetes version format: ${K8S_SEMVER}"
        log "ERROR: Expected format: X.Y.Z or vX.Y.Z, optionally with a pre-release suffix (e.g. '-rc.1' or '-alpha.2.3')"
        exit 1
    fi

    local version_pattern="${normalized_k8s_version}-"

    # Check if kubeadm package exists with our version
    if echo "${package_info}" | grep -q "Package: kubeadm"; then
        if echo "${package_info}" | grep -A5 "Package: kubeadm" | grep -q "Version:.*${version_pattern}"; then
            log "[OK] Kubernetes version ${K8S_SEMVER} found in repository"
        else
            log "ERROR: Kubernetes version ${K8S_SEMVER} not found in repository"
            log "ERROR: The specified version may not exist or may be misspelled"
            log "ERROR: Available versions can be found at: https://kubernetes.io/releases/"

            # Try to show available versions
            local available_versions
            local kubeadm_section

            # Extract the kubeadm package section, then list up to 5 recent versions
            if kubeadm_section=$(extract_package_section "kubeadm" "${package_info}"); then
                if ! available_versions=$(printf '%s\n' "${kubeadm_section}" | grep '^Version:' | head -n 5 | sed 's/^Version: /  - /'); then
                    available_versions="  (could not list versions)"
                fi
            else
                available_versions="  (could not list versions)"
            fi
            log "Recent versions in repository:"
            while read -r line; do
                log "${line}"
            done <<< "${available_versions}"

            if [[ "${MENU_MODE}" == "true" ]]; then
                echo ""
                echo "KUBERNETES VERSION NOT FOUND!"
                echo "The specified version ${K8S_SEMVER} does not exist in the repository."
                echo "Please update K8S_SEMVER and K8S_CHANNEL in the script configuration."
                echo ""
                echo "Recent available versions:"
                echo "${available_versions}"
                echo ""
                read -p "Press Enter to exit..."
            fi
            exit 1
        fi
    else
        log "WARNING: Could not parse package repository format"
        log "WARNING: Skipping version validation"
    fi
}

############################################
# MENU SYSTEM FUNCTIONS
############################################

get_vm_status() {
    local vmid=$1
    if pve_has_vmid "${vmid}"; then
        # Use grep to extract status without relying on field positions
        if qm status "${vmid}" 2>/dev/null | grep -qi 'stopped'; then
            echo "stopped"
        elif qm status "${vmid}" 2>/dev/null | grep -qi 'running'; then
            echo "running"
        else
            echo "unknown"
        fi
    else
        echo "not found"
    fi
}

show_menu() {
    clear
    echo "============================================================================"
    echo "  Kubernetes on Proxmox - Cluster Management"
    echo "============================================================================"
    echo ""
    echo "Current Configuration:"
    echo "  Control Plane: ${CP_IP} (VMID ${CP_VMID})"
    echo "  Workers:       ${WORKER_COUNT} nodes starting at ${WORKER_IP_BASE}${WORKER_IP_START_OCTET}"
    echo "  Kubernetes:    ${K8S_SEMVER}"
    echo "  Calico:        ${CALICO_VERSION}"
    echo "  Ubuntu:        ${UBUNTU_RELEASE}"
    echo ""
    echo "VM Status:"
    echo "  Template (${TEMPLATE_VMID}): $(get_vm_status ${TEMPLATE_VMID})"
    echo "  CP1 (${CP_VMID}):      $(get_vm_status ${CP_VMID})"
    for ((i=0; i<WORKER_COUNT; i++)); do
        vmid=$(( WORKER_VMID_START + i ))
        printf "  Worker%d (%d):   %s\n" $((i+1)) ${vmid} "$(get_vm_status ${vmid})"
    done
    echo ""
    echo "============================================================================"
    echo ""
    echo "  1) Fresh Install (Destroy all VMs and reinstall from scratch)"
    echo "  2) Reconfigure/Update (Update existing cluster, non-destructive)"
    echo "  3) Scale Cluster (Add or remove worker nodes)"
    echo "  4) Reset Kubernetes (Keep VMs, reinitialize cluster)"
    echo "  5) Destroy Cluster (Delete all VMs)"
    echo "  6) Stop/Start VMs (Power management)"
    echo "  7) Kill Stuck Processes (Cleanup ansible/apt processes)"
    echo "  8) View Status (Show detailed cluster information)"
    echo "  9) SSH to Node (Quick SSH access)"
    echo " 10) Update Dependencies (Update packages on all nodes)"
    echo " 11) Export Kubeconfig (For Lens/external kubectl access)"
    echo "  0) Exit"
    echo ""
    echo "============================================================================"
    echo ""
}

read_choice() {
    local choice
    read -p "Enter choice [0-11]: " choice
    echo "${choice}"
}

confirm_action() {
    local prompt="$1"
    local response
    read -p "${prompt} (y/N): " response
    [[ "${response}" =~ ^[Yy]$ ]]
}

############################################
# MENU ACTION FUNCTIONS
############################################

action_view_status() {
    log "Viewing cluster status..."
    echo ""
    echo "=== VM Status ==="
    echo "Template (${TEMPLATE_VMID}): $(get_vm_status ${TEMPLATE_VMID})"
    echo "CP1 (${CP_VMID}): $(get_vm_status ${CP_VMID})"
    for ((i=0; i<WORKER_COUNT; i++)); do
        vmid=$(( WORKER_VMID_START + i ))
        echo "Worker$((i+1)) (${vmid}): $(get_vm_status ${vmid})"
    done

    echo ""
    echo "=== Network Configuration ==="
    echo "Gateway: ${NET_GATEWAY}"
    echo "DNS: ${NET_DNS}"
    echo "Control Plane IP: ${CP_IP}"
    for ((i=0; i<WORKER_COUNT; i++)); do
        ip="$(ip_add_octet "${WORKER_IP_BASE}" "${WORKER_IP_START_OCTET}" "${i}")"
        echo "Worker$((i+1)) IP: ${ip}"
    done

    # Check if control plane is accessible
    if pve_has_vmid "${CP_VMID}" && [[ "$(get_vm_status ${CP_VMID})" == "running" ]]; then
        echo ""
        echo "=== Kubernetes Cluster Status ==="
        if ssh -o BatchMode=yes -o ConnectTimeout=5 -i "${VM_SSH_KEY_PATH}" \
               -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
               "${VM_USER}@${CP_IP}" "kubectl get nodes" >/dev/null 2>&1; then
            echo ""
            echo "Nodes:"
            ssh_vm "${CP_IP}" "kubectl get nodes -o wide" 2>/dev/null || echo "  Unable to get nodes"

            echo ""
            echo "System Pods:"
            ssh_vm "${CP_IP}" "kubectl get pods -A" 2>/dev/null || echo "  Unable to get pods"
        else
            echo "  Kubernetes cluster not accessible (kubectl not available or cluster not initialized)"
        fi
    else
        echo ""
        echo "=== Kubernetes Cluster Status ==="
        echo "  Control plane VM not running"
    fi

    echo ""
    echo "=== Ansible Configuration ==="
    if [[ -f "${ANSIBLE_INVENTORY}" ]]; then
        echo "Inventory file exists: ${ANSIBLE_INVENTORY}"
        echo "Contents:"
        cat "${ANSIBLE_INVENTORY}" | head -20
    else
        echo "Inventory file not found: ${ANSIBLE_INVENTORY}"
    fi
}

action_kill_processes() {
    log "Killing stuck processes..."
    cleanup_previous_run
    log "Cleanup complete"
}

action_ssh_node() {
    echo ""
    echo "Select node to SSH into:"
    echo "  1) Control Plane (${CP_IP})"
    for ((i=0; i<WORKER_COUNT; i++)); do
        ip="$(ip_add_octet "${WORKER_IP_BASE}" "${WORKER_IP_START_OCTET}" "${i}")"
        echo "  $((i+2))) Worker$((i+1)) (${ip})"
    done
    echo "  0) Cancel"
    echo ""

    local choice
    read -p "Enter choice: " choice

    if [[ "${choice}" == "0" ]]; then
        return 0
    elif [[ "${choice}" == "1" ]]; then
        log "Connecting to Control Plane (${CP_IP})..."
        ssh_vm "${CP_IP}"
    elif [[ "${choice}" =~ ^[0-9]+$ ]] && (( choice >= 2 && choice < WORKER_COUNT + 2 )); then
        local worker_idx=$((choice - 2))
        local worker_ip="$(ip_add_octet "${WORKER_IP_BASE}" "${WORKER_IP_START_OCTET}" "${worker_idx}")"
        log "Connecting to Worker$((worker_idx+1)) (${worker_ip})..."
        ssh_vm "${worker_ip}"
    else
        log "Invalid choice"
    fi
}

action_update_dependencies() {
    log "Updating packages on all nodes..."

    # Check if VMs are running
    if ! pve_has_vmid "${CP_VMID}" || [[ "$(get_vm_status ${CP_VMID})" != "running" ]]; then
        log "ERROR: Control plane VM is not running"
        return 1
    fi

    echo ""
    echo "This will update all packages (apt update && apt upgrade) on:"
    echo "  - Control Plane (${CP_IP})"
    for ((i=0; i<WORKER_COUNT; i++)); do
        ip="$(ip_add_octet "${WORKER_IP_BASE}" "${WORKER_IP_START_OCTET}" "${i}")"
        echo "  - Worker$((i+1)) (${ip})"
    done
    echo ""

    if ! confirm_action "Proceed with package updates?"; then
        log "Update cancelled"
        return 0
    fi

    # Update control plane
    log "Updating control plane packages..."
    if ssh_vm "${CP_IP}" "sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"; then
        log "Control plane updated successfully"
    else
        log "ERROR: Failed to update control plane"
        return 1
    fi

    # Update workers
    for ((i=0; i<WORKER_COUNT; i++)); do
        local worker_ip="$(ip_add_octet "${WORKER_IP_BASE}" "${WORKER_IP_START_OCTET}" "${i}")"
        local worker_vmid=$((WORKER_VMID_START + i))

        if ! pve_has_vmid "${worker_vmid}" || [[ "$(get_vm_status ${worker_vmid})" != "running" ]]; then
            log "WARNING: Worker$((i+1)) (${worker_vmid}) is not running - skipping"
            continue
        fi

        log "Updating Worker$((i+1)) packages..."
        if ssh_vm "${worker_ip}" "sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive apt-get upgrade -y"; then
            log "Worker$((i+1)) updated successfully"
        else
            log "ERROR: Failed to update Worker$((i+1))"
        fi
    done

    log "Package updates complete"
    echo ""
    echo "Note: You may need to reboot nodes if kernel updates were installed"
    echo "Use option 6 (Power Management) to restart VMs if needed"
}

action_export_kubeconfig() {
    log "Exporting kubeconfig for external access..."

    # Check if control plane is running
    if ! pve_has_vmid "${CP_VMID}" || [[ "$(get_vm_status ${CP_VMID})" != "running" ]]; then
        log "ERROR: Control plane VM is not running"
        return 1
    fi

    # Check if cluster is initialized
    if ! ssh -o BatchMode=yes -o ConnectTimeout=5 -i "${VM_SSH_KEY_PATH}" \
           -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
           "${VM_USER}@${CP_IP}" "test -f /etc/kubernetes/admin.conf" 2>/dev/null; then
        log "ERROR: Kubernetes cluster not initialized (admin.conf not found)"
        return 1
    fi

    # Create export directory
    mkdir -p "${KUBECONFIG_EXPORT_DIR}"

    # Generate timestamp for filename
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local kubeconfig_file="${KUBECONFIG_EXPORT_DIR}/kubeconfig-${timestamp}.yaml"
    local kubeconfig_latest="${KUBECONFIG_EXPORT_DIR}/kubeconfig-latest.yaml"

    echo ""
    echo "Export Options:"
    echo "  1) Export with control plane IP (${CP_IP}) - for local network access"
    echo "  2) Export with custom hostname/IP - for remote access or DNS name"
    echo "  3) Print to console (display kubeconfig directly)"
    echo "  0) Cancel"
    echo ""

    local export_choice
    read -p "Enter choice: " export_choice

    local api_server_address="${CP_IP}"

    case "${export_choice}" in
        1)
            api_server_address="${CP_IP}"
            ;;
        2)
            echo ""
            echo "Enter the hostname or IP address to use for the API server."
            echo "This should be reachable from where you will use kubectl/Lens."
            echo "Examples: k8s.example.com, 192.168.1.100, my-cluster.local"
            echo ""
            read -p "API Server address: " custom_address
            if [[ -z "${custom_address}" ]]; then
                log "ERROR: No address provided"
                return 1
            fi
            api_server_address="${custom_address}"
            ;;
        3)
            # Print to console option
            log "Fetching kubeconfig from control plane..."

            # Fetch the admin.conf from control plane
            local raw_kubeconfig
            raw_kubeconfig=$(ssh_vm "${CP_IP}" "sudo cat /etc/kubernetes/admin.conf" 2>/dev/null)

            if [[ -z "${raw_kubeconfig}" ]]; then
                log "ERROR: Failed to fetch kubeconfig from control plane"
                return 1
            fi

            # Replace the API server address
            local modified_kubeconfig
            modified_kubeconfig=$(echo "${raw_kubeconfig}" | sed "s|server: https://[^:]*:6443|server: https://${api_server_address}:6443|g")

            # Update cluster name and context for clarity
            # First, rename the cluster
            modified_kubeconfig=$(echo "${modified_kubeconfig}" | sed "s|name: kubernetes$|name: proxmox-k8s|g")
            modified_kubeconfig=$(echo "${modified_kubeconfig}" | sed "s|cluster: kubernetes$|cluster: proxmox-k8s|g")

            # Rename the user (both in users list and context reference)
            modified_kubeconfig=$(echo "${modified_kubeconfig}" | sed "s|name: kubernetes-admin$|name: proxmox-k8s-admin|g")
            modified_kubeconfig=$(echo "${modified_kubeconfig}" | sed "s|user: kubernetes-admin$|user: proxmox-k8s-admin|g")

            # Rename the context name and current-context
            modified_kubeconfig=$(echo "${modified_kubeconfig}" | sed "s|name: kubernetes-admin@kubernetes$|name: proxmox-k8s-admin@proxmox-k8s|g")
            modified_kubeconfig=$(echo "${modified_kubeconfig}" | sed "s|current-context: kubernetes-admin@kubernetes$|current-context: proxmox-k8s-admin@proxmox-k8s|g")

            log "============================================================================"
            log "Kubeconfig for API server: https://${api_server_address}:6443"
            log "============================================================================"
            echo ""
            echo "Copy the content below (select and copy to clipboard):"
            echo ""
            echo "---BEGIN KUBECONFIG---"
            echo "${modified_kubeconfig}"
            echo "---END KUBECONFIG---"
            echo ""
            log "To use this kubeconfig:"
            log "  1. Copy the content above to a file (e.g., ~/.kube/proxmox-k8s.yaml)"
            log "  2. Use it with kubectl: export KUBECONFIG=~/.kube/proxmox-k8s.yaml"
            log "  3. Or import to Lens by pasting the content"
            log "============================================================================"
            return 0
            ;;
        0)
            log "Export cancelled"
            return 0
            ;;
        *)
            log "Invalid choice"
            return 1
            ;;
    esac

    log "Fetching kubeconfig from control plane..."

    # Fetch the admin.conf from control plane
    local raw_kubeconfig
    raw_kubeconfig=$(ssh_vm "${CP_IP}" "sudo cat /etc/kubernetes/admin.conf" 2>/dev/null)

    if [[ -z "${raw_kubeconfig}" ]]; then
        log "ERROR: Failed to fetch kubeconfig from control plane"
        return 1
    fi

    # Replace the API server address
    local modified_kubeconfig
    modified_kubeconfig=$(echo "${raw_kubeconfig}" | sed "s|server: https://[^:]*:6443|server: https://${api_server_address}:6443|g")

    # Update cluster name and context for clarity
    # First, rename the cluster
    modified_kubeconfig=$(echo "${modified_kubeconfig}" | sed "s|name: kubernetes$|name: proxmox-k8s|g")
    modified_kubeconfig=$(echo "${modified_kubeconfig}" | sed "s|cluster: kubernetes$|cluster: proxmox-k8s|g")

    # Rename the user (both in users list and context reference)
    modified_kubeconfig=$(echo "${modified_kubeconfig}" | sed "s|name: kubernetes-admin$|name: proxmox-k8s-admin|g")
    modified_kubeconfig=$(echo "${modified_kubeconfig}" | sed "s|user: kubernetes-admin$|user: proxmox-k8s-admin|g")

    # Rename the context name and current-context
    modified_kubeconfig=$(echo "${modified_kubeconfig}" | sed "s|name: kubernetes-admin@kubernetes$|name: proxmox-k8s-admin@proxmox-k8s|g")
    modified_kubeconfig=$(echo "${modified_kubeconfig}" | sed "s|current-context: kubernetes-admin@kubernetes$|current-context: proxmox-k8s-admin@proxmox-k8s|g")

    # Write to timestamped file
    echo "${modified_kubeconfig}" > "${kubeconfig_file}"
    chmod 600 "${kubeconfig_file}"

    # Update the latest symlink
    ln -sf "$(basename "${kubeconfig_file}")" "${kubeconfig_latest}"

    log "============================================================================"
    log "Kubeconfig exported successfully!"
    log "============================================================================"
    echo ""
    echo "Files created:"
    echo "  ${kubeconfig_file}"
    echo "  ${kubeconfig_latest} (symlink to latest)"
    echo ""
    echo "API Server: https://${api_server_address}:6443"
    echo ""
    echo "Usage Options:"
    echo ""
    echo "1. For Lens:"
    echo "   - Open Lens"
    echo "   - Click Add Cluster or +"
    echo "   - Select Add from kubeconfig"
    echo "   - Paste contents or browse to: ${kubeconfig_file}"
    echo ""
    echo "2. For kubectl (temporary):"
    echo "   export KUBECONFIG=${kubeconfig_file}"
    echo "   kubectl get nodes"
    echo ""
    echo "3. For kubectl (permanent - merge with existing):"
    echo "   KUBECONFIG=~/.kube/config:${kubeconfig_file} kubectl config view --flatten > ~/.kube/config.new"
    echo "   mv ~/.kube/config.new ~/.kube/config"
    echo "   kubectl config use-context admin@proxmox-k8s"
    echo ""
    echo "4. Copy to local machine:"
    echo "   scp root@\$(hostname -I | awk '{print \$1}'):${kubeconfig_file} ~/.kube/proxmox-k8s.yaml"
    echo ""

    # Verify the kubeconfig works
    if [[ "${MENU_MODE}" == "true" ]]; then
        echo ""
        if confirm_action "Test the kubeconfig now?"; then
            log "Testing kubeconfig..."
            if KUBECONFIG="${kubeconfig_file}" kubectl cluster-info --request-timeout=10s 2>/dev/null; then
                echo ""
                log "[OK] Kubeconfig is valid and cluster is accessible"
            else
                echo ""
                log "WARNING: Could not connect to cluster using the exported kubeconfig"
                log "This may be expected if testing from a different network"
            fi
        fi
    fi

    log "============================================================================"
}

action_power_management() {
    echo ""
    echo "Power Management:"
    echo "  1) Start all VMs"
    echo "  2) Stop all VMs"
    echo "  3) Restart all VMs"
    echo "  4) Individual VM control"
    echo "  0) Cancel"
    echo ""

    local choice
    read -p "Enter choice: " choice

    case "${choice}" in
        1)
            log "Starting all VMs..."
            qm start "${CP_VMID}" 2>/dev/null && log "  Started CP1 (${CP_VMID})" || log "  Failed to start CP1"
            for ((i=0; i<WORKER_COUNT; i++)); do
                vmid=$(( WORKER_VMID_START + i ))
                qm start "${vmid}" 2>/dev/null && log "  Started Worker$((i+1)) (${vmid})" || log "  Failed to start Worker$((i+1))"
            done
            ;;
        2)
            if confirm_action "Stop all VMs?"; then
                log "Stopping all VMs..."
                qm stop "${CP_VMID}" 2>/dev/null && log "  Stopped CP1 (${CP_VMID})" || log "  Failed to stop CP1"
                for ((i=0; i<WORKER_COUNT; i++)); do
                    vmid=$(( WORKER_VMID_START + i ))
                    qm stop "${vmid}" 2>/dev/null && log "  Stopped Worker$((i+1)) (${vmid})" || log "  Failed to stop Worker$((i+1))"
                done
            fi
            ;;
        3)
            if confirm_action "Restart all VMs?"; then
                log "Restarting all VMs..."
                qm reboot "${CP_VMID}" 2>/dev/null && log "  Restarted CP1 (${CP_VMID})" || log "  Failed to restart CP1"
                for ((i=0; i<WORKER_COUNT; i++)); do
                    vmid=$(( WORKER_VMID_START + i ))
                    qm reboot "${vmid}" 2>/dev/null && log "  Restarted Worker$((i+1)) (${vmid})" || log "  Failed to restart Worker$((i+1))"
                done
            fi
            ;;
        4)
            echo ""
            echo "Select VM:"
            echo "  1) Control Plane (${CP_VMID})"
            for ((i=0; i<WORKER_COUNT; i++)); do
                vmid=$(( WORKER_VMID_START + i ))
                echo "  $((i+2))) Worker$((i+1)) (${vmid})"
            done
            echo "  0) Cancel"

            local vm_choice
            read -p "Enter VM choice: " vm_choice

            if [[ "${vm_choice}" == "0" ]]; then
                return 0
            fi

            local selected_vmid
            if [[ "${vm_choice}" == "1" ]]; then
                selected_vmid="${CP_VMID}"
            elif [[ "${vm_choice}" =~ ^[0-9]+$ ]] && (( vm_choice >= 2 && vm_choice < WORKER_COUNT + 2 )); then
                selected_vmid=$(( WORKER_VMID_START + vm_choice - 2 ))
            else
                log "Invalid choice"
                return 1
            fi

            echo ""
            echo "Action:"
            echo "  1) Start"
            echo "  2) Stop"
            echo "  3) Restart"
            echo "  0) Cancel"

            local action_choice
            read -p "Enter action: " action_choice

            case "${action_choice}" in
                1) qm start "${selected_vmid}" && log "Started VM ${selected_vmid}" || log "Failed to start VM ${selected_vmid}" ;;
                2) qm stop "${selected_vmid}" && log "Stopped VM ${selected_vmid}" || log "Failed to stop VM ${selected_vmid}" ;;
                3) qm reboot "${selected_vmid}" && log "Restarted VM ${selected_vmid}" || log "Failed to restart VM ${selected_vmid}" ;;
                *) log "Cancelled" ;;
            esac
            ;;
        *)
            log "Cancelled"
            ;;
    esac
}

action_reconfigure() {
    log "Starting deployment/reconfiguration..."
    cleanup_previous_run
    ensure_root
    ensure_dirs

    # Run pre-flight checks
    log "Running pre-flight checks..."
    validate_worker_count
    validate_k8s_version
    ensure_ssh_keys
    validate_network_config
    check_host_resources
    log "Pre-flight checks complete"
    log ""

log "============================================================================"
log "Network (auto-detected from ${PM_BRIDGE}):"
log "  Host IP:       ${AUTO_DETECTED_HOST_IP}"
log "  Network:       ${AUTO_DETECTED_NETWORK_PREFIX}.0/${NET_CIDR_PREFIX}"
log "  Gateway:       ${NET_GATEWAY}"
log "  DNS:           ${NET_DNS}"
log "  Control plane: ${CP_IP}"
log "  Workers:       ${WORKER_IP_BASE}${WORKER_IP_START_OCTET}-$((WORKER_IP_START_OCTET + WORKER_COUNT - 1))"
log "============================================================================"
log ""

# Install prerequisites on Proxmox host
log "Installing prerequisites..."
if ! need_cmd curl; then
    apt-get update -y
    apt-get install -y curl
fi
if ! need_cmd ssh; then
    apt-get update -y
    apt-get install -y openssh-client
fi
if ! need_cmd ansible; then
    apt-get update -y
    apt-get install -y ansible
fi

# Generate SSH key for VM access if it doesn't exist
if [[ ! -f "${VM_SSH_KEY_PATH}" || ! -f "${VM_SSH_PUBKEY_PATH}" ]]; then
    log "Generating SSH key..."
    mkdir -p "$(dirname "${VM_SSH_KEY_PATH}")"
    chmod 700 "$(dirname "${VM_SSH_KEY_PATH}")"
    ssh-keygen -t ed25519 -N "" -f "${VM_SSH_KEY_PATH}" -C "proxmox-k8s" >/dev/null
fi
chmod 600 "${VM_SSH_KEY_PATH}"
chmod 644 "${VM_SSH_PUBKEY_PATH}"

# Determine Ubuntu cloud image
if [[ -z "${UBUNTU_IMAGE_FILE}" ]]; then
    UBUNTU_IMAGE_FILE="$(ubuntu_image_filename "${UBUNTU_RELEASE}")"
fi
UBUNTU_IMAGE_PATH="${UBUNTU_IMAGE_DIR}/${UBUNTU_IMAGE_FILE}"
UBUNTU_IMAGE_URL="$(ubuntu_image_url "${UBUNTU_RELEASE}")"

# Download Ubuntu cloud image if missing
if [[ ! -f "${UBUNTU_IMAGE_PATH}" ]]; then
    log "Downloading Ubuntu ${UBUNTU_RELEASE}..."
    curl -fsSL -o "${UBUNTU_IMAGE_PATH}" "${UBUNTU_IMAGE_URL}"

    # Download SHA256SUMS file for verification
    log "Downloading SHA256 checksums..."
    local sha256_url="${UBUNTU_IMAGE_URL%/*}/SHA256SUMS"
    local sha256_file="${UBUNTU_IMAGE_PATH}.sha256"

    if curl -fsSL -o "${sha256_file}" "${sha256_url}"; then
        log "Verifying image integrity..."

        # Extract only the checksum for our specific file (match filename from URL as in SHA256SUMS)
        # SHA256SUMS format: "checksum *filename" (exactly 2 fields)
        # The asterisk (*) indicates binary mode in checksum files (vs space for text mode)
        local image_filename="${UBUNTU_IMAGE_URL##*/}"
        local expected_checksum
        expected_checksum=$(awk -v f="${image_filename}" '{filename = $2; sub(/^\*/, "", filename); if (filename == f) { print $1; exit }}' "${sha256_file}")

        if [[ -z "${expected_checksum}" ]]; then
            log "ERROR: Could not find checksum for ${image_filename} in SHA256SUMS"
            log "ERROR: Downloaded image may be compromised or incorrect"
            rm -f "${UBUNTU_IMAGE_PATH}" "${sha256_file}"
            exit 1
        fi

        # Calculate actual checksum
        local sha256_output
        if ! sha256_output=$(sha256sum "${UBUNTU_IMAGE_PATH}"); then
            log "ERROR: Failed to calculate SHA256 checksum for ${UBUNTU_IMAGE_PATH}"
            log "ERROR: The downloaded image may be corrupted, unreadable, or missing"
            rm -f "${UBUNTU_IMAGE_PATH}" "${sha256_file}"
            exit 1
        fi
        local actual_checksum
        actual_checksum=$(awk '{print $1}' <<< "${sha256_output}")

        if [[ -z "${actual_checksum}" ]]; then
            log "ERROR: Calculated SHA256 checksum is empty for ${UBUNTU_IMAGE_PATH}"
            log "ERROR: The downloaded image may be corrupted, unreadable, or missing"
            rm -f "${UBUNTU_IMAGE_PATH}" "${sha256_file}"
            exit 1
        fi

        if [[ "${actual_checksum}" != "${expected_checksum}" ]]; then
            log "ERROR: SHA256 checksum verification FAILED!"
            log "ERROR: Expected: ${expected_checksum}"
            log "ERROR: Got:      ${actual_checksum}"
            log "ERROR: The downloaded image may be corrupted or compromised"
            rm -f "${UBUNTU_IMAGE_PATH}" "${sha256_file}"
            exit 1
        fi

        log "[OK] SHA256 checksum verification passed"
        rm -f "${sha256_file}"
    else
        log "WARNING: Could not download SHA256SUMS file"
        log "WARNING: Proceeding without integrity verification (not recommended)"

        if [[ "${MENU_MODE}" == "true" ]]; then
            echo ""
            echo "SECURITY WARNING: Unable to verify image integrity!"
            echo "The Ubuntu cloud image could not be verified against SHA256 checksums."
            echo "This may indicate a compromised or corrupted download."
            echo ""
            if ! confirm_action "Continue without verification?"; then
                log "Deployment cancelled due to failed integrity check"
                rm -f "${UBUNTU_IMAGE_PATH}"
                exit 1
            fi
        fi
    fi
else
    log "Ubuntu image found: ${UBUNTU_IMAGE_PATH}"
fi

# Create VM template if it doesn't exist
if ! pve_has_vmid "${TEMPLATE_VMID}"; then
    log "Creating template ${TEMPLATE_VMID}..."
    
    qm create "${TEMPLATE_VMID}" \
        --name "${VM_NAME_PREFIX}-ubuntu-${UBUNTU_RELEASE}-template" \
        --memory "${TEMPLATE_MEMORY_MB}" \
        --cores "${TEMPLATE_CORES}" \
        --cpu host \
        --net0 "virtio,bridge=${PM_BRIDGE}" \
        --scsihw virtio-scsi-pci \
        --agent enabled=1 \
        --serial0 socket \
        --vga serial0

    # Import disk and capture the volume name
    qm importdisk "${TEMPLATE_VMID}" "${UBUNTU_IMAGE_PATH}" "${PM_STORAGE}"
    
    # Find the first unused disk (could be unused0, unused1, etc.)
    UNUSED_DISK=$(qm config "${TEMPLATE_VMID}" | grep -E '^unused[0-9]+:' | head -n1 | awk '{print $2}')
    
    if [[ -z "${UNUSED_DISK}" ]]; then
        log "ERROR: Failed to find imported disk"
        exit 1
    fi
    
    log "Attaching disk: ${UNUSED_DISK}"
    
    qm set "${TEMPLATE_VMID}" \
        --scsi0 "${UNUSED_DISK}" \
        --boot order=scsi0 \
        --ide2 "${PM_STORAGE}:cloudinit" \
        --ciuser "${VM_USER}" \
        --sshkeys "${VM_SSH_PUBKEY_PATH}" \
        --ipconfig0 "ip=dhcp" \
        --nameserver "${NET_DNS}"

    qm resize "${TEMPLATE_VMID}" scsi0 "${TEMPLATE_DISK_GB}G"
    qm template "${TEMPLATE_VMID}"
    
    log "Template ${TEMPLATE_VMID} created"
else
    log "Template ${TEMPLATE_VMID} exists"
fi

# Function to create/clone a VM from template
create_vm_from_template() {
    local vmid="$1" name="$2" ip="$3" cores="$4" memory="$5" disk_gb="$6"
    
    if pve_has_vmid "${vmid}"; then
        log "VM ${vmid} (${name}) exists - checking config..."
        
        # Read existing net0 config to preserve MAC address and other settings
        EXISTING_NET0=$(qm config "${vmid}" | grep "^net0:" | cut -d' ' -f2- || echo "")
        
        if [[ -n "${EXISTING_NET0}" ]]; then
            # Preserve existing config, only update bridge if needed
            if ! echo "${EXISTING_NET0}" | grep -q "bridge=${PM_BRIDGE}"; then
                # Check if bridge parameter exists at all
                if echo "${EXISTING_NET0}" | grep -q 'bridge='; then
                    # Replace existing bridge value
                    NEW_NET0=$(echo "${EXISTING_NET0}" | sed "s/bridge=[^,]*/bridge=${PM_BRIDGE}/")
                else
                    # Add bridge parameter
                    NEW_NET0="${EXISTING_NET0},bridge=${PM_BRIDGE}"
                fi
                qm set "${vmid}" --net0 "${NEW_NET0}"
            fi
        else
            # No net0 exists, create it
            qm set "${vmid}" --net0 "virtio,bridge=${PM_BRIDGE}"
        fi
        
        # Update other settings (these are safe to reapply)
        # Check if IP config is changing to determine if reboot is needed
        CURRENT_IP="$(qm config "${vmid}" | awk -F'ip=' '/^ipconfig0:/{print $2}' | cut -d, -f1 | cut -d/ -f1 | head -n1)"
        CURRENT_IP="${CURRENT_IP:-}"
        IP_CHANGED=0
        if [[ -n "${CURRENT_IP}" && "${CURRENT_IP}" != "${ip}" ]]; then
            IP_CHANGED=1
            log "Detected IP change from ${CURRENT_IP} to ${ip}"
        fi
        
        # Check if cloud-init disk already exists
        EXISTING_IDE2=$(qm config "${vmid}" | grep "^ide2:" || echo "")
        
        # Build qm set command conditionally
        QM_SET_ARGS=(
            --cores "${cores}"
            --memory "${memory}"
            --cpu host
            --agent enabled=1
            --onboot 1
            --ciuser "${VM_USER}"
            --sshkeys "${VM_SSH_PUBKEY_PATH}"
            --ipconfig0 "ip=${ip}/${NET_CIDR_PREFIX},gw=${NET_GATEWAY}"
            --nameserver "${NET_DNS}"
        )
        
        # Only add ide2 if it doesn't exist
        if [[ -z "${EXISTING_IDE2}" ]]; then
            QM_SET_ARGS+=(--ide2 "${PM_STORAGE}:cloudinit")
        fi
        
        qm set "${vmid}" "${QM_SET_ARGS[@]}"
        
        # Resize disk if needed (qm resize only grows, never shrinks)
        CURRENT_DISK_SIZE=$(qm config "${vmid}" | awk -F'size=' '/^scsi0:/{print $2}' | cut -d, -f1 | head -n1)
        CURRENT_DISK_SIZE=${CURRENT_DISK_SIZE:-0G}
        CURRENT_SIZE_NUM=$(echo "${CURRENT_DISK_SIZE}" | sed 's/[^0-9]//g')
        CURRENT_SIZE_NUM=${CURRENT_SIZE_NUM:-0}
        if (( CURRENT_SIZE_NUM < disk_gb )); then
            log "Growing disk from ${CURRENT_DISK_SIZE} to ${disk_gb}G"
            qm resize "${vmid}" scsi0 "${disk_gb}G" || log "Warning: Could not resize disk (may already be larger)"
        fi
        
        # Reboot or start VM if IP changed to apply cloud-init network changes
        if [[ ${IP_CHANGED} -eq 1 ]]; then
            log "Applying IP change for VM ${vmid}..."
            if qm status "${vmid}" 2>/dev/null | grep -qE 'status:\s+running'; then
                log "Rebooting VM ${vmid}..."
                if ! qm_output=$(qm reboot "${vmid}" 2>&1); then
                    log "WARNING: Failed to reboot VM ${vmid}: ${qm_output}"
                fi
            else
                log "Starting VM ${vmid}..."
                if ! qm_output=$(qm start "${vmid}" 2>&1); then
                    log "WARNING: Failed to start VM ${vmid}: ${qm_output}"
                fi
            fi
            sleep 5
        fi
        
        log "VM ${vmid} config updated"
        return 0
    fi
    
    log "Creating VM ${vmid} (${name})..."
    
    qm clone "${TEMPLATE_VMID}" "${vmid}" --name "${name}" --full true --storage "${PM_STORAGE}"
    
    qm set "${vmid}" \
        --cores "${cores}" \
        --memory "${memory}" \
        --cpu host \
        --scsihw virtio-scsi-pci \
        --net0 "virtio,bridge=${PM_BRIDGE}" \
        --agent enabled=1 \
        --serial0 socket \
        --vga serial0 \
        --onboot 1 \
        --ciuser "${VM_USER}" \
        --sshkeys "${VM_SSH_PUBKEY_PATH}" \
        --ipconfig0 "ip=${ip}/${NET_CIDR_PREFIX},gw=${NET_GATEWAY}" \
        --nameserver "${NET_DNS}"

    # Resize disk if different from template
    if [[ "${disk_gb}" != "${TEMPLATE_DISK_GB}" ]]; then
        qm resize "${vmid}" scsi0 "${disk_gb}G" || log "Warning: Could not resize disk"
    fi
    
    log "VM ${vmid} (${name}) created"
}

# Create control plane VM
log "Setting up control plane..."
create_vm_from_template "${CP_VMID}" "${VM_NAME_PREFIX}-cp-1" "${CP_IP}" "${CP_CORES}" "${CP_MEMORY_MB}" "${CP_DISK_GB}"

# Create worker VMs
log "Setting up workers..."
WORKER_IPS=()
for ((i=0; i<WORKER_COUNT; i++)); do
    vmid=$(( WORKER_VMID_START + i ))
    ip="$(ip_add_octet "${WORKER_IP_BASE}" "${WORKER_IP_START_OCTET}" "${i}")"
    WORKER_IPS+=("${ip}")
    create_vm_from_template "${vmid}" "${VM_NAME_PREFIX}-worker-$((i+1))" "${ip}" "${WORKER_CORES}" "${WORKER_MEMORY_MB}" "${WORKER_DISK_GB}"
done

# Check for orphaned worker VMs if WORKER_COUNT was reduced
ORPHAN_START=$((WORKER_VMID_START + WORKER_COUNT))
ORPHAN_CHECK_LIMIT=$((ORPHAN_START + 10))
ORPHANS_FOUND=0
for ((vmid=ORPHAN_START; vmid<ORPHAN_CHECK_LIMIT; vmid++)); do
    if pve_has_vmid "${vmid}"; then
        if [[ ${ORPHANS_FOUND} -eq 0 ]]; then
            log "WARNING: Orphaned VMs found (WORKER_COUNT was reduced):"
        fi
        ORPHANS_FOUND=$((ORPHANS_FOUND + 1))
        log "  VM ${vmid} beyond WORKER_COUNT=${WORKER_COUNT}"
    fi
done
if [[ ${ORPHANS_FOUND} -gt 0 ]]; then
    log "Consider removing orphaned VMs and draining nodes"
fi

# Start all VMs
log "Starting VMs..."
if ! qm_output=$(qm start "${CP_VMID}" 2>&1); then
    log "WARNING: Failed to start control plane VM ${CP_VMID}: ${qm_output}"
else
    log "Started control plane VM ${CP_VMID}"
fi

for ((i=0; i<WORKER_COUNT; i++)); do
    vmid=$(( WORKER_VMID_START + i ))
    if ! qm_output=$(qm start "${vmid}" 2>&1); then
        log "WARNING: Failed to start worker VM ${vmid}: ${qm_output}"
    else
        log "Started worker VM ${vmid}"
    fi
done

log "Waiting ${STARTUP_WAIT_SECONDS}s for VMs..."
sleep "${STARTUP_WAIT_SECONDS}"

# Wait for SSH on all nodes
wait_for_ssh "${CP_IP}"
for ip in "${WORKER_IPS[@]}"; do
    wait_for_ssh "${ip}"
done

# Wait for cloud-init to complete on all nodes
log "Waiting for cloud-init to complete..."
for node_ip in "${CP_IP}" "${WORKER_IPS[@]}"; do
    log "  Checking cloud-init status on ${node_ip}..."

    # Wait for cloud-init to complete (configurable timeout via CLOUD_INIT_TIMEOUT_SECONDS)
    if ssh_vm_opts "${node_ip}" "-o ConnectTimeout=10" \
           "timeout ${CLOUD_INIT_TIMEOUT_SECONDS} cloud-init status --wait" 2>/dev/null; then
        log "  [OK] Cloud-init completed on ${node_ip}"
    else
        log "WARNING: cloud-init status check failed on ${node_ip}"
        log "WARNING: This may cause configuration issues"

        # Check if cloud-init is at least done (even if it had errors)
        local cloud_init_status=$(ssh_vm_opts "${node_ip}" "-o ConnectTimeout=10" "cloud-init status" 2>/dev/null || echo "unknown")

        if [[ "${cloud_init_status}" == *"done"* ]]; then
            log "  Cloud-init status shows 'done' on ${node_ip} (may have had errors)"
        else
            log "ERROR: Cloud-init may not be ready on ${node_ip} (status: ${cloud_init_status})"

            if [[ "${MENU_MODE}" == "true" ]]; then
                echo ""
                echo "CLOUD-INIT WARNING!"
                echo "Cloud-init may not have completed successfully on ${node_ip}"
                echo "Continuing may result in incomplete VM configuration."
                echo ""
                if ! confirm_action "Continue anyway?"; then
                    log "Deployment cancelled due to cloud-init issues"
                    exit 1
                fi
            fi
        fi
    fi
done
log "Cloud-init checks complete"

############################################
# ANSIBLE CONFIGURATION
############################################

log "Generating inventory..."

# Write Ansible configuration
cat > "${ANSIBLE_CFG}" <<'EOF'
[defaults]
deprecation_warnings = False
host_key_checking = False
interpreter_python = auto_silent
stdout_callback = yaml
timeout = 30

[ssh_connection]
pipelining = True
ssh_args = -o ControlMaster=auto -o ControlPersist=60s
EOF

# Write Ansible inventory
{
    echo "[control_plane]"
    echo "cp1 ansible_host=${CP_IP}"
    echo
    echo "[workers]"
    for ((i=0; i<WORKER_COUNT; i++)); do
        echo "worker$((i+1)) ansible_host=${WORKER_IPS[$i]}"
    done
    echo
    echo "[k8s:children]"
    echo "control_plane"
    echo "workers"
    echo
    echo "[k8s:vars]"
    echo "ansible_user=${VM_USER}"
    echo "ansible_ssh_private_key_file=${VM_SSH_KEY_PATH}"
    echo "ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'"
    echo "k8s_channel=${K8S_CHANNEL}"
    echo "k8s_semver=${K8S_SEMVER}"
    echo "k8s_pkg_version=${K8S_PKG_VERSION}"
    echo "pod_cidr=${POD_CIDR}"
    echo "service_cidr=${SERVICE_CIDR}"
    echo "cp_ip=${CP_IP}"
    echo "calico_manifest_url=${CALICO_MANIFEST_URL}"
} > "${ANSIBLE_INVENTORY}"

log "Generating playbook..."

# Write comprehensive Ansible playbook
cat > "${ANSIBLE_PLAYBOOK}" <<\EOF
---
- name: Common Kubernetes node setup
  hosts: k8s
  become: true
  gather_facts: true
  tasks:
    - name: Wait for cloud-init to complete
      command: timeout {{ cloud_init_timeout | default(600) }} cloud-init status --wait
      changed_when: false
      failed_when: false

    - name: Disable Ubuntu Pro services that may interfere
      shell: |
        # Disable ESM cache and apt news services that auto-restart and cause issues
        echo "Disabling Ubuntu Pro background services..."
        systemctl stop esm-cache.service 2>/dev/null || true
        systemctl disable esm-cache.service 2>/dev/null || true
        systemctl stop ua-timer.service 2>/dev/null || true
        systemctl disable ua-timer.service 2>/dev/null || true
        systemctl stop ua-timer.timer 2>/dev/null || true
        systemctl disable ua-timer.timer 2>/dev/null || true
        systemctl stop apt-news.service 2>/dev/null || true
        systemctl disable apt-news.service 2>/dev/null || true
        systemctl stop ubuntu-advantage.service 2>/dev/null || true
        systemctl disable ubuntu-advantage.service 2>/dev/null || true

        # Mask the services to prevent them from starting
        systemctl mask esm-cache.service 2>/dev/null || true
        systemctl mask apt-news.service 2>/dev/null || true

        echo "Services disabled"
        exit 0
      changed_when: false
      failed_when: false

    - name: Optionally terminate Ubuntu Pro helper scripts
      shell: |
        # Send SIGTERM (not SIGKILL) to helper scripts only, not to apt/dpkg
        pkill -f apt_news.py 2>/dev/null || true
        pkill -f esm_cache.py 2>/dev/null || true
        pkill -f ubuntu-advantage 2>/dev/null || true
        sleep 2
      changed_when: false
      failed_when: false

    - name: Create apt lock wait script
      copy:
        dest: /tmp/wait_apt_locks.sh
        mode: '0755'
        content: |
          #!/bin/bash
          set -e
          MAX_WAIT=300
          ELAPSED=0
          INTERVAL=5

          echo "Waiting for apt locks to be released..."
          while [ $ELAPSED -lt $MAX_WAIT ]; do
            LOCKED=0

            # Check each lock file
            if fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; then
              LOCKED=1
              echo "Lock held: /var/lib/dpkg/lock-frontend"
            fi
            if fuser /var/lib/dpkg/lock >/dev/null 2>&1; then
              LOCKED=1
              echo "Lock held: /var/lib/dpkg/lock"
            fi
            if fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
              LOCKED=1
              echo "Lock held: /var/lib/apt/lists/lock"
            fi

            # If no locks held, we're done
            if [ $LOCKED -eq 0 ]; then
              echo "All apt locks released"
              touch /tmp/wait_apt_locks_done
              exit 0
            fi

            # Wait and retry
            sleep $INTERVAL
            ELAPSED=$((ELAPSED + INTERVAL))
            echo "Still waiting... (${ELAPSED}s elapsed)"
          done

          # Timeout reached - provide diagnostics
          echo "ERROR: Timeout waiting for apt locks after ${MAX_WAIT}s"
          echo ""
          echo "=== Lock file diagnostics ==="
          for lockfile in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock; do
            if [ -f "$lockfile" ]; then
              echo "Lock: $lockfile"
              if command -v lsof >/dev/null 2>&1; then
                lsof "$lockfile" 2>&1 || echo "  (no lsof info available)"
              else
                fuser -v "$lockfile" 2>&1 || echo "  (file exists but no process info)"
              fi
            fi
          done

          echo ""
          echo "=== Running apt/dpkg processes ==="
          ps aux | grep -E 'apt|dpkg' | grep -v grep || echo "(none)"

          echo ""
          echo "=== Systemd service status ==="
          systemctl list-units --type=service --state=running | grep -E 'apt|dpkg|unattended' || echo "(none)"

          exit 1

    - name: Wait for apt locks to be available
      shell: /bin/bash /tmp/wait_apt_locks.sh
      args:
        creates: /tmp/wait_apt_locks_done

    - name: Ensure lsof is installed for diagnostics
      shell: |
        if ! command -v lsof >/dev/null 2>&1; then
          export DEBIAN_FRONTEND=noninteractive
          apt-get update -qq && apt-get install -y -qq lsof
        fi
      changed_when: false

    - name: Ensure required packages
      shell: |
        set -e
        export DEBIAN_FRONTEND=noninteractive
        
        echo "Starting package installation..."
        
        # Update package list
        echo "Updating package lists..."
        apt-get update -qq || {
          echo "Failed to update package lists, retrying..."
          sleep 5
          apt-get update -qq
        }
        
        # Install packages with --no-install-recommends to reduce package count
        echo "Installing required packages..."
        apt-get install -y -qq --no-install-recommends \
          apt-transport-https \
          ca-certificates \
          curl \
          gnupg \
          lsb-release \
          software-properties-common \
          qemu-guest-agent || {
          
          # If installation fails, provide diagnostic info
          echo "ERROR: Package installation failed"
          echo "Checking for lock files..."
          for lockfile in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock; do
            if [ -f "$lockfile" ]; then
              if command -v lsof >/dev/null 2>&1; then
                echo "  $lockfile: $(lsof "$lockfile" 2>&1 || echo 'exists but no lsof info')"
              else
                fuser -v "$lockfile" 2>&1 || echo "  $lockfile: exists (lsof not available)"
              fi
            fi
          done
          
          echo "Checking dpkg status..."
          dpkg --audit || true
          
          echo "Disk space:"
          df -h / /var || true
          
          exit 1
        }
        
        echo "Package installation completed successfully"
      register: apt_install
      retries: 5
      delay: 60
      until: apt_install is succeeded

    - name: Set hostname to match inventory hostname
      hostname:
        name: "{{ inventory_hostname }}"

    - name: Update /etc/hosts with hostname
      lineinfile:
        path: /etc/hosts
        regexp: '^127\.0\.1\.1'
        line: "127.0.1.1 {{ inventory_hostname }}"
        state: present

    - name: Enable and start qemu-guest-agent
      systemd:
        name: qemu-guest-agent
        enabled: true
        state: started

    - name: Disable swap immediately if enabled
      command: swapoff -a
      when: ansible_swaptotal_mb | int > 0
      changed_when: false

    - name: Disable swap entries in /etc/fstab (fstype swap)
      replace:
        path: /etc/fstab
        regexp: '^([^#]\S+\s+\S+\s+swap\s+.*)$'
        replace: '# \1'

    - name: Ensure kernel modules config for Kubernetes
      copy:
        dest: /etc/modules-load.d/k8s.conf
        content: |
          overlay
          br_netfilter
        owner: root
        group: root
        mode: '0644'

    - name: Load overlay module
      modprobe:
        name: overlay
        state: present

    - name: Load br_netfilter module
      modprobe:
        name: br_netfilter
        state: present

    - name: Ensure sysctl params for Kubernetes networking
      copy:
        dest: /etc/sysctl.d/99-kubernetes-cri.conf
        content: |
          net.bridge.bridge-nf-call-iptables  = 1
          net.bridge.bridge-nf-call-ip6tables = 1
          net.ipv4.ip_forward                 = 1
        owner: root
        group: root
        mode: '0644'

    - name: Apply sysctl params
      command: sysctl --system
      changed_when: false

    - name: Install containerd
      apt:
        name:
          - containerd
        state: present
        update_cache: true

    - name: Ensure containerd config directory exists
      file:
        path: /etc/containerd
        state: directory
        mode: '0755'

    - name: Check if containerd config exists
      stat:
        path: /etc/containerd/config.toml
      register: containerd_config_stat

    - name: Generate default containerd config if missing
      shell: containerd config default > /etc/containerd/config.toml
      when: not containerd_config_stat.stat.exists

    - name: Check if SystemdCgroup = false exists in config
      shell: grep -q 'SystemdCgroup\s*=\s*false' /etc/containerd/config.toml
      register: systemdcgroup_false_check
      failed_when: false
      changed_when: false

    - name: Replace SystemdCgroup = false with true if it exists
      replace:
        path: /etc/containerd/config.toml
        regexp: '^(\s*)SystemdCgroup\s*=\s*false(\s*(#.*)?)$'
        replace: '\1SystemdCgroup = true\2'
      when: systemdcgroup_false_check.rc == 0
      register: containerd_cgroup_replace

    - name: Check if SystemdCgroup is already set in config
      shell: grep -q 'SystemdCgroup\s*=\s*true' /etc/containerd/config.toml
      register: systemdcgroup_check
      failed_when: false
      changed_when: false

    - name: Ensure SystemdCgroup managed block exists in runc options if not already set
      blockinfile:
        path: /etc/containerd/config.toml
        marker: "# {mark} ANSIBLE MANAGED BLOCK - SystemdCgroup"
        insertafter: '^\s*\[plugins\.(\".*\"|\S+).*runtimes\.runc\.options\]\s*$'
        block: |2
                  SystemdCgroup = true
        state: present
      when: systemdcgroup_check.rc != 0
      register: containerd_cgroup_block

    - name: Restart containerd if config changed
      systemd:
        name: containerd
        state: restarted
        enabled: true
      when: containerd_cgroup_replace is changed or containerd_cgroup_block is changed

    - name: Ensure containerd is running
      systemd:
        name: containerd
        state: started
        enabled: true

    - name: Ensure keyrings directory exists
      file:
        path: /etc/apt/keyrings
        state: directory
        mode: '0755'

    - name: Add Kubernetes apt repository keyring
      shell: |
        set -euo pipefail
        curl -fsSL "https://pkgs.k8s.io/core:/stable:/{{ k8s_channel }}/deb/Release.key" | \
        gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
      args:
        creates: /etc/apt/keyrings/kubernetes-apt-keyring.gpg
        executable: /bin/bash

    - name: Add Kubernetes apt repository
      copy:
        dest: /etc/apt/sources.list.d/kubernetes.list
        content: |
          deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/{{ k8s_channel }}/deb/ /
        owner: root
        group: root
        mode: '0644'

    - name: Update apt cache after adding Kubernetes repo
      apt:
        update_cache: true

    - name: Validate Kubernetes package availability
      shell: |
        set -euo pipefail
        AVAILABLE_VERSIONS=$(apt-cache madison kubeadm 2>/dev/null | awk '{print $3}' || echo "")
        if ! echo "$AVAILABLE_VERSIONS" | grep -qxF "{{ k8s_pkg_version }}"; then
          echo "ERROR: Kubernetes package version {{ k8s_pkg_version }} not found in repository" >&2
          echo "Available versions:" >&2
          echo "$AVAILABLE_VERSIONS" | head -10 >&2
          exit 1
        fi
      args:
        executable: /bin/bash
      changed_when: false

    - name: Install kubelet, kubeadm, kubectl at specified version
      apt:
        name:
          - "kubelet={{ k8s_pkg_version }}"
          - "kubeadm={{ k8s_pkg_version }}"
          - "kubectl={{ k8s_pkg_version }}"
        state: present

    - name: Hold Kubernetes packages
      dpkg_selections:
        name: "{{ item }}"
        selection: hold
      loop:
        - kubelet
        - kubeadm
        - kubectl

    - name: Ensure kubelet is enabled and running
      systemd:
        name: kubelet
        enabled: true
        state: started

- name: Initialize control plane
  hosts: control_plane
  become: true
  gather_facts: false
  tasks:
    - name: Check if control plane setup complete
      stat:
        path: /etc/kubernetes/admin.conf
      register: adminconf

    - name: Initialize Kubernetes control plane with kubeadm
      command: >
        kubeadm init
        --kubernetes-version {{ k8s_semver }}
        --pod-network-cidr {{ pod_cidr }}
        --service-cidr {{ service_cidr }}
        --apiserver-advertise-address {{ cp_ip }}
        --node-name {{ inventory_hostname }}
        --cri-socket unix:///run/containerd/containerd.sock
      when: not adminconf.stat.exists

    - name: Ensure kubectl config directory for default user
      file:
        path: "/home/{{ ansible_user }}/.kube"
        state: directory
        owner: "{{ ansible_user }}"
        group: "{{ ansible_user }}"
        mode: '0700'

    - name: Copy admin kubeconfig to default user
      copy:
        src: /etc/kubernetes/admin.conf
        dest: "/home/{{ ansible_user }}/.kube/config"
        remote_src: true
        owner: "{{ ansible_user }}"
        group: "{{ ansible_user }}"
        mode: '0600'

    - name: Wait for Kubernetes API server to be ready
      shell: |
        set -euo pipefail
        kubectl cluster-info --request-timeout=5s >/dev/null 2>&1
      args:
        executable: /bin/bash
      environment:
        KUBECONFIG: /etc/kubernetes/admin.conf
      register: api_ready
      until: api_ready is succeeded
      retries: 60
      delay: 5
      changed_when: false

    - name: Check if Calico is already installed
      shell: |
        set -euo pipefail
        kubectl -n kube-system get ds calico-node >/dev/null 2>&1 && echo "installed" || echo "not_installed"
      args:
        executable: /bin/bash
      environment:
        KUBECONFIG: /etc/kubernetes/admin.conf
      register: calico_check
      changed_when: false
      failed_when: false

    - name: Install Calico CNI
      shell: |
        set -euo pipefail
        kubectl apply -f "{{ calico_manifest_url }}"
      args:
        executable: /bin/bash
      environment:
        KUBECONFIG: /etc/kubernetes/admin.conf
      register: calico_install
      until: calico_install is succeeded
      retries: 5
      delay: 10
      when: calico_check.stdout == "not_installed"

    - name: Generate join command
      command: kubeadm token create --ttl 0 --print-join-command
      register: joincmd
      changed_when: false

    - name: Save join command for worker nodes
      set_fact:
        k8s_join_command: "{{ joincmd.stdout }}"

- name: Join workers to cluster
  hosts: workers
  become: true
  gather_facts: false
  tasks:
    - name: Check if worker already joined locally
      stat:
        path: /etc/kubernetes/kubelet.conf
      register: kubeletconf

    - name: Verify node exists in cluster from control plane
      shell: |
        set -euo pipefail
        kubectl get node {{ inventory_hostname }} >/dev/null 2>&1 && echo "exists" || echo "missing"
      args:
        executable: /bin/bash
      environment:
        KUBECONFIG: /etc/kubernetes/admin.conf
      delegate_to: "{{ groups['control_plane'][0] }}"
      register: node_in_cluster
      when: kubeletconf.stat.exists
      changed_when: false
      failed_when: false

    - name: Reset failed join if kubelet.conf exists but node not in cluster
      command: kubeadm reset -f
      when: 
        - kubeletconf.stat.exists
        - node_in_cluster.stdout is defined
        - node_in_cluster.stdout == "missing"
      register: kubeadm_reset

    - name: Clean up kubelet.conf after reset
      file:
        path: /etc/kubernetes/kubelet.conf
        state: absent
      when: kubeadm_reset is changed

    - name: Recheck kubelet.conf after potential reset
      stat:
        path: /etc/kubernetes/kubelet.conf
      register: kubeletconf_final

    - name: Join worker to cluster
      command: "{{ hostvars[groups['control_plane'][0]].k8s_join_command }} --node-name {{ inventory_hostname }} --cri-socket unix:///run/containerd/containerd.sock"
      when:
        - hostvars[groups['control_plane'][0]].k8s_join_command is defined
        - not kubeletconf_final.stat.exists
EOF

############################################
# RUN ANSIBLE PLAYBOOK
############################################

log "Running Ansible (5-15 min)..."

ANSIBLE_CONFIG="${ANSIBLE_CFG}" ansible-playbook -v -i "${ANSIBLE_INVENTORY}" \
    -e "cloud_init_timeout=${CLOUD_INIT_TIMEOUT_SECONDS}" \
    "${ANSIBLE_PLAYBOOK}"

############################################
# COMPLETION
############################################

log "============================================================================"
log "Deployment complete"
log "============================================================================"
log "Versions: K8s ${K8S_SEMVER}, Calico ${CALICO_VERSION}"
log "Control plane: ${CP_IP} (${CP_CORES}c, ${CP_MEMORY_MB}MB, ${CP_DISK_GB}GB)"
log "Workers (${WORKER_COUNT}):"
for ((i=0; i<WORKER_COUNT; i++)); do
    log "  ${WORKER_IPS[$i]} (${WORKER_CORES}c, ${WORKER_MEMORY_MB}MB, ${WORKER_DISK_GB}GB)"
done
log ""
log "Access: ssh -i ${VM_SSH_KEY_PATH} ${VM_USER}@${CP_IP}"
log "Verify: kubectl get nodes"
log ""
log "Note: If IPs/hostnames changed, verify with 'kubectl get nodes -o wide'"
log "      Manual cleanup may be needed for stale nodes or certificates"
log "============================================================================"
}

action_fresh_install() {
    log "Fresh install - destroying all VMs and recreating from scratch..."
    cleanup_previous_run

    echo ""
    echo "WARNING: This will destroy all existing VMs and data!"
    echo "  - Template VM (${TEMPLATE_VMID})"
    echo "  - Control Plane VM (${CP_VMID})"
    for ((i=0; i<WORKER_COUNT; i++)); do
        vmid=$(( WORKER_VMID_START + i ))
        echo "  - Worker$((i+1)) VM (${vmid})"
    done
    echo ""

    if ! confirm_action "Are you ABSOLUTELY SURE you want to proceed?"; then
        log "Fresh install cancelled"
        return 0
    fi

    # Stop and destroy all VMs (sweep up to 10 workers to catch orphans)
    log "Stopping and destroying VMs..."

    for vmid in ${CP_VMID} $(seq ${WORKER_VMID_START} $((WORKER_VMID_START + 9))); do
        if pve_has_vmid "${vmid}"; then
            log "  Stopping VM ${vmid}..."
            if ! qm_output=$(qm stop "${vmid}" 2>&1); then
                # VM might already be stopped, check status without relying on field positions
                if qm status "${vmid}" 2>/dev/null | grep -qi 'stopped'; then
                    log "    VM ${vmid} already stopped"
                else
                    log "    WARNING: Failed to stop VM ${vmid}: ${qm_output}"
                fi
            fi
            sleep 2
            log "  Destroying VM ${vmid}..."
            if ! qm_output=$(qm destroy "${vmid}" 2>&1); then
                log "    ERROR: Failed to destroy VM ${vmid}: ${qm_output}"
            else
                log "    Destroyed VM ${vmid}"
            fi
        fi
    done

    # Destroy template
    if pve_has_vmid "${TEMPLATE_VMID}"; then
        log "  Destroying template ${TEMPLATE_VMID}..."
        if ! qm_output=$(qm destroy "${TEMPLATE_VMID}" 2>&1); then
            log "    ERROR: Failed to destroy template: ${qm_output}"
        else
            log "    Destroyed template"
        fi
    fi

    # Clean up Ansible directory
    if [[ -d "${ANSIBLE_DIR}" ]]; then
        log "Cleaning up Ansible directory..."
        rm -rf "${ANSIBLE_DIR}"
    fi

    # Flush ARP cache to prevent IP conflict warnings from stale entries
    log "Flushing ARP cache..."
    if command -v ip >/dev/null 2>&1; then
        ip -s -s neigh flush all >/dev/null 2>&1 || true
    fi
    sleep 2  # Give ARP cache time to clear

    log "VMs destroyed. Starting fresh deployment..."
    # Set flag to skip IP conflict checks since we just destroyed the VMs
    SKIP_IP_CONFLICT_CHECK="true"
    action_reconfigure
    SKIP_IP_CONFLICT_CHECK="false"  # Reset for future operations
}

action_destroy_cluster() {
    log "Destroying cluster..."

    echo ""
    echo "DANGER: This will permanently delete:"
    echo "  - All VMs (Template, Control Plane, Workers)"
    echo "  - All Kubernetes data"
    echo "  - Ansible configuration"
    echo "  - (Ubuntu cloud image will be kept)"
    echo ""

    if ! confirm_action "Are you SURE you want to destroy the cluster?"; then
        log "Destroy cancelled"
        return 0
    fi

    echo ""
    if ! confirm_action "Type 'y' again to confirm PERMANENT DELETION"; then
        log "Destroy cancelled"
        return 0
    fi

    # Stop and destroy all VMs (sweep up to 10 workers to catch orphans)
    log "Stopping and destroying VMs..."

    for vmid in ${CP_VMID} $(seq ${WORKER_VMID_START} $((WORKER_VMID_START + 9))); do
        if pve_has_vmid "${vmid}"; then
            log "  Stopping VM ${vmid}..."
            if ! qm_output=$(qm stop "${vmid}" 2>&1); then
                # VM might already be stopped, check status without relying on field positions
                if qm status "${vmid}" 2>/dev/null | grep -qi 'stopped'; then
                    log "    VM ${vmid} already stopped"
                else
                    log "    WARNING: Failed to stop VM ${vmid}: ${qm_output}"
                fi
            fi
            sleep 2
            log "  Destroying VM ${vmid}..."
            if ! qm_output=$(qm destroy "${vmid}" 2>&1); then
                log "    ERROR: Failed to destroy VM ${vmid}: ${qm_output}"
            else
                log "    Destroyed"
            fi
        fi
    done

    # Destroy template
    if pve_has_vmid "${TEMPLATE_VMID}"; then
        log "  Destroying template ${TEMPLATE_VMID}..."
        if ! qm_output=$(qm destroy "${TEMPLATE_VMID}" 2>&1); then
            log "    ERROR: Failed to destroy template: ${qm_output}"
        else
            log "    Destroyed"
        fi
    fi

    # Clean up Ansible directory
    if [[ -d "${ANSIBLE_DIR}" ]]; then
        log "Removing Ansible directory..."
        rm -rf "${ANSIBLE_DIR}"
    fi

    log "============================================================================"
    log "Cluster destroyed"
    log "============================================================================"
}

action_reset_kubernetes() {
    log "Resetting Kubernetes cluster (keeping VMs)..."
    cleanup_previous_run

    echo ""
    echo "This will reset Kubernetes on all nodes:"
    echo "  - Run 'kubeadm reset' on all nodes"
    echo "  - Clear /etc/kubernetes, /var/lib/kubelet, /etc/cni/net.d"
    echo "  - Reinitialize the cluster"
    echo "  - VMs and OS configuration will be preserved"
    echo ""

    if ! confirm_action "Proceed with Kubernetes reset?"; then
        log "Reset cancelled"
        return 0
    fi

    # Check if VMs are running
    if ! pve_has_vmid "${CP_VMID}" || [[ "$(get_vm_status ${CP_VMID})" != "running" ]]; then
        log "ERROR: Control plane VM not running"
        return 1
    fi

    # Reset all nodes
    log "Resetting Kubernetes on all nodes..."

    # Reset workers first
    for ((i=0; i<WORKER_COUNT; i++)); do
        local ip="$(ip_add_octet "${WORKER_IP_BASE}" "${WORKER_IP_START_OCTET}" "${i}")"
        log "  Resetting worker$((i+1)) (${ip})..."
        ssh_vm "${ip}" 'sudo systemctl stop kubelet 2>/dev/null || true; \
             sudo kubeadm reset -f; \
             sudo rm -rf /etc/cni/net.d/* /var/lib/cni/* /var/lib/kubelet/* /etc/kubernetes/*; \
             sudo iptables -F 2>/dev/null || true; \
             sudo iptables -t nat -F 2>/dev/null || true; \
             sudo iptables -t mangle -F 2>/dev/null || true; \
             sudo iptables -X 2>/dev/null || true; \
             sudo systemctl restart containerd; \
             sudo systemctl start kubelet 2>/dev/null || true' 2>/dev/null || log "    Failed to reset worker$((i+1))"
    done

    # Reset control plane last
    log "  Resetting control plane (${CP_IP})..."
    ssh_vm "${CP_IP}" 'sudo systemctl stop kubelet 2>/dev/null || true; \
         sudo kubeadm reset -f; \
         sudo rm -rf /etc/cni/net.d/* /var/lib/cni/* /var/lib/kubelet/* /etc/kubernetes/*; \
         sudo iptables -F 2>/dev/null || true; \
         sudo iptables -t nat -F 2>/dev/null || true; \
         sudo iptables -t mangle -F 2>/dev/null || true; \
         sudo iptables -X 2>/dev/null || true; \
         sudo systemctl restart containerd; \
         sudo systemctl start kubelet 2>/dev/null || true' 2>/dev/null || log "    Failed to reset control plane"

    # Clean up Ansible directory to force regeneration
    if [[ -d "${ANSIBLE_DIR}" ]]; then
        log "Cleaning Ansible configuration..."
        rm -rf "${ANSIBLE_DIR}"
    fi

    log "Kubernetes reset complete. Reinitializing cluster..."

    # Rerun the deployment (which will detect empty cluster and reinitialize)
    action_reconfigure
}

action_scale_cluster() {
    log "Scaling cluster..."

    echo ""
    echo "Current worker count: ${WORKER_COUNT}"
    echo ""

    # Count existing worker VMs
    local existing_workers=0
    for ((i=0; i<10; i++)); do
        vmid=$(( WORKER_VMID_START + i ))
        if pve_has_vmid "${vmid}"; then
            existing_workers=$((existing_workers + 1))
        fi
    done

    echo "Existing worker VMs: ${existing_workers}"
    echo "Script configured for: ${WORKER_COUNT} workers"
    echo ""

    if (( existing_workers < WORKER_COUNT )); then
        log "Scaling UP: Adding $((WORKER_COUNT - existing_workers)) worker(s)"
        if confirm_action "Add new worker nodes?"; then
            # Run cleanup before reconfigure when scaling up
            cleanup_previous_run
            action_reconfigure
        fi
    elif (( existing_workers > WORKER_COUNT )); then
        log "Scaling DOWN: Removing $((existing_workers - WORKER_COUNT)) worker(s)"
        echo ""
        echo "Orphaned VMs:"
        for ((i=WORKER_COUNT; i<existing_workers; i++)); do
            vmid=$(( WORKER_VMID_START + i ))
            echo "  Worker$((i+1)) (VMID ${vmid})"
        done
        echo ""

        if ! confirm_action "Remove orphaned worker VMs?"; then
            log "Scale down cancelled"
            return 0
        fi

        # Try to drain and delete nodes from Kubernetes first
        if pve_has_vmid "${CP_VMID}" && [[ "$(get_vm_status ${CP_VMID})" == "running" ]]; then
            log "Attempting to drain nodes from Kubernetes..."
            for ((i=WORKER_COUNT; i<existing_workers; i++)); do
                local node_name="worker$((i+1))"
                log "  Draining ${node_name}..."
                ssh_vm "${CP_IP}" "kubectl drain ${node_name} --delete-emptydir-data --force --ignore-daemonsets --timeout=60s" 2>/dev/null || log "    Failed to drain"
                log "  Deleting ${node_name} from cluster..."
                ssh_vm "${CP_IP}" "kubectl delete node ${node_name}" 2>/dev/null || log "    Failed to delete"
            done
        fi

        # Destroy orphaned VMs
        log "Destroying orphaned VMs..."
        for ((i=WORKER_COUNT; i<existing_workers; i++)); do
            vmid=$(( WORKER_VMID_START + i ))
            log "  Stopping VM ${vmid}..."
            if ! qm_output=$(qm stop "${vmid}" 2>&1); then
                # VM might already be stopped, check status without relying on field positions
                if qm status "${vmid}" 2>/dev/null | grep -qi 'stopped'; then
                    log "    VM ${vmid} already stopped"
                else
                    log "    WARNING: Failed to stop VM ${vmid}: ${qm_output}"
                fi
            fi
            sleep 2
            log "  Destroying VM ${vmid}..."
            if ! qm_output=$(qm destroy "${vmid}" 2>&1); then
                log "    ERROR: Failed to destroy VM ${vmid}: ${qm_output}"
            else
                log "    Destroyed"
            fi
        done

        log "Scale down complete"
    else
        log "Cluster is already at desired scale (${WORKER_COUNT} workers)"
    fi
}

############################################
# MAIN EXECUTION
############################################

# If non-interactive mode, execute action and exit
if [[ "${MENU_MODE}" == "false" ]]; then
    ensure_root
    detect_network_config
    apply_network_defaults

    case "${CHOSEN_ACTION}" in
        install) action_fresh_install ;;
        reconfigure) action_reconfigure ;;
        scale) action_scale_cluster ;;
        reset) action_reset_kubernetes ;;
        destroy) action_destroy_cluster ;;
        status) action_view_status ;;
        cleanup) action_kill_processes ;;
        update-deps) action_update_dependencies ;;
        export-kubeconfig) action_export_kubeconfig ;;
        *) log "ERROR: Unknown action '${CHOSEN_ACTION}'"; show_help; exit 1 ;;
    esac
    exit 0
fi

# Interactive menu mode
log "Starting in interactive mode..."
ensure_root
detect_network_config
apply_network_defaults

# Main menu loop
while true; do
    show_menu
    choice=$(read_choice)

    case $choice in
        1) action_fresh_install ;;
        2) action_reconfigure ;;
        3) action_scale_cluster ;;
        4) action_reset_kubernetes ;;
        5) action_destroy_cluster ;;
        6) action_power_management ;;
        7) action_kill_processes ;;
        8) action_view_status ;;
        9) action_ssh_node ;;
        10) action_update_dependencies ;;
        11) action_export_kubeconfig ;;
        0) log "Exiting..."; exit 0 ;;
        *) echo "Invalid choice. Press Enter to continue..."; read ;;
    esac

    echo ""
    echo "Press Enter to return to menu..."
    read
done
