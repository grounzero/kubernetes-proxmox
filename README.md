# Kubernetes on Proxmox

Automated Kubernetes cluster deployment script for Proxmox VE with an interactive menu system.

## Features

- **Interactive Menu System**: Choose between different operations instead of running full deployment every time
- **Multiple Deployment Options**:
  - Fresh Install (complete reinstall from scratch)
  - Reconfigure/Update (update existing cluster)
  - Scale Cluster (add or remove worker nodes)
  - Reset Kubernetes (reinitialize cluster while keeping VMs)
  - Destroy Cluster (remove all VMs)
  - Power Management (start/stop VMs)
  - Process Cleanup (kill stuck processes)
  - View Status (cluster information)
  - SSH to Node (quick SSH access)

- **Non-Interactive Mode**: Run specific actions via command-line for automation
- **Network Auto-Detection**: Automatically detects network configuration from Proxmox bridge interface
- **Safety Features**:
  - Confirmation prompts for destructive operations
  - Ping checks before SSH attempts
  - SSH key validation
  - Empty IP checks
  - Orphaned VM cleanup

## Requirements

- Proxmox VE host
- Root access to Proxmox
- Network connectivity from Proxmox to VMs
- Sufficient storage for VM creation

## Default Configuration

- **Kubernetes Version**: v1.35.0
- **Calico CNI Version**: v3.29
- **Ubuntu Release**: 24.04 (Noble)
- **Control Plane**: 1 node (VMID 9100)
- **Workers**: 2 nodes (VMIDs 9101-9102)
- **Template**: VMID 9000

## Usage

### Interactive Mode (Default)

```bash
./kubernetes-proxmox.sh
```

This launches an interactive menu where you can select from 10 different options.

### Non-Interactive Mode

Run specific actions via command-line:

```bash
# Fresh install from scratch
./kubernetes-proxmox.sh -a install

# Update existing cluster
./kubernetes-proxmox.sh -a reconfigure

# Scale cluster (adjust WORKER_COUNT in script first)
./kubernetes-proxmox.sh -a scale

# Reset Kubernetes (keep VMs)
./kubernetes-proxmox.sh -a reset

# Destroy cluster
./kubernetes-proxmox.sh -a destroy

# View cluster status
./kubernetes-proxmox.sh -a status

# Kill stuck processes
./kubernetes-proxmox.sh -a cleanup

# Show help
./kubernetes-proxmox.sh -h
```

## Configuration Variables

Edit the following variables at the top of the script to customize your deployment:

```bash
# VM Configuration
CP_VMID=9100                    # Control plane VM ID
WORKER_VMID_START=9101          # First worker VM ID
WORKER_COUNT=2                  # Number of worker nodes
TEMPLATE_VMID=9000              # Template VM ID

# VM Resources
VM_CORES=2
VM_MEMORY=4096
VM_DISK_SIZE="32G"

# Kubernetes Versions
K8S_VERSION="1.35"
K8S_SEMVER="v1.35.0"
CALICO_VERSION="v3.29"

# Ubuntu Release
UBUNTU_RELEASE="noble"          # 24.04 LTS
```

## Network Configuration

The script auto-detects network configuration from your Proxmox bridge interface (`vmbr0` by default). You can override these settings:

```bash
NET_CIDR_PREFIX=""              # e.g., "10.0.0.0/24"
NET_GATEWAY=""                  # e.g., "10.0.0.1"
CP_IP=""                        # Control plane IP
WORKER_IP_BASE=""               # Worker IP prefix
WORKER_IP_START_OCTET=51        # Starting octet for workers
```

## What the Script Does

1. **Creates VMs**: Downloads Ubuntu cloud image and creates Proxmox VMs
2. **Configures Cloud-Init**: Sets up SSH keys, network configuration
3. **Installs Prerequisites**: Installs containerd, kubeadm, kubectl, kubelet
4. **Initializes Kubernetes**: Creates control plane and joins worker nodes
5. **Installs Calico CNI**: Deploys Calico networking
6. **Validates Cluster**: Ensures all nodes are ready and pods are running

## Menu Options Explained

1. **Fresh Install**: Destroys all existing VMs and performs complete reinstall
2. **Reconfigure/Update**: Updates existing cluster (non-destructive, current default behavior)
3. **Scale Cluster**: Add or remove worker nodes based on WORKER_COUNT
4. **Reset Kubernetes**: Runs `kubeadm reset` and reinitializes cluster (keeps VMs)
5. **Destroy Cluster**: Removes all VMs and cleans up resources
6. **Stop/Start VMs**: Power management submenu
7. **Kill Stuck Processes**: Cleans up ansible-playbook and apt processes
8. **View Status**: Shows VM status and cluster information
9. **SSH to Node**: Quick SSH access to control plane or workers
0. **Exit**: Exit without performing any actions

## Safety Considerations

- All destructive operations require confirmation
- Destroy Cluster option requires double confirmation
- Network detection validates configuration before proceeding
- SSH operations include timeout and connectivity checks
- Cleanup operations check for SSH key existence before attempting connections

## Troubleshooting

### Stuck apt processes

Run cleanup: `./kubernetes-proxmox.sh -a cleanup`

### VMs not responding

Check VM status: `./kubernetes-proxmox.sh -a status`

### Network issues

The script auto-detects network from vmbr0. Verify bridge configuration on Proxmox.

### SSH connection failures

Ensure VM_SSH_KEY_PATH points to valid SSH key (default: `/root/.ssh/vm_deploy_key`)

## License

MIT

## Contributing

Contributions welcome! Please open an issue or submit a pull request.
