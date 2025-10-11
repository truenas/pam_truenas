#!/usr/bin/env bash

######################################################################
# Build and install pam_truenas in the VM
######################################################################

set -eu

echo "Building and installing pam_truenas..."

# Load VM info
source /tmp/vm-info.sh

# Wait for cloud-init to finish
echo "Waiting for cloud-init to complete..."
ssh debian@$VM_IP "cloud-init status --wait" || true

# Install rsync in VM first
echo "Installing rsync in VM..."
ssh debian@$VM_IP "sudo apt-get update && sudo apt-get install -y rsync"

# Copy source code to VM
echo "Copying source code to VM..."
ssh debian@$VM_IP "mkdir -p ~/pam_truenas"
rsync -az --exclude='.git' --exclude='debian/.debhelper' \
  --exclude='src/.libs' --exclude='*.o' --exclude='*.lo' \
  "$GITHUB_WORKSPACE/" debian@$VM_IP:~/pam_truenas/

# Install dependencies and build
echo "Installing dependencies in VM..."
ssh debian@$VM_IP 'bash -s' <<'REMOTE_SCRIPT'
set -eu

cd ~/pam_truenas

# Update package lists
sudo apt-get update

# Install build dependencies
sudo apt-get install -y \
  build-essential \
  devscripts \
  debhelper \
  dh-autoreconf \
  dh-python \
  autoconf \
  automake \
  libtool \
  pkg-config \
  libpam0g-dev \
  libkeyutils-dev \
  libjansson-dev \
  uuid-dev \
  libssl-dev \
  libbsd-dev \
  libidn-dev \
  python3-dev \
  python3-all-dev \
  python3-pip \
  python3-setuptools \
  python3-build \
  python3-installer \
  python3-pytest \
  python3-pycryptodome \
  pybuild-plugin-pyproject \
  git

# Build and install truenas_scram
echo "Building truenas_scram..."
cd /tmp
git clone https://github.com/truenas/truenas_scram.git
cd truenas_scram
dpkg-buildpackage -us -uc -b
sudo dpkg -i ../libtruenas-scram1_*.deb
sudo dpkg -i ../libtruenas-scram-dev_*.deb
sudo dpkg -i ../python3-truenas-scram_*.deb

# Build and install truenas_pwenc
echo "Building truenas_pwenc..."
cd /tmp
git clone https://github.com/truenas/truenas_pwenc.git
cd truenas_pwenc
dpkg-buildpackage -us -uc -b
sudo dpkg -i ../libtruenas-pwenc1_*.deb
sudo dpkg -i ../libtruenas-pwenc-dev_*.deb
sudo dpkg -i ../python3-truenas-pwenc_*.deb

# Build and install truenas_pykeyring (with debug symbols)
echo "Building truenas_pykeyring..."
cd /tmp
git clone https://github.com/truenas/truenas_pykeyring.git
cd truenas_pykeyring
# Build with debug symbols for better backtraces
DEB_BUILD_OPTIONS="nostrip" dpkg-buildpackage -us -uc -b
sudo dpkg -i ../python3-truenas-pykeyring_*.deb

# Build and install truenas_pypam
echo "Building truenas_pypam..."
cd /tmp
git clone https://github.com/truenas/truenas_pypam.git
cd truenas_pypam
dpkg-buildpackage -us -uc -b
sudo dpkg -i ../python3-truenas-pypam_*.deb

# Build pam_truenas
echo "Building pam_truenas..."
cd ~/pam_truenas
dpkg-buildpackage -us -uc -b

# Install pam_truenas packages
echo "Installing pam_truenas..."
sudo dpkg -i ../libpam-truenas_*.deb
sudo dpkg -i ../python3-truenas-pam-utils_*.deb

# Verify installation
echo "Verifying installation..."
test -f /usr/lib/security/pam_truenas.so || (echo "ERROR: PAM module not found"; exit 1)
python3 -c "import truenas_pam_session" || (echo "ERROR: truenas_pam_session not importable"; exit 1)
python3 -c "import truenas_pam_faillog" || (echo "ERROR: truenas_pam_faillog not importable"; exit 1)

echo "Build and installation complete!"
REMOTE_SCRIPT

echo "pam_truenas installed successfully in VM"
