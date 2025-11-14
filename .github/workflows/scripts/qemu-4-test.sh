#!/usr/bin/env bash

######################################################################
# Run pytest tests in the VM
######################################################################

set -eu

echo "Running pytest tests..."

# Load VM info
source /tmp/vm-info.sh

# Run tests in VM
ssh debian@$VM_IP 'bash -s' <<'REMOTE_SCRIPT'
set -eu

cd ~/pam_truenas

echo "=========================================="
echo "Running pytest tests"
echo "=========================================="

# Create PAM service files for tests (using the working configuration from the server)
sudo tee /etc/pam.d/middleware <<'EOF'
#
# The PAM configuration file for the Shadow `login' service
#
auth	[success=1 default=ignore] pam_truenas.so debug allow_password_auth use_env_config
auth	[default=done] pam_truenas.so debug authfail
auth	required pam_truenas.so debug authsucc
auth	required	pam_permit.so

# Standard Un*x account and session
account sufficient pam_permit.so
session required pam_truenas.so debug session_utmp
session sufficient pam_permit.so
EOF

sudo tee /etc/pam.d/middleware-scram <<'EOF'
#
# The PAM configuration file for SCRAM authentication with tally support
#
auth	[success=1 default=ignore] pam_truenas.so debug use_env_config
auth	[default=done] pam_truenas.so debug authfail
auth	required pam_truenas.so debug authsucc
auth	required	pam_permit.so

# Standard Un*x account and session
account sufficient pam_permit.so
session required pam_truenas.so debug session_utmp
session sufficient pam_permit.so
EOF

# Create directory for pwenc secret (needed for keyring encryption)
sudo mkdir -p /data

# Create test user 'bob' that the tests use
sudo useradd -m -s /bin/bash bob || true

# Verify PAM module installation
echo "Verifying PAM module installation..."
echo "Searching for pam_truenas.so in standard locations:"
find /lib /usr/lib -name "pam_truenas.so" 2>/dev/null || echo "Not found with find"
echo ""
echo "Checking standard PAM module directories:"
ls -la /lib/*/security/ 2>/dev/null | grep -E "pam_|total" || echo "No /lib/*/security/"
ls -la /usr/lib/*/security/ 2>/dev/null | grep -E "pam_|total" || echo "No /usr/lib/*/security/"
ls -la /usr/lib/security/ 2>/dev/null | grep -E "pam_|total" || echo "No /usr/lib/security/"
echo ""
echo "Checking where other PAM modules are installed:"
ls -la /lib/x86_64-linux-gnu/security/pam_permit.so 2>/dev/null || \
ls -la /usr/lib/x86_64-linux-gnu/security/pam_permit.so 2>/dev/null || \
echo "Could not find pam_permit.so"
echo ""
if [ -f /usr/lib/security/pam_truenas.so ]; then
  echo "Found at /usr/lib/security/pam_truenas.so"
  sudo ldd /usr/lib/security/pam_truenas.so
fi

# Install debug symbols for better crash reports
echo "Installing debug symbols..."
sudo apt-get install -y python3-dbg gdb systemd-coredump 2>&1 | grep -v "^\(Reading\|Building\|Extracting\)" || true

# Configure core dumps - bypass systemd-coredump and dump directly to files
echo "Configuring core dumps..."

# Create directory for core dumps
sudo mkdir -p /tmp/cores
sudo chmod 777 /tmp/cores

# Disable systemd-coredump and dump directly to files
sudo systemctl mask systemd-coredump.socket 2>&1 || true
echo '/tmp/cores/core.%e.%p.%t' | sudo tee /proc/sys/kernel/core_pattern

# Enable unlimited core dumps for current shell and sudo
ulimit -c unlimited

echo "Core dump configuration:"
cat /proc/sys/kernel/core_pattern
echo "ulimit -c: $(ulimit -c)"
echo ""
echo "Core dump directory:"
ls -la /tmp/cores/

# Run pytest with verbose output and catch crashes
echo "Running tests..."

# Verify ulimit is set before running tests
echo "Current ulimit -c: $(ulimit -c)"
echo "Verifying core dumps will work with sudo:"
sudo sh -c "ulimit -c unlimited && ulimit -c"

# First, run a single test with full output to see what's failing
echo "Running single test with full traceback for debugging..."
sudo sh -c "ulimit -c unlimited && cd /home/debian/pam_truenas && python3 -m pytest tests/test_api_key_auth_legacy.py::test_api_key_authentication -vv --tb=long" 2>&1 | tee /home/debian/test-debug.txt

# Show relevant PAM errors from journalctl
echo ""
echo "PAM errors from journalctl:"
sudo journalctl -n 100 --no-pager | grep -i pam | tail -20 || echo "No PAM logs found"
echo ""
echo "Now running full test suite..."
sudo sh -c "ulimit -c unlimited && cd /home/debian/pam_truenas && python3 -m pytest tests/ -v --tb=short" 2>&1 | tee /home/debian/test-output.txt
TEST_EXIT_CODE=${PIPESTATUS[0]}

# Check if there was a core dump
echo ""
echo "=========================================="
echo "Checking for core dumps..."
echo "=========================================="
ls -lh /tmp/cores/
echo ""

if ls /tmp/cores/core.* 2>/dev/null; then
    echo "Core dumps found!"
    echo ""
    for core in /tmp/cores/core.*; do
        echo "=========================================="
        echo "Analyzing $core"
        echo "=========================================="
        # Extract executable name from core filename (core.python3.PID.timestamp)
        exe_name=$(echo "$core" | sed 's|.*core\.\([^.]*\)\..*|\1|')
        exe_path="/usr/bin/$exe_name"

        echo "Executable: $exe_path"
        echo "Core file: $core"
        echo ""
        echo "Extracting full backtrace..."
        echo "----------------------------------------"
        sudo gdb -batch \
            -ex "set pagination off" \
            -ex "thread apply all bt full" \
            -ex "quit" \
            "$exe_path" "$core" 2>&1 | tee -a ~/test-output.txt
        echo "----------------------------------------"
        echo ""
    done
    echo "=========================================="
else
    echo "No core dumps found in /tmp/cores/"
    echo "This may indicate the crash didn't generate a core, or ulimit settings prevented it."
fi
echo $TEST_EXIT_CODE > ~/test-exitcode.txt

echo "=========================================="
echo "Test run complete (exit code: $TEST_EXIT_CODE)"
echo "=========================================="

exit $TEST_EXIT_CODE
REMOTE_SCRIPT

# Capture test results
TEST_EXIT_CODE=$?

# Copy test output back to runner
scp debian@$VM_IP:~/test-output.txt /tmp/ || true
scp debian@$VM_IP:~/test-exitcode.txt /tmp/ || true

if [ $TEST_EXIT_CODE -eq 0 ]; then
  echo "All tests passed!"
else
  echo "Tests failed with exit code: $TEST_EXIT_CODE"
  exit $TEST_EXIT_CODE
fi
