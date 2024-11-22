#Comprehensive script to scan Docker and Kubernetes installations for the top 15 application security issues.
#It identifies installed components, checks for specific vulnerabilities and misconfigurations, and provides actionable advice

# for detail usage steps refer README file


#!/bin/bash

# Script to scan Docker and Kubernetes security issues and generate a report

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root"
  exit 1
fi

# Get hostname and date
HOSTNAME=$(hostname)
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
OUTPUT_FILE="security_report_${HOSTNAME}_${TIMESTAMP}.txt"

# Function to check if a package is installed
check_installed() {
  dpkg -l | grep -qw "$1" && echo "$1 is installed" || echo "$1 is NOT installed"
}

# Function to analyze a Docker installation
scan_docker() {
  echo "Checking Docker security issues..."
  echo "Docker Installation Status: $(check_installed docker)" >> $OUTPUT_FILE
  
  # Check for insecure images
  echo "Scanning for insecure images..." >> $OUTPUT_FILE
  docker images --format "{{.Repository}}:{{.Tag}}" | while read image; do
    if ! docker scan "$image" &>/dev/null; then
      echo "WARNING: Image $image has vulnerabilities. Scan it manually." >> $OUTPUT_FILE
    fi
  done
  
  # Check if Docker is running as root
  echo "Checking if Docker is running as root..." >> $OUTPUT_FILE
  ps aux | grep dockerd | grep -q -- "--userns-remap" || echo "WARNING: Docker is running as root. Enable user namespace remapping." >> $OUTPUT_FILE
  
  # Check for exposed ports
  echo "Checking for exposed container ports..." >> $OUTPUT_FILE
  docker ps --format "{{.Names}}" | while read container; do
    ports=$(docker inspect --format='{{range $p, $conf := .NetworkSettings.Ports}}{{$p}} {{end}}' $container)
    if [ -n "$ports" ]; then
      echo "Container $container has exposed ports: $ports" >> $OUTPUT_FILE
    else
      echo "Container $container has no exposed ports." >> $OUTPUT_FILE
    fi
  done
}

# Function to analyze a Kubernetes installation
scan_kubernetes() {
  echo "Checking Kubernetes security issues..."
  echo "Kubernetes Installation Status: $(check_installed kubectl)" >> $OUTPUT_FILE
  
  # Check for RBAC misconfigurations
  echo "Checking RBAC configurations..." >> $OUTPUT_FILE
  kubectl get clusterroles --no-headers | while read role; do
    kubectl get clusterrole "$role" -o yaml | grep -q "rules: \[\]" && echo "WARNING: Role $role has excessive permissions." >> $OUTPUT_FILE
  done
  
  # Check for network policies
  echo "Checking for network policies..." >> $OUTPUT_FILE
  policies=$(kubectl get networkpolicy --all-namespaces)
  if [ -z "$policies" ]; then
    echo "WARNING: No network policies found. Pods are overly permissive." >> $OUTPUT_FILE
  else
    echo "Network policies are configured." >> $OUTPUT_FILE
  fi
  
  # Check for unencrypted traffic
  echo "Checking for unencrypted traffic..." >> $OUTPUT_FILE
  kubectl get svc --all-namespaces -o json | jq -r '.items[] | select(.spec.ports[] | select(.name == "http")).metadata.name' | while read svc; do
    echo "WARNING: Service $svc is running on unencrypted HTTP." >> $OUTPUT_FILE
  done
}

# Main Execution
echo "Starting security scan..." > $OUTPUT_FILE
scan_docker
scan_kubernetes

echo "Security scan completed. Report saved in $OUTPUT_FILE"
