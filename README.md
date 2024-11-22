# Security-scan-docker-k8s
comprehensive script to scan Docker and Kubernetes installations for the top 15 application security issues.
It identifies installed components, checks for specific vulnerabilities and misconfigurations, and provides actionable advice.


The output is saved in a file with the hostname and timestamp.


Key Features:

1. Component Detection: Checks if Docker and Kubernetes are installed.

2. Security Checks: Validates RBAC, exposed ports, unencrypted traffic, etc.

3. Actionable Advice: Suggests fixes for identified issues.

4. Output: Saves a timestamped report for later reference.


To run this script,

a. save it as scan_security.sh

b. make it executable (chmod +x scan_security.sh)

c. execute it as root.


