# Introduction

For some cloud use cases, the VM-Series firewalls are behind a device that alters (source NATs) the source IP.  The VM-Series has a variety of features that can detect malicious behavior coming from a specific IP and then block traffic for a period of time from that source IP.  This does not work if an upstream device SNATs the IP.  Many devices including AWS load balancers preserve the original source IP in the X-Forwarded-For (XFF) header.  This solution leverages the XFF header in policy for additional protection.

This project demonstrates the Use of HTTP log forwarding and Lambda functions to respond to detected threats. In this case we extract the true source ip of the threat from the XFF header and inject it into the firewalls User-ID database to block traffic from a source IP.  This allows us to block traffic based on a soure IP when the firewall is behind an Application loadbalancer that is performing source NAT and X-Forwarded-For header insertion of the original source IP.

# Architecture
This solution is based on the following architecture and native AWS services:
![alt text](/documentation/XFF-User-ID-mapping.png?raw=true "Topology for the XFF to User-ID mapping solution")

# Support
This template/solution is released under an as-is, best effort, support policy. These scripts should be seen as community supported and Palo Alto Networks will contribute our expertise as and when possible. We do not provide technical support or help in using or troubleshooting the components of the project through our normal support options such as Palo Alto Networks support teams, or ASC (Authorized Support Centers) partners and backline support options. The underlying product used (the VM-Series firewall) by the scripts or templates are still supported, but the support is only for the product functionality and not for help in deploying or using the template or script itself. Unless explicitly tagged, all projects or work posted in our GitHub repository (at https://github.com/PaloAltoNetworks) or sites other than our official Downloads page on https://support.paloaltonetworks.com are provided under the best effort policy.

For assistance from the community, please post your questions and comments either to the GitHub page where the solution is posted or on our Live Community site dedicated to public cloud discussions at https://live.paloaltonetworks.com/t5/AWS-Azure-Discussions/bd-p/AWS_Azure_Discussions
