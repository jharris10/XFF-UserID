This project demonstrates the Use of HTTP log forwarding and Lambda functions to respond to detected threats. In this case we extract the true source ip of the threat from the X-Forwarded-For header and inject it into the firewalls User database to block traffic from a source IP.  This allows us to block traffic based on a soure IP when the firewall is behind and Elastic loadbalancer that is performing source NAT.
Password for the firewall is admin/Pal0Alt0