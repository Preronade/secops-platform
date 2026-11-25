# SSH brute force response
Signs: many failed SSH logins from one IP in a short time, often against root or common usernames.
Immediate actions: block the source IP at the security group or firewall, check auth logs for any successful login from that IP, rotate credentials if one succeeded.
Hardening: disable password login and use keys only, disable root login, restrict port 22 to known IP ranges, use fail2ban, enable MFA or a bastion host.
Triage: HIGH if a login succeeded or there are hundreds of attempts. MEDIUM for a few failures. LOW for a single stray attempt.
