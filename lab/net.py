"""Addresses and names shared by every component. All of them exist only inside the lab.

`.example` is a reserved TLD (RFC 2606), so none of these names can resolve on the real internet.
The IPs match docker-compose.yml; in-process runs present the same IPs to fake_graph.
"""

TENANT_DOMAIN = "contoso-lab.example"
ATTACKER_DOMAIN = "attacker.example"
EXFIL_HOST = f"cdn.{ATTACKER_DOMAIN}"
INTRANET_HOST = f"intranet.{TENANT_DOMAIN}"
PARTNER_DOMAIN = "vendor-partner.example"

GRAPH_AUDIENCE = "https://graph.lab.example"
COPILOT_AUDIENCE = "api://helpdesk-copilot"
ISSUER = "https://login.lab.example/contoso-lab"

AGENT_VULNERABLE_IP = "172.30.77.10"
AGENT_HARDENED_IP = "172.30.77.11"
ATTACKER_IP = "172.30.77.66"
USER_IP = "172.30.77.100"
SIDECAR_IP = "172.30.78.12"

HELPDESK_MAILBOX = f"helpdesk@{TENANT_DOMAIN}"
COPILOT_APP = "HelpdeskCopilot"
PUBLIC_CLIENT = "LabWebClient"
