# Credential Attacks in Network Traffic

## Overview

Credential theft and misuse are central to most intrusions. Network traffic captures can reveal authentication attempts, credential harvesting, brute force attacks, and cleartext credential exposure. This analysis maps to MITRE ATT&CK Tactic TA0006 (Credential Access) and TA0008 (Lateral Movement).

## NTLM Authentication Analysis

NTLM authentication is visible in SMB, HTTP, LDAP, and MSSQL traffic. The NTLMSSP (NT LAN Manager Security Support Provider) exchange consists of three messages:

### NTLMSSP Message Flow

1. **NTLMSSP_NEGOTIATE** (Type 1): Client announces supported NTLM features and flags.
2. **NTLMSSP_CHALLENGE** (Type 2): Server responds with a challenge (8-byte nonce), server information, and target name.
3. **NTLMSSP_AUTH** (Type 3): Client responds with the username, domain, workstation name, and NT/LM response computed from the password hash and server challenge.

### Extracting NTLM Hashes from PCAP

The NTLMSSP_CHALLENGE and NTLMSSP_AUTH messages together contain all the information needed to construct a Net-NTLMv2 hash suitable for offline cracking:

- **Username** from the NTLMSSP_AUTH message.
- **Domain** from the NTLMSSP_AUTH message.
- **Server Challenge** (8 bytes) from the NTLMSSP_CHALLENGE message.
- **NTProofStr** (first 16 bytes of the NT response) from the NTLMSSP_AUTH message.
- **Client Challenge** (remaining bytes of the NT response) from the NTLMSSP_AUTH message.

The format for hashcat (-m 5600) is: `username::domain:server_challenge:NTProofStr:client_challenge`.

Tools such as Responder and ntlmrelayx capture these hashes on the network. In PCAP analysis, the same hashes can be extracted post-incident to understand which credentials were exposed and potentially cracked.

### NTLM Relay Detection

NTLM relay attacks forward authentication from one service to another. In PCAP, indicators include:

- An NTLMSSP_CHALLENGE from a legitimate server being forwarded to a victim, visible as the same challenge nonce appearing in authentication to two different services.
- Authentication timing anomalies: the Type 3 response arrives faster than expected if it was relayed rather than computed locally.
- The same credential being used against a target that the original client did not intend to contact.
- MITRE ATT&CK: T1557.001 (LLMNR/NBT-NS Poisoning and SMB Relay).

## Kerberos Traffic Analysis

Kerberos authentication (TCP/UDP port 88) provides rich forensic information in PCAP captures.

### Kerberos Message Types

- **AS-REQ** (Authentication Service Request): Client requests a TGT from the KDC. Contains the client principal name and requested encryption types.
- **AS-REP** (Authentication Service Reply): KDC returns the TGT. If pre-authentication is disabled, the AS-REP contains encrypted data that can be cracked offline (AS-REP Roasting, hashcat -m 18200).
- **TGS-REQ** (Ticket Granting Service Request): Client requests a service ticket using its TGT. Contains the target service principal name (SPN).
- **TGS-REP** (Ticket Granting Service Reply): KDC returns the service ticket. The ticket is encrypted with the service account's key and can be cracked offline if the service runs under a user account (Kerberoasting, hashcat -m 13100).
- **AP-REQ** (Application Request): Client presents the service ticket to the target service.
- **KRB-ERROR**: Authentication failures with error codes that reveal the reason for failure.

### Kerberoasting in PCAP

Kerberoasting involves requesting TGS tickets for services running under user accounts (not computer accounts) and cracking them offline:

- Look for a single client sending TGS-REQ messages for many different SPNs in rapid succession.
- Normal usage requests tickets for one or two services per session. Requesting tickets for dozens of SPNs indicates Kerberoasting.
- The requested SPNs typically target service accounts (MSSQLSvc, HTTP, exchangeMDB) rather than computer accounts.
- MITRE ATT&CK: T1558.003 (Kerberoasting).

### AS-REP Roasting in PCAP

- AS-REQ messages for accounts with pre-authentication disabled receive AS-REP responses containing data encrypted with the user's key.
- Look for AS-REQ messages without the PA-ENC-TIMESTAMP pre-authentication data, followed by successful AS-REP responses.
- Multiple AS-REQ messages for different user accounts from a single source indicate enumeration of roastable accounts.
- MITRE ATT&CK: T1558.004 (AS-REP Roasting).

### Golden and Silver Ticket Detection

- **Golden Ticket**: A forged TGT allows requesting service tickets for any service. In PCAP, look for TGS-REQ messages using a TGT that was not preceded by a corresponding AS-REQ/AS-REP exchange.
- **Silver Ticket**: A forged service ticket is presented directly in AP-REQ without a preceding TGS-REQ. The AP-REQ message appears without any prior Kerberos traffic for that service.
- Tickets with anomalous lifetimes (e.g., 10-year validity) indicate forged tickets.

## Cleartext Credential Detection

Several protocols transmit credentials in cleartext, making them directly visible in PCAP:

### FTP (Port 21)

- `USER username` and `PASS password` commands are transmitted in plaintext.
- Credentials are immediately visible in the TCP stream without decoding.

### HTTP Basic Authentication

- The `Authorization: Basic` header contains base64-encoded `username:password`.
- Decode with standard base64 to recover credentials.
- Look for `Authorization` headers in HTTP requests.

### HTTP Form Authentication

- POST requests to login endpoints contain credentials in the request body.
- Parameters commonly named `username`, `user`, `email`, `password`, `passwd`, `pass`.
- Form data may be URL-encoded or JSON-formatted.

### LDAP (Port 389)

- LDAP Simple Bind requests transmit the distinguished name and password in cleartext.
- Look for LDAP Bind Request messages with authentication type "simple".
- LDAPS (port 636) encrypts the connection, protecting credentials from capture.

### Telnet (Port 23)

- All Telnet communication is plaintext, including login prompts and passwords.
- Credentials can be reconstructed from the TCP stream by following the character-by-character input.

### SMTP (Port 25/587)

- `AUTH LOGIN` and `AUTH PLAIN` mechanisms transmit base64-encoded credentials.
- SMTP without STARTTLS exposes all authentication in cleartext.

### SNMP (Port 161)

- SNMPv1 and v2c use community strings as authentication, transmitted in cleartext.
- Community strings function as passwords and often provide read-write access to device configurations.

## Password Spraying Detection

Password spraying attempts a single password against many accounts to avoid lockout thresholds. In PCAP:

- Look for authentication attempts against many different usernames from a single source IP within a short time window.
- The time between attempts may be deliberately paced to stay below lockout detection (e.g., one attempt per account every 30 minutes).
- Kerberos AS-REQ messages for many different client principal names from a single source.
- SMB NTLMSSP_AUTH messages with many different usernames from a single source.
- A high rate of KRB-ERROR with error code KDC_ERR_PREAUTH_FAILED (24) or STATUS_LOGON_FAILURE in SMB indicates failed authentication attempts.
- MITRE ATT&CK: T1110.003 (Password Spraying).

## Brute Force Detection

- Repeated authentication attempts for the same username from one or more sources.
- Extremely high frequency of failed authentications followed by a success.
- Distributed brute force uses multiple source IPs against the same account.
- MITRE ATT&CK: T1110.001 (Password Guessing).

## Adversary-in-the-Middle

AitM attacks intercept authentication traffic to capture or relay credentials:

- **ARP spoofing**: Visible as ARP replies mapping multiple IPs to the same MAC, or gratuitous ARP responses from unexpected sources.
- **LLMNR/NBT-NS poisoning**: Responses to LLMNR (UDP 5355) or NBT-NS (UDP 137) queries from hosts that are not the legitimate resolver, directing victims to attacker-controlled services that capture NTLM hashes.
- **DHCPv6 poisoning**: Rogue DHCPv6 responses that set attacker-controlled DNS servers.
- MITRE ATT&CK: T1557 (Adversary-in-the-Middle).

## Related Topics

For lateral movement using stolen credentials, see `04_lateral_movement_detection.md`. For Kerberos analysis in the context of Active Directory attacks, cross-reference with BloodHound analysis in the BloodHound knowledge base. For building incident timelines from credential usage, see `09_incident_response_pcap.md`.
