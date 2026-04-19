# Lateral Movement Detection in PCAP

## Overview

Lateral movement is the process by which attackers move from an initially compromised system to other systems within the network. Detecting lateral movement in packet captures is critical for understanding breach scope and identifying all compromised hosts. Lateral movement maps to MITRE ATT&CK Tactic TA0008 and includes techniques T1021 (Remote Services), T1570 (Lateral Tool Transfer), and T1550 (Use Alternate Authentication Material).

## SMB-Based Lateral Movement

SMB (Server Message Block) on TCP port 445 is the most common lateral movement vector in Windows environments. Analysing SMB traffic in PCAP reveals detailed information about attacker activity.

### PsExec and SCM-Based Execution

PsExec (and its Impacket equivalent `psexec.py`) creates a service on the remote host via the Service Control Manager (SCM):

1. The attacker authenticates to the target over SMB (NTLMSSP or Kerberos).
2. A connection is made to the `IPC$` share (inter-process communication).
3. The `svcctl` named pipe is opened to interact with the Service Control Manager.
4. A service binary is uploaded to the `ADMIN$` share (maps to `C:\Windows`).
5. A new service is created and started, executing the uploaded binary.
6. The service is stopped and deleted after execution.

In PCAP, look for:

- SMB Tree Connect requests to `IPC$` followed by `ADMIN$` or `C$` on the same session.
- Named pipe opens to `\pipe\svcctl` (Service Control Manager).
- File write operations to `ADMIN$` with executable content.
- Sequential pattern: authentication, IPC$ connect, file upload, svcctl pipe, within a short time window.
- Impacket's psexec.py uses a randomly named service and executable (e.g., `RemComSvc`, or 8 random characters).

### WMI-Based Execution

Windows Management Instrumentation (WMI) remote execution uses DCOM over TCP port 135 (RPC Endpoint Mapper) followed by a dynamically assigned high port:

- Initial connection to port 135 for endpoint resolution.
- DCOM/RPC connection on a dynamic port (typically 49152-65535) for WMI operations.
- `wmic /node:target process call create "command"` creates a remote process.
- Impacket's `wmiexec.py` uses WMI to execute commands and retrieves output via SMB.

In PCAP, look for:

- TCP connections to port 135 followed shortly by connections to high-numbered ports on the same destination.
- RPC bind requests to the WMI interface UUID `{76A64158-CB41-11D1-8B02-00600806D9B6}`.
- Correlate with SMB traffic to the same host if output retrieval uses file shares.

### SMB Share Access Patterns

- **IPC$ access**: Required for named pipe communication. Legitimate admin tools use IPC$, but IPC$ access from workstations to other workstations (not servers) is unusual.
- **ADMIN$ access**: Maps to the Windows directory. Access to ADMIN$ from non-administrative tools is suspicious.
- **C$ access**: Maps to the C: drive root. Used for file transfer during lateral movement.
- **Non-default shares**: Attackers may create temporary shares for file staging.

### Named Pipe Analysis

Named pipes in SMB traffic reveal the remote services being accessed:

- `\pipe\svcctl`: Service Control Manager (service creation/modification).
- `\pipe\atsvc`: Task Scheduler (scheduled task creation).
- `\pipe\samr`: Security Account Manager (user enumeration).
- `\pipe\lsarpc`: Local Security Authority (policy and trust enumeration).
- `\pipe\srvsvc`: Server Service (share enumeration).
- `\pipe\epmapper`: Endpoint Mapper (RPC service discovery).
- `\pipe\winreg`: Remote Registry (registry access).
- Cobalt Strike default pipes: `\pipe\msagent_*`, `\pipe\MSSE-*`, `\pipe\postex_*`.

## Pass-the-Hash and Pass-the-Ticket

### Pass-the-Hash (PtH)

Pass-the-Hash attacks use stolen NTLM hashes to authenticate without knowing the plaintext password. In PCAP, PtH is visible in NTLMSSP authentication exchanges:

- NTLMSSP_AUTH messages contain the NT response computed from the hash. The authentication itself is indistinguishable from legitimate NTLM authentication at the packet level.
- Behavioural indicators are more reliable: a single workstation authenticating to many hosts in rapid succession using the same account, or authentication from a host that the account does not normally use.
- NTLM authentication (rather than Kerberos) to domain-joined systems is itself notable, as modern Windows environments prefer Kerberos. NTLM fallback may indicate PtH or relay attacks.
- MITRE ATT&CK: T1550.002 (Pass the Hash).

### Pass-the-Ticket (PtT)

Pass-the-Ticket uses stolen Kerberos tickets (TGT or TGS) to authenticate:

- In PCAP, look for Kerberos AP-REQ messages that use tickets not preceded by a corresponding AS-REQ or TGS-REQ from the same source host.
- Golden Ticket attacks use forged TGTs. The TGT is presented directly in TGS-REQ without a prior AS-REQ/AS-REP exchange from that host.
- Silver Ticket attacks use forged service tickets. The ticket is presented in AP-REQ without a prior TGS-REQ for that service from that host.
- Ticket reuse from multiple source IPs is a definitive indicator of credential theft.
- MITRE ATT&CK: T1550.003 (Pass the Ticket).

## RDP Lateral Movement

Remote Desktop Protocol on TCP port 3389 is commonly used for legitimate administration but also for lateral movement:

- RDP connections from workstation to workstation (rather than workstation to server) are unusual and warrant investigation.
- Rapid successive RDP connections from one host to multiple destinations indicate systematic lateral movement.
- RDP is often preceded by credential theft. Correlate RDP connections with preceding authentication events.
- RDP session metadata (client hostname, username) can sometimes be extracted from the initial negotiation packets before encryption.
- NLA (Network Level Authentication) uses CredSSP, and the authentication exchange occurs before the RDP session is established. CredSSP uses NTLMSSP or Kerberos, which can be analysed in the PCAP.
- MITRE ATT&CK: T1021.001 (Remote Desktop Protocol).

## WinRM and PowerShell Remoting

Windows Remote Management uses HTTP on port 5985 (plaintext) or HTTPS on port 5986 (encrypted):

- WinRM traffic is SOAP/XML over HTTP. When unencrypted (port 5985), the full PowerShell commands and output can be extracted from the PCAP.
- Look for HTTP POST requests to `/wsman` URI paths.
- WinRM from workstation to workstation is unusual in most environments.
- PowerShell remoting (Enter-PSSession, Invoke-Command) uses WinRM as the transport.
- Correlate with authentication events: WinRM authentication uses NTLMSSP or Kerberos within HTTP Negotiate/Authorization headers.
- MITRE ATT&CK: T1021.006 (Windows Remote Management).

## SSH Lateral Movement

SSH on TCP port 22 in Linux/Unix environments:

- SSH traffic is encrypted, limiting payload analysis. Focus on connection patterns and timing.
- SSH connections from hosts that do not normally SSH to a given destination are suspicious.
- Key-based authentication without prior password authentication may indicate stolen SSH keys.
- SSH tunneling (port forwarding) through compromised hosts can be detected by analysing connection patterns: internal hosts connecting to other internal hosts through an intermediary.
- MITRE ATT&CK: T1021.004 (SSH).

## Detection Strategies

### Baseline and Anomaly Detection

- Establish normal internal communication patterns: which hosts talk to which hosts, on which ports.
- Alert on new host-to-host communication pairs on administrative ports (445, 3389, 5985, 22, 135).
- Alert on workstation-to-workstation connections on these ports.

### Temporal Analysis

- Lateral movement often occurs in rapid succession. An attacker who compromises one host will move to the next within minutes.
- Look for clusters of SMB/RDP/WinRM connections from a single source to multiple destinations within a short time window.
- Correlate the timing of lateral movement with C2 beaconing to identify the command-and-control relationship.

### Account Usage Patterns

- A single account authenticating to an unusual number of hosts is a strong indicator.
- Service accounts authenticating from unexpected source hosts indicate credential theft.
- Local administrator accounts (same username/hash across multiple hosts) used for SMB authentication across the network indicate PtH.

## Related Topics

For credential theft and authentication analysis, see `05_credential_attacks_in_traffic.md`. For C2 communications that precede and direct lateral movement, see `03_c2_detection.md`. For using PCAP to scope a breach, see `09_incident_response_pcap.md`.
