# Lab Limitations and Unrealistic Elements

---

## 1. Network Architecture and Segmentation

### 1.1 SSH Permitted Directly from IT Zone to OT Zone

**What is Unrealistic:**
- pfSense firewall rule explicitly permits SSH (TCP/22) directly from a Windows workstation in the IT zone (192.168.10.20) to the HMI in the OT zone (192.168.20.10)
- This creates a direct IT-to-OT conduit without intermediate security controls

**Why It Was Done This Way:**
- Educational constraint: Demonstrates lateral movement and firewall traversal techniques
- Lab simplification: Eliminates need for complex jump host infrastructure
- Time constraint: Setting up proper secure remote access architecture would require additional VMs and services
- Demonstration purpose: Shows how a common misconfiguration can be exploited by attackers

**How It Would Be Different in Production:**
- The Purdue Model strictly prohibits direct connections between Level 4 (IT) and Level 2 (Control Systems)
- All remote access would traverse through Level 3.5 (Industrial Demilitarized Zone / IDMZ) with:
  - **Jump hosts/bastions:** Hardened secure remote access servers with multi-factor authentication
  - **Session recording:** All privileged access recorded for audit and forensics
  - **Protocol breaks:** Application-level proxies (VNC gateway, RDP gateway) that terminate and re-initiate connections
  - **Data diodes:** Unidirectional network devices for IT-to-OT data transfer (where only monitoring data flows, not control commands)
  - **Zero Trust architecture:** Continuous verification of user identity and device posture before granting access

**References:**
- IEC 62443-3-2: Security for industrial automation and control systems - Security risk assessment and system design
- NIST SP 800-82 Rev. 3: Guide to Operational Technology (OT) Security

---

### 1.2 Simplified Network Topology (Only 2 Zones)

**What is Unrealistic:**
- Lab implements only IT zone (Level 4-5) and OT zone (Level 2)
- Missing intermediate zones: IDMZ (Level 3.5), SCADA/supervisory control (Level 3), field devices (Level 1), physical process (Level 0)
- All OT assets (HMI and PLC) in single flat network (192.168.20.0/24)

**Why It Was Done This Way:**
- Resource constraint: Limited to 5 VMs in VMware Workstation Pro environment
- Complexity management: Simplified topology sufficient to demonstrate key concepts
- Time constraint: Full 6-level Purdue Model implementation would require additional configuration
- Demonstration focus: Project emphasizes attack-defense cycle, not comprehensive architecture

**How It Would Be Different in Production:**
- **Level 0 (Physical Process):** Sensors, actuators, field instruments
- **Level 1 (Field Devices):** PLCs, RTUs, IEDs (separated by functional zones - pump station, substation, etc.)
- **Level 2 (Control Systems):** HMI, engineering workstations, supervisory control
- **Level 3 (Site Operations):** SCADA servers, historians, MES (Manufacturing Execution Systems)
- **Level 3.5 (IDMZ):** DMZ with unidirectional gateways, data historians, remote access jump hosts
- **Level 4 (Enterprise):** ERP, business logistics, corporate IT systems
- **Level 5 (Enterprise Network):** Corporate WAN, internet connections

**Additional Production Segmentation:**
- OT zone would be further subdivided by function (process cells, safety systems)
- Separate VLANs for engineering workstations, HMIs, and PLCs
- Dedicated out-of-band management network for administrative access
- Physically separate safety instrumented systems (SIS) networks

---

### 1.3 No Data Diodes or Unidirectional Gateways

**What is Unrealistic:**
- All firewall rules are bidirectional (pfSense allows stateful return traffic)
- No unidirectional network devices preventing OT-to-IT command injection

**Why It Was Done This Way:**
- Commercial data diodes are expensive specialized hardware not available in lab
- Software-based unidirectional gateway simulation would add complexity
- Bidirectional firewall rules sufficient for demonstrating attack concepts

**How It Would Be Different in Production:**
- High-security critical infrastructure (power generation, water treatment, chemical plants) deploy **data diodes** or **unidirectional security gateways** at the IT-OT boundary
- These devices enforce **physically unidirectional data flow** using fiber optic transmit-only/receive-only connections
- Typically used for:
  - OT-to-IT monitoring data export (process values, alarms, historian data)
  - Preventing any IT-to-OT command injection at the network layer
- Allows IT systems to monitor OT, but makes it physically impossible for IT-based malware to send commands to OT

**References:**
- NERC CIP-005-7: Electronic Security Perimeter(s) - Includes requirements for unidirectional gateway deployment in bulk electric systems
- Waterfall Security Solutions: Unidirectional Security Gateway Technology Guide

---

## 2. Authentication and Access Control

### 2.1 Password-Based SSH Authentication with Weak Credentials

**What is Unrealistic:**
- SSH authentication relies solely on username/password
- No public key cryptography or certificate-based authentication
- Passwords are documented in plain text in lab notes (VM Details.md)
- No password complexity requirements enforced on OT systems

**Why It Was Done This Way:**
- Simplicity: Password-based auth easier to set up and demonstrate
- Lab convenience: Allows quick VM access without key management
- Attack demonstration: Weak authentication shows vulnerability to credential theft
- Time constraint: SSH key infrastructure would require additional configuration steps

**How It Would Be Different in Production:**
- **SSH Key-Based Authentication:** Private/public key pairs with passphrase protection
- **Certificate-Based Authentication:** SSH certificates signed by trusted Certificate Authority
- **Multi-Factor Authentication (MFA):** Hardware tokens (YubiKey), one-time passwords (TOTP), or biometric factors
- **Privileged Access Management (PAM):** Solutions like CyberArk, BeyondTrust for credential vaulting
- **Bastion/Jump Host:** All OT SSH access proxied through hardened jump host with MFA

**ICS-Specific Considerations:**
- **NERC CIP-005-6:** Requires multi-factor authentication for interactive remote access to critical cyber assets
- **TSA Pipeline Security Directive:** Mandates multi-factor authentication for OT network access

---

### 2.2 No Role-Based Access Control (RBAC) or Least Privilege

**What is Unrealistic:**
- SSH user (`operator`) has broad system access to HMI
- No granular permissions restricting specific Modbus operations
- PLC Modbus server accepts commands from any source IP without authentication

**Why It Was Done This Way:**
- Modbus protocol limitation: Modbus/TCP has no native authentication mechanism
- Lab simplification: RBAC implementation would require additional PAM configuration
- Attack demonstration: Shows vulnerability of unrestricted OT protocol access

**How It Would Be Different in Production:**
- **Application-Level RBAC:** HMI software (like Rockwell FactoryTalk, Siemens WinCC) implements user roles with specific permissions
- **Modbus/TCP Security Enhancements:**
  - **IP Whitelisting:** PLC firewall rules restricting Modbus connections to specific HMI IPs
  - **VPN Tunneling:** Modbus traffic encapsulated in IPsec or TLS tunnels
  - **Modbus/TLS (IEC 62351):** Encrypted and authenticated Modbus communication
- **PLC Security Features:**
  - Password protection for online/offline mode changes
  - Digitally signed ladder logic preventing unauthorized logic modifications
  - Run-time write protection for safety-critical memory regions

---

### 2.3 No Network Access Control (NAC) or 802.1X

**What is Unrealistic:**
- Any device connected to GNS3 virtual switches can communicate if firewall rules permit
- No port-level authentication or device posture verification
- No MAC address filtering or port security

**Why It Was Done This Way:**
- GNS3 limitation: Virtual switches don't support 802.1X authentication
- Lab simplification: NAC infrastructure would require RADIUS server and additional configuration
- Demonstration focus: Physical layer security not primary objective

**How It Would Be Different in Production:**
- **802.1X Port-Based Authentication:** Network switches require device authentication before granting network access
- **RADIUS/TACACS+ Servers:** Centralized authentication for network devices and administrative access
- **Device Profiling:** Network Access Control systems identify and categorize devices (HMI, PLC, workstation)
- **Posture Assessment:** Verify device security configuration (OS patches, antivirus status) before network admission
- **Port Security:** MAC address binding to specific switch ports to prevent device impersonation

---

### 2.4 No Endpoint Detection and Response (EDR) or Antivirus

**What is Unrealistic:**
- No antivirus or endpoint detection solutions on Windows or Linux systems
- No application whitelisting preventing execution of unauthorized scripts
- Malicious Python scripts can be written and executed without detection
- No behavioral monitoring of process execution or file creation

**Why It Was Done This Way:**
- Lab simplification: Focus on network-based detection rather than host-based
- Attack demonstration: Allow malicious scripts to execute for educational purposes
- Cost: Commercial EDR solutions (CrowdStrike, SentinelOne, Microsoft Defender for Endpoint) expensive
- Resource constraint: EDR agents would consume additional VM resources

**How It Would Be Different in Production:**
- **Endpoint Protection:**
  - Antivirus/anti-malware on all Windows and Linux endpoints
  - Application whitelisting (e.g., Windows AppLocker, Carbon Black) preventing execution of unauthorized binaries
  - Behavioral detection identifying suspicious script execution or network activity
- **EDR Solutions:**
  - CrowdStrike Falcon, Microsoft Defender for Endpoint, SentinelOne
  - Real-time monitoring of process creation, file modifications, network connections
  - Detection of malicious PowerShell/Python script execution
  - Automated isolation of compromised endpoints
- **ICS-Specific Considerations:**
  - **NERC CIP-007:** Requires malware prevention on critical cyber assets
  - **ICS Endpoint Protection:** Specialized solutions (e.g., Trend Micro TXOne, Claroty xDome) designed for OT environments with minimal performance impact
  - Application whitelisting particularly important in OT (only approved HMI/engineering software should execute)

---

## 3. Programmable Logic Controller (PLC) Simulation

### 3.1 Software-Based PLC Simulation (pymodbus) vs. Real Industrial Hardware

**What is Unrealistic:**
- PLC is simulated using Python pymodbus library on a generic Ubuntu Server VM
- No actual industrial controller hardware (Siemens S7-1500, Allen-Bradley ControlLogix, Schneider Modicon, etc.)
- No ladder logic programming or real-time control algorithms
- No physical I/O modules or field device connections

**Why It Was Done This Way:**
- Cost: Real PLCs range from $500-$5000+; not feasible for student capstone project
- Availability: Industrial hardware requires specialized vendors and long lead times
- Software licensing: PLC programming software (TIA Portal, RSLogix 5000) expensive and restrictive
- Lab simplicity: pymodbus provides sufficient Modbus protocol simulation for educational purposes
- Safety: No risk of accidentally damaging expensive industrial equipment

**How It Would Be Different in Production:**
- **Real PLCs:** Siemens S7-1200/1500, Allen-Bradley CompactLogix/ControlLogix, Schneider Modicon M580
- **Ladder Logic Programming:** Control logic implemented in IEC 61131-3 languages (Ladder Diagram, Structured Text, Function Block Diagram)
- **Real-Time Operating Systems:** Deterministic RTOS with microsecond-level scan cycles
- **Physical I/O:** Analog inputs (4-20mA sensor signals), digital outputs (relay contacts controlling valves/motors)
- **Field Device Integration:** PROFINET, EtherNet/IP, Modbus RTU communication to sensors and actuators
- **Redundancy:** Hot-standby redundant PLCs for high-availability processes

**ICS-Specific Considerations:**
- Real PLCs have vendor-specific security features (password protection, access levels, key switches)
- Modbus is often encapsulated in vendor protocols (e.g., EtherNet/IP for Allen-Bradley)
- Safety PLCs (SIL-rated) have additional write-protection and certified logic

---

### 3.2 Simplified Modbus Data Model (Flat 100-Element Arrays)

**What is Unrealistic:**
- Modbus datastore initialized with simple 100-element arrays of zeros
- Coils and registers have no semantic meaning (no mapping to actual process control points)
- No realistic process simulation (pump control, valve positioning, pressure monitoring)
- Writing to arbitrary coil addresses (e.g., coil 50 - emergency main breaker) has no operational impact

**Why It Was Done This Way:**
- Demonstration simplicity: Focus on protocol exploitation, not process engineering
- Time constraint: Simulating realistic industrial process would require significant engineering
- Educational scope: Project demonstrates cybersecurity concepts, not control system design

**How It Would Be Different in Production:**
- **Process-Mapped Addressing:** Each coil/register corresponds to physical control points:
  - Coil 0: Pump 1 Start/Stop
  - Coil 1: Valve 2 Open/Close
  - Register 100: Flow rate setpoint (scaled engineering units)
  - Register 200: Pressure sensor reading (PSI)
- **Alarm Conditions:** Writing out-of-range values triggers safety alarms
- **Interlocks:** Safety logic prevents unsafe state combinations (can't open drain valve while tank is filling)
- **Process Simulation:** HMI displays would show real-time visualization of simulated process (tank levels, flow rates)

---

### 3.3 No PLC Security Features Enabled

**What is Unrealistic:**
- PLC has no access restrictions (any Modbus client can write to any address)
- No password protection for online mode or logic downloads
- No cryptographic validation of commands
- No write protection for safety-critical memory regions

**Why It Was Done This Way:**
- pymodbus limitation: Open-source library doesn't implement vendor-specific security features
- Demonstration purpose: Shows vulnerability of unsecured industrial protocols
- Lab simplification: Security features would require custom implementation

**How It Would Be Different in Production:**
- **PLC Password Protection:** Require password for switching to online/run mode, downloading logic
- **Memory Write Protection:** Safety-critical regions protected from runtime modification
- **Digitally Signed Firmware:** PLC verifies cryptographic signatures before executing firmware updates
- **Key Switches:** Physical switches on PLC front panel restricting mode changes
- **Vendor-Specific Security:**
  - Siemens: Access levels (read-only, operator, maintenance, administrator)
  - Allen-Bradley: User accounts with role-based permissions in ControlLogix
  - Schneider: Cyber Security Level settings restricting HMI connections

---

## 4. Detection and Monitoring Capabilities

### 4.1 No Industrial Intrusion Detection System (IDS)

**What is Unrealistic:**
- Detection relies solely on manual PCAP analysis in Wireshark
- No real-time alerting or automated anomaly detection
- No ICS-specific protocol inspection beyond Wireshark dissectors

**Why It Was Done This Way:**
- Cost: Commercial ICS IDS solutions (Nozomi Networks, Claroty, Dragos) are expensive enterprise products
- Lab simplification: Manual PCAP analysis sufficient for demonstrating attack indicators
- Educational focus: Teaches forensic analysis skills rather than relying on automated tools

**How It Would Be Different in Production:**
- **Industrial IDS/IPS:** Passive monitoring solutions purpose-built for OT protocols:
  - **Nozomi Networks Guardian:** Deep packet inspection for Modbus, DNP3, IEC 104, OPC UA
  - **Claroty CTD (Continuous Threat Detection):** Asset discovery and behavioral anomaly detection
  - **Dragos Platform:** Threat detection with ICS-specific threat intelligence
- **OT-Aware Detection Rules:**
  - Alert on burst of Modbus write commands
  - Detect unusual coil/register addresses being accessed
  - Baseline normal traffic patterns and alert on deviations
  - Correlate IT zone events with OT protocol anomalies
- **Asset Inventory:** Automatic discovery and profiling of OT devices
- **Real-Time Alerting:** Integration with SIEM platforms for incident response workflow

---

### 4.2 Limited Logging and Log Correlation

**What is Unrealistic:**
- System logs (auth.log, pfSense firewall logs) reviewed manually without automation
- No centralized SIEM (Security Information and Event Management) platform
- No correlation of events across multiple systems
- Bash history preserved by default (attacker would typically clear history)

**Why It Was Done This Way:**
- Cost/Complexity: SIEM platforms (Splunk, QRadar, Azure Sentinel) expensive and complex to deploy
- Lab resource constraint: SIEM would require additional VM and storage
- Educational purpose: Manual log analysis teaches fundamentals before introducing automation
- Attacker simulation: Assumed attacker didn't perform advanced anti-forensics

**How It Would Be Different in Production:**
- **Centralized SIEM:** Aggregate logs from IT and OT systems:
  - Windows Event Logs → SIEM
  - Firewall logs → SIEM
  - ICS IDS alerts → SIEM
  - PLC audit logs → SIEM (if supported by vendor)
- **Automated Correlation Rules:**
  - Alert on SSH from IT zone → OT zone followed by burst of Modbus writes
  - Detect lateral movement patterns (multiple failed logins, then success, then pivoting)
- **Threat Intelligence Integration:** Correlate with known ICS threat actor TTPs (MITRE ATT&CK for ICS)
- **Anti-Forensics Countermeasures:**
  - Write-once log storage preventing attacker log deletion
  - Syslog forwarding to external collector (logs preserved even if host compromised)

---

### 4.3 No Baseline Traffic Profiling or Anomaly Detection

**What is Unrealistic:**
- Attack detection relies on recognizing obviously malicious patterns (rapid write bursts)
- No established baseline of "normal" OT traffic patterns
- No statistical anomaly detection algorithms

**Why It Was Done This Way:**
- Lab simplification: Requires extended operational period to establish baseline
- Manual demonstration: Human analyst can visually identify attack traffic
- Time constraint: Machine learning models would require training data collection period

**How It Would Be Different in Production:**
- **Baseline Establishment Phase:** Monitor OT network for 2-4 weeks to establish normal patterns:
  - Typical Modbus polling intervals (e.g., HMI polls PLC every 2 seconds)
  - Expected function code distribution (90% reads, 10% writes)
  - Authorized communication pairs (which HMIs talk to which PLCs)
  - Time-of-day patterns (different traffic during operational shifts vs. maintenance windows)
- **Anomaly Detection:**
  - Deviation from established polling intervals
  - Unexpected function codes (e.g., Function Code 23 "Read/Write Multiple Registers" rarely used)
  - New communication pairs not seen during baseline
  - Statistical outliers (sudden burst of traffic 10x normal volume)
- **Machine Learning:** Some ICS IDS platforms use ML models to detect subtle deviations

---

## 5. Incident Response Capabilities

### 5.1 Snapshot-Based Recovery vs. Real Backup/Restore Procedures

**What is Unrealistic:**
- VM recovery achieved via VMware snapshots (instant rollback)
- No formal backup validation or disaster recovery testing
- No consideration of physical equipment replacement

**Why It Was Done This Way:**
- VMware feature: Snapshots provide convenient lab reset mechanism
- Time efficiency: Instant rollback enables repeated attack-response practice
- Lab environment: No physical equipment that could be damaged

**How It Would Be Different in Production:**
- **PLC Backup Procedures:**
  - Regular offline backups of PLC ladder logic programs
  - Configuration backups stored in secure offline location
  - Version control for PLC program changes
- **HMI/SCADA Backup:**
  - Database backups (historian data, tag configurations)
  - Application configuration backups
  - Validated restore procedures with documented recovery time objectives (RTO)
- **Disaster Recovery Testing:**
  - Annual or semi-annual DR exercises
  - Validated restoration from backup within RTO
- **Hardware Spares:**
  - Maintain spare PLCs, network switches for rapid replacement
  - Known-good firmware versions maintained offline

**ICS-Specific Considerations:**
- **NERC CIP-009:** Recovery Plans for Critical Cyber Assets - Requires backup procedures and restoration testing
- Recovery may require physical equipment replacement (damaged PLC or network equipment)
- Configuration changes during response must be documented and reconciled with change management process

---

### 5.2 No Coordination with Physical Operations or Safety Teams

**What is Unrealistic:**
- Incident response actions (firewall rule changes, system isolation) taken unilaterally
- No consideration of operational impact on physical processes
- No safety analysis of response actions

**Why It Was Done This Way:**
- Lab environment: No actual physical process to impact
- Simplified demonstration: Single student can perform all IR actions
- Educational scope: Focus on cyber IR, not cross-functional coordination

**How It Would Be Different in Production:**
- **Operations Coordination:** All IR actions coordinated with control room operators
  - "We need to isolate the HMI - can the process safely continue in local/manual control?"
  - "What is the operational impact of blocking IT-to-OT access?"
- **Safety Team Involvement:** Evaluate safety implications of IR actions
  - Will blocking Modbus traffic disable safety instrumented systems?
  - Can we isolate compromised assets without causing emergency shutdowns?
- **Change Management:** Even emergency IR actions documented in change management system
- **Communication Plan:** Notify stakeholders (plant manager, corporate security, regulatory agencies)

**Real-World Examples:**
- **Colonial Pipeline (2021):** Decision to shut down OT network was coordinated operation decision
- **Triton/TRISIS (2017):** Safety system compromise required coordination with process safety experts

---

### 5.3 No Legal, Regulatory, or Public Relations Considerations

**What is Unrealistic:**
- No involvement of legal counsel, insurance, or public relations teams
- No consideration of mandatory breach notification requirements
- No regulatory agency coordination (CISA, TSA, EPA, etc.)

**Why It Was Done This Way:**
- Lab environment: No actual critical infrastructure at risk
- Educational scope: Focus on technical IR, not organizational response
- Simplified scenario: Assume incident contained before public impact

**How It Would Be Different in Production:**
- **Legal Involvement:**
  - Attorney-client privilege considerations for IR documentation
  - Potential law enforcement involvement (FBI, Secret Service)
  - Contractual obligations to customers/partners
- **Regulatory Reporting:**
  - **CISA ICS-CERT:** Voluntary reporting of ICS incidents to federal agency
  - **TSA:** Mandatory reporting for pipeline and rail operators (Security Directives)
  - **NERC:** Electric utilities must report cyber incidents under NERC CIP-008
  - **EPA:** Water/wastewater systems may have reporting obligations
  - **State/Local:** Some states have critical infrastructure incident reporting laws
- **Public Relations:**
  - Media inquiries if incident becomes public
  - Customer communication (if service disrupted)
  - Investor relations (if publicly traded company)
- **Insurance:**
  - Cyber insurance policy notification requirements
  - Coordination with insurance carrier for forensic investigation

---

## 6. Attack Simplifications and Unrealistic Elements

### 6.1 Single-Path Linear Attack (No Persistence or Alternate C2)

**What is Unrealistic:**
- Attack follows single linear path: Kali → Windows → HMI → PLC
- No persistence mechanisms (backdoors, scheduled tasks, additional user accounts)
- No command-and-control (C2) infrastructure or data exfiltration
- No anti-forensics (log deletion, timestamp manipulation)
- Attacker abandons access after single Modbus attack

**Why It Was Done This Way:**
- Educational simplicity: Linear attack path easier to understand and demonstrate
- Time constraint: Multi-stage persistent attack would complicate demonstration
- Lab scope: Focus on IT-to-OT pivot and protocol exploitation
- Evidence preservation: Attacker leaves clear forensic trail for IR demonstration

**How Real ICS Attacks Differ:**
- **Extended Dwell Time:** APT groups maintain access for months before impact phase (TRITON: 2014-2017)
- **Persistence Mechanisms:**
  - Windows: Scheduled tasks, registry run keys, WMI event subscriptions
  - Linux: cron jobs, systemd services, SSH key implantation
  - PLC: Some sophisticated attacks modify PLC ladder logic for persistence (Stuxnet)
- **Command and Control:**
  - Encrypted C2 channels (HTTPS, DNS tunneling)
  - Use of legitimate cloud services (Google Drive, Dropbox) for C2
- **Lateral Movement:**
  - Compromise multiple IT and OT systems for redundancy
  - Establish alternate access paths in case primary route blocked
- **Data Exfiltration:**
  - Steal PLC programs, HMI configurations (operational intelligence)
  - Exfiltrate process data for reconnaissance or competitive intelligence
- **Anti-Forensics:**
  - Clear bash history, Windows event logs
  - Timestomp (modify file timestamps)
  - Use of memory-only malware leaving minimal disk artifacts

**Real-World Example: CRASHOVERRIDE/Industroyer (Ukraine 2016)**
- Multi-month dwell time
- Custom malware components for IEC 104, IEC 61850, OPC DA protocols
- Wiper component to destroy evidence and delay recovery

---

### 6.2 No Social Engineering or Spear Phishing Simulation

**What is Unrealistic:**
- Initial IT compromise achieved via direct RDP connection (assumes attacker already has credentials or network access)
- No simulation of phishing email or malicious attachment
- No user interaction or social engineering component

**Why It Was Done This Way:**
- Technical focus: Project emphasizes network security and protocol exploitation
- Lab limitation: Simulating email infrastructure and user behavior would add complexity
- Time constraint: Phishing campaign simulation would require additional setup
- Demonstration clarity: Starting from "already compromised" workstation simplifies narrative

**How Real Attacks Begin:**
- **Spear Phishing:** Targeted emails with malicious attachments or links
  - **CRASHOVERRIDE:** Likely initial access via spear phishing
  - **TRITON:** Initial compromise vector unknown but likely phishing or external remote access
- **Watering Hole Attacks:** Compromise of websites frequently visited by ICS engineers
- **Supply Chain Compromise:** Trojanized software updates or vendor remote access
- **Removable Media:** USB drives with malware (Stuxnet propagation method)
- **Stolen VPN Credentials:** Purchase credentials from dark web or use of stolen VPN tokens

**ICS-Specific Initial Access Vectors:**
- Compromise of vendor remote support connections
- Exploitation of internet-facing HMI or ICS management software (common misconfiguration)
- Targeting of ICS engineering contractors with access to multiple facilities

---

### 6.3 No Exploit Development (Assumes Vulnerabilities or Weak Credentials)

**What is Unrealistic:**
- Attack relies on weak credentials and firewall misconfiguration
- No CVE exploitation or 0-day vulnerability usage
- No buffer overflow, SQL injection, or other technical exploitation

**Why It Was Done This Way:**
- Realism: Most real-world OT compromises exploit weak security practices, not 0-days
- Lab simplification: Exploit development beyond scope of capstone project
- Ethical constraint: Demonstrating vulnerability exploitation of specific products raises concerns
- Educational focus: Shows configuration and policy weaknesses, not software vulnerabilities

**How Real ICS Attacks Use Exploits:**
- **SCADA Software Vulnerabilities:**
  - Siemens SIMATIC WinCC, GE CIMPLICITY, Wonderware InTouch have all had published CVEs
  - Attackers may exploit unpatched HMI/SCADA vulnerabilities for initial access or privilege escalation
- **PLC Vulnerabilities:**
  - Siemens S7 protocol vulnerabilities (CVE-2019-13945: authentication bypass)
  - Allen-Bradley EtherNet/IP vulnerabilities (various CVEs)
  - Modbus lacks authentication by design (protocol-level vulnerability)
- **Custom Exploit Development:**
  - **Stuxnet:** Exploited multiple Windows 0-days (CVE-2010-2568, CVE-2010-2729, etc.)
  - **TRITON:** Custom exploit framework targeting Triconex safety controllers

**However, Most ICS Compromises Don't Require Exploits:**
- Weak/default passwords
- Unpatched systems (old CVEs, not 0-days)
- Firewall misconfiguration
- Lack of network segmentation

---

### 6.4 No Modbus Over Serial (Modbus RTU) - Only Modbus/TCP

**What is Unrealistic:**
- Lab implements only Modbus/TCP (Ethernet-based)
- No simulation of Modbus RTU (serial communication over RS-232/RS-485)
- Real industrial environments often use hybrid TCP and serial Modbus

**Why It Was Done This Way:**
- Virtual environment limitation: Difficult to simulate serial communication in GNS3/VMware
- Protocol simplicity: Modbus/TCP easier to implement and capture in Wireshark
- Network focus: Project emphasizes network-based attacks

**How It Would Be Different in Production:**
- **Modbus RTU:** Serial communication between field devices:
  - PLC to remote I/O modules
  - PLC to variable frequency drives (VFDs)
  - Typically RS-485 multi-drop networks
- **Protocol Gateways:** Modbus RTU to Modbus/TCP conversion
  - HMI uses Modbus/TCP to communicate with gateway
  - Gateway converts to Modbus RTU for field devices
- **Security Implications:**
  - Serial Modbus more difficult to intercept (requires physical access to wiring)
  - But also lacks any encryption or authentication
  - Modbus/TCP attacks can propagate through gateways to RTU devices

---

## 7. Operational Realism and Safety Considerations

### 7.1 No Safety Instrumented Systems (SIS) or IEC 61511 Compliance

**What is Unrealistic:**
- No dedicated safety PLC or Safety Instrumented System (SIS)
- Control PLC and safety functions not physically separated
- No Safety Integrity Level (SIL) rated components

**Why It Was Done This Way:**
- Lab simplification: Safety systems would require additional PLC and network infrastructure
- Cost: Safety PLCs (e.g., Siemens S7-1500F, Triconex) more expensive than standard PLCs
- Educational scope: Focus on control system security, not process safety engineering

**How It Would Be Different in Production:**
- **Dedicated Safety PLC:** Physically separate from control system
  - Triconex (Schneider Electric)
  - Siemens S7-1500F Safety controllers
  - Allen-Bradley GuardLogix
- **Separate Safety Network:** Independent communication path not shared with control system
- **SIL Certification:** Safety functions certified to Safety Integrity Levels (SIL 1-4)
- **IEC 61511:** Functional safety standard for process industry
- **Safety Lifecycle:** Formal hazard analysis (HAZOP), safety requirements specification, independent verification

**Real-World Security Impact:**
- **TRITON/TRISIS (2017):** First publicly disclosed malware targeting safety systems
  - Attacked Triconex safety controllers at Saudi petrochemical plant
  - Attempted to prevent safety shutdown during operational attack
  - Demonstrated attackers are targeting safety systems specifically

---

### 7.2 No Physical Process Simulation or Consequences

**What is Unrealistic:**
- Manipulating PLC coils has no visible operational impact
- No tank level simulation, pump operation visualization, or alarm generation
- Incident response doesn't consider physical damage or safety hazards

**Why It Was Done This Way:**
- Lab limitation: No physical equipment connected to PLC
- Software limitation: pymodbus doesn't include process simulation
- Educational scope: Focus on cyber attack, not process control engineering

**How It Would Be Different in Production:**
- **Process Consequences:** Unauthorized coil manipulation would have real effects:
  - Starting pump with closed discharge valve: pump damage (cavitation)
  - Opening valve while tank overfilled: environmental spill
  - Disabling cooling system: equipment overheating, potential fire
  - Rapid cycling of motor starter: electrical damage
- **Alarms and Notifications:** HMI displays would show:
  - High-high pressure alarms
  - Low-low level alarms triggering safety shutdowns
  - Equipment fault conditions
- **Safety Systems:** Would activate in response to unsafe conditions
  - Emergency shutdown systems (ESD)
  - Pressure relief valves opening
  - Fire suppression systems

**Real-World Examples of Physical Impact:**
- **Stuxnet (2010):** Caused physical destruction of Iranian uranium enrichment centrifuges
- **Ukrainian Power Grid (2015, 2016):** Disabled electrical substations causing blackouts
- **Oldsmar Water Treatment (2021):** Attempted to increase sodium hydroxide to dangerous levels (stopped by operator intervention)

---

## 8. Environmental and Deployment Differences

### 8.1 Virtualized Environment vs. Physical Hardware

**What is Unrealistic:**
- All systems are VMs in VMware Workstation Pro on a single physical host
- No physical PLCs, network switches, firewalls, or industrial equipment
- Network is simulated in GNS3, not actual industrial Ethernet switches
- Can snapshot and restore entire environment instantly

**Why It Was Done This Way:**
- Cost: Physical industrial equipment prohibitively expensive for student project
- Portability: Virtualized lab can be backed up and transported
- Safety: No risk of equipment damage or personal injury
- Rapid iteration: Can reset environment and re-run attacks quickly

**How It Would Be Different in Production:**
- **Physical PLCs:** Rack-mounted industrial controllers in control cabinets
- **Industrial Network Infrastructure:**
  - Managed industrial Ethernet switches (e.g., Cisco IE-4000, Hirschmann RS40)
  - Redundant ring topologies (Profinet IRT, EtherNet/IP DLR)
  - Fiber optic links for long-distance or high-EMI environments
- **Physical Security:** Equipment in locked control rooms or electrical cabinets
- **Environmental Considerations:** Temperature, humidity, vibration, electrical noise
- **Cabling:** Industrial-grade cabling with proper shielding and grounding

---

### 8.2 No Air Gap or Removable Media Controls

**What is Unrealistic:**
- IT and OT zones connected via firewall (logical segmentation only)
- No physical air gap between IT and OT
- No removable media usage (USB drives) in scenario
- No removable media scanning or whitelisting

**Why It Was Done This Way:**
- Demonstration purpose: Network-based attack easier to show than USB-based attack
- Logical segmentation: Firewall sufficient to demonstrate Purdue Model concepts
- Virtual environment: No physical media in virtualized systems

**How It Would Be Different in Production:**
- **Air Gap Deployment:** Highest security environments use physical air gaps:
  - No network connection between IT and OT
  - Data transfer only via removable media (USB drives, optical discs)
  - Challenges: Stuxnet demonstrated USB-based air gap jumping
- **Removable Media Controls:**
  - USB port whitelisting (only authorized devices)
  - Endpoint security scanning all USB media
  - Dedicated USB sanitization stations
  - Procedural controls (change management for USB usage)
- **Trade-offs:**
  - Air gaps increase security but reduce operational efficiency
  - Remote support and monitoring difficult without network connectivity
  - Most modern ICS not truly air-gapped (cellular modems, vendor remote access)

---

### 8.3 No Patch Management or Vulnerability Management Process

**What is Unrealistic:**
- All systems running with default configurations
- No patch management or security update process
- No vulnerability scanning or security hardening

**Why It Was Done This Way:**
- Lab baseline: Systems installed with default settings for simplicity
- Vulnerability demonstration: Some weaknesses intentional for educational purposes
- Time constraint: Security hardening would obscure attack demonstration

**How It Would Be Different in Production:**
- **Patch Management Challenges in ICS:**
  - **Operational constraints:** Cannot patch during production (24/7 operations common)
  - **Testing requirements:** All patches must be tested in non-production environment
  - **Vendor certification:** Some HMI/SCADA software unsupported if OS patched
  - **Long lifecycles:** ICS equipment operational for 10-25 years, may run unsupported OS
- **ICS Patch Management Best Practices:**
  - **Risk-based prioritization:** Critical vulnerabilities patched first
  - **Compensating controls:** If patching not feasible, use network segmentation, firewalls
  - **Change management:** All patches follow formal change control process
  - **Maintenance windows:** Coordinate with operations for planned downtime
- **Vulnerability Management:**
  - Regular vulnerability scanning (carefully - some scanners can crash PLCs)
  - Asset inventory and software bill of materials
  - Tracking of known vulnerabilities and compensating controls

**NERC CIP Requirements:**
- **NERC CIP-007-6:** Systems Security Management - Requires patch management and vulnerability assessment programs for electric utility critical cyber assets

---

## 9. Documentation and Process Maturity

### 9.1 No Formal Change Management or Configuration Management

**What is Unrealistic:**
- Firewall rules created/modified without formal approval process
- No change management tickets or audit trail
- System configurations not documented or version-controlled
- PLC programs not under version control

**Why It Was Done This Way:**
- Lab agility: Need to make rapid changes for demonstration
- Single operator: No organizational approval process needed
- Educational focus: Technical demonstration, not process maturity

**How It Would Be Different in Production:**
- **Change Management Process:**
  - All firewall rule changes require change ticket with approvals
  - Risk assessment before any OT system changes
  - Pre-approved emergency change procedures for incident response
  - Post-change validation and documentation
- **Configuration Management:**
  - PLC ladder logic programs in version control (Git, proprietary systems)
  - Firewall rule sets backed up and version-controlled
  - HMI configurations documented and backed up
  - Baseline configurations for all OT assets
- **Configuration Management Database (CMDB):**
  - Inventory of all OT assets with firmware versions, network addresses, dependencies
  - Impact analysis: What other systems affected if asset X is isolated?

**NERC CIP Requirements:**
- **NERC CIP-010:** Configuration Change Management and Vulnerability Assessments - Requires baseline configurations and change control for critical cyber assets

---

## 10. Threat Intelligence and Threat Actor Realism

### 10.1 Attack Does Not Match Known ICS Threat Actor TTPs

**What is Unrealistic:**
- Attack completed in single demonstration session (minutes to hours)
- No realistic threat actor motivation or targeting
- No use of known ICS malware families (TRITON, CRASHOVERRIDE, Stuxnet)

**Why It Was Done This Way:**
- Educational simplification: Generic attack scenario easier to understand
- Time constraint: Replicating sophisticated state-sponsored attack beyond scope
- Ethical constraint: Not attempting to recreate actual malware

**How Real ICS Threat Actors Operate:**
- **State-Sponsored APTs:**
  - **XENOTIME:** Russian APT group, responsible for TRITON malware targeting safety systems
  - **Sandworm:** Russian GRU Unit 74455, responsible for Ukraine power grid attacks (CRASHOVERRIDE)
  - **APT33:** Iranian APT targeting aviation and energy sectors
- **Motivations:**
  - Geopolitical disruption (Ukraine power grid attacks)
  - Sabotage of strategic programs (Stuxnet destroying Iranian centrifuges)
  - Pre-positioning for future conflict (access maintained but not activated)
  - Cyber espionage (stealing operational intelligence)
- **Sophisticated TTPs:**
  - Custom malware for specific ICS environments
  - Extended reconnaissance and planning (months to years)
  - Understanding of industrial processes (not just IT skills)
  - Use of legitimate ICS engineering tools to blend in

**MITRE ATT&CK for ICS:**
- Framework documenting ICS-specific tactics, techniques, and procedures
- Examples: Modify Control Logic (T0821), Modify Parameter (T0836), Manipulation of View (T0832)

---

## Summary Table: Key Lab Limitations

| Category                   | Lab Configuration                              | Production Reality                                           | Primary Gap                |
| -------------------------- | ---------------------------------------------- | ------------------------------------------------------------ | -------------------------- |
| **Network Access Control** | Direct SSH from IT to OT permitted             | Multi-layered security: IDMZ, jump hosts, MFA                | Purdue Model violation     |
| **Authentication**         | Password-based SSH                             | Certificate-based, MFA, PAM vaults                           | Weak credential management |
| **Endpoint Security**      | No antivirus, EDR, or application whitelisting | EDR solutions, application whitelisting, malware prevention  | No host-based detection    |
| **PLC Implementation**     | Python pymodbus software simulation            | Physical industrial controllers (Siemens, Allen-Bradley)     | No real hardware           |
| **Modbus Security**        | No authentication or encryption                | IP whitelisting, Modbus/TLS, VPN tunnels                     | Protocol-level security    |
| **Detection**              | Manual PCAP analysis in Wireshark              | Real-time ICS IDS (Nozomi, Claroty, Dragos)                  | No automated alerting      |
| **Logging**                | Manual log review                              | Centralized SIEM with correlation rules                      | No log aggregation         |
| **Incident Response**      | Unilateral actions by single analyst           | Cross-functional coordination (ops, safety, legal)           | No organizational context  |
| **Recovery**               | Instant VM snapshot rollback                   | Validated backup restoration, potential hardware replacement | Unrealistic recovery speed |
| **Safety Systems**         | None implemented                               | Dedicated SIS (Triconex, GuardLogix) per IEC 61511           | No safety architecture     |
| **Physical Process**       | No operational impact from attacks             | Real equipment damage, safety hazards, service disruption    | No consequences            |
| **Environment**            | Fully virtualized (VMware + GNS3)              | Physical PLCs, industrial switches, control panels           | No physical hardware       |
| **Attack Sophistication**  | Simple scripted attack, completed in hours     | State-sponsored APT, months-long campaigns, custom malware   | Threat actor realism       |
