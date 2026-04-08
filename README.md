**Brute Force Investigation on an Internet‑Exposed VM**
=======================================================

This lab walks through how I investigated a VM that was accidentally exposed to the public internet. I used Defender, KQL, and some basic hunting techniques to figure out whether anyone tried to brute‑force into it and whether any of those attempts were successful.

**1\. Preparation**
-------------------

**Goal:** Figure out what I'm looking for before diving into logs.

During routine maintenance, our team needed to check the shared‑services VMs (DNS, Domain Services, DHCP, etc.) to make sure none of them were accidentally exposed to the internet. If they were, the next step was to see whether anyone tried to brute‑force their way in --- especially since some older machines don't have account lockout policies.

**Activity:** My hypothesis was simple: If the VM was exposed long enough, someone probably tried to brute‑force it. And if they tried, I needed to confirm whether any of those attempts actually succeeded.

**2\. Data Collection**
-----------------------

**Goal:** Pull the logs I need to understand what happened.

**Activity:** I focused on two tables:

-   `DeviceInfo`
-   `DeviceLogonEvents`

These give me everything I need to check exposure, failed logons, successful logons, and where they came from.

### **Checking if the VM Was Internet‑Facing**


```
DeviceInfo
| where DeviceName == "queen-th-vm"
| where IsInternetFacing == true
| order by Timestamp desc
```

The VM had been exposed for several days. **Last internet‑facing timestamp:** `2026-03-24T04:07:49Z`.

### **Looking for Failed Logons**


```
DeviceLogonEvents
| where DeviceName == "queen-th-vm"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts
```
<img width="855" height="206" alt="image" src="https://github.com/user-attachments/assets/9ce4da1c-24b9-4cc3-b783-1447ecbe0e6d" />

Several external IPs were hammering the VM with failed login attempts --- classic brute‑force behavior.

### **Checking Whether Any of Those IPs Succeeded**


```
let RemoteIPsInQuestion = dynamic(["154.192.222.89","37.49.226.115","14.136.73.18","105.157.241.11"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
<img width="1236" height="429" alt="image" src="https://github.com/user-attachments/assets/34ce7776-4667-4e4c-ace9-576f73f7e767" />

**None** of the attacker IPs ever logged in successfully.

**3\. Data Analysis**
---------------------

**Goal:** Test the hypothesis and look for anything suspicious.

**Activity:** I checked for:

-   Failed → then successful logons
-   Suspicious usernames
-   Suspicious source IPs
-   Any abnormal login patterns

### **Reviewing All Successful Logons**


```
DeviceLogonEvents
| where DeviceName == "queen-th-vm"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
```

Everything looked normal.

### **Checking Which Accounts Logged In**


```
DeviceLogonEvents
| where DeviceName == "queen-th-vm"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| distinct AccountName
```

Only expected accounts showed up.

### **Checking Whether My Account Was Targeted**


```
DeviceLogonEvents
| where DeviceName == "queen-th-vm"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "paige"
```

No one tried to brute‑force my username. Attackers were just guessing common names.

### **Counting My Successful and Failed Logons**


```
// Successful
DeviceLogonEvents
| where DeviceName == "queen-th-vm"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "paige"
| summarize count()

// Failed
DeviceLogonEvents
| where DeviceName == "queen-th-vm"
| where LogonType == "Network"
| where ActionType == "LogonFailed"
| where AccountName == "paige"
| summarize count()
```

My account had **zero** failed attempts.

### **Checking Where My Successful Logons Came From**


```
DeviceLogonEvents
| where DeviceName == "queen-th-vm"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "paige"
| summarize LoginCount = count() by DeviceName, ActionType, AccountName, RemoteIP
```
<img width="877" height="142" alt="image" src="https://github.com/user-attachments/assets/6883f3f0-c62b-46ee-922e-c8b20ce56152" />


All successful logons came from my desktop → Azure VM. Nothing suspicious.

**4\. Investigation**
---------------------

**Goal:** Dig deeper into anything suspicious and map it to MITRE ATT&CK.

**Activity:** I took the behaviors I observed and mapped them to TTPs.

### **MITRE ATT&CK TTPs Identified**


```
T1595 -- Active Scanning
T1110 -- Brute Force
T1021 -- Remote Services
T1589 -- Gather Victim Identity Information
T1033 -- System Owner/User Discovery
```

These line up with what I saw: scanning, brute‑force attempts, username guessing, and remote logon probing.

**5\. Response**
----------------

**Goal:** Mitigate the issue and prevent it from happening again.

**Activity:** Since these VMs should never be exposed to the internet, the fix is straightforward:

-   Add NSG inbound rules to only allow RDP from approved IPs
-   Implement account lockout thresholds
-   Add MFA for administrative access

This reduces brute‑force risk and tightens access control.

**6\. Documentation**
---------------------

**Goal:** Record everything for future hunts.

**Activity:** This write‑up documents:

-   What happened
-   What I looked for
-   What I found
-   What I ruled out
-   What actions were taken


**7\. Improvement**
-------------------

**Goal:** Strengthen the environment and refine the process.

**Activity:** A few things that would help prevent this in the future:

-   Avoid exposing shared‑services VMs to the internet
-   Use JIT (Just‑In‑Time) access
-   Increase log retention
-   Automate brute‑force detection alerts
-   Standardize account lockout policies
-   Regularly review NSG/firewall rules
