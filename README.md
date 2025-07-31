

# Virtual Machine Brute Forcing

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- Microsoft Sentinel 
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)

##  Scenario

When entities (local or remote users, usually) attempt to log into a virtual machine, a log will be created on the local machine and then forwarded to Microsoft Defender for Endpoint under the DeviceLogonEvents table. These logs are then forwarded to the Log Analytics Workspace being used by Microsoft Sentinel, SIEM.

# Creating an alert rule in Sentinel 

Step 1 (defining rule): 

<img width="1912" height="1154" alt="image" src="https://github.com/user-attachments/assets/9c300e3d-ab6e-4ef5-b7f6-a49255285d94" />

Step 2 (setting entity mapping):

<img width="1213" height="1022" alt="image" src="https://github.com/user-attachments/assets/b015d815-79d8-48f8-be00-3a018ad3fba7" />

Rule has been created and active. 

---

# Alert triggered and assigned to myself 

<img width="1233" height="569" alt="image" src="https://github.com/user-attachments/assets/8b1e09cb-b53f-4cb7-8aad-d6d7a880123c" />

---

<img width="316" height="159" alt="image" src="https://github.com/user-attachments/assets/dba6c8e4-67af-43f8-b5bb-aa82d7b26b73" />

## NIST 800-61: Incident Response Lifecycle

### Brute Force Login Attempt

## Analysis

Affected Assets:

Two virtual machines (including kylesvm) Source IPs:

- 45.227.254.155  — 37 failed login attempts

- 88.214.25.123  — 35 failed login attempts
  
These brute-force attempts originated from two different public IP addresses and targeted RDP
access on the affected virtual machines.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "kylesvm"
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, DeviceName
| where EventCount >= 10
| order by EventCount
```
<img width="1148" height="310" alt="image" src="https://github.com/user-attachments/assets/6060908c-0ff5-4bc3-94ac-bd2760b7c406" />

---

## Investigation

I checked to see if any of the IP addresses attemtping to brute force successfully logged in but none were successful: 

**Query used to locate event:**

```kql
DeviceLogonEvents
| where RemoteIP in ("45.227.254.155", "88.214.25.123")
| where ActionType == "LogonSuccess"
```
<img width="512" height="272" alt="image" src="https://github.com/user-attachments/assets/bdbf5bad-166c-4ca7-bfaa-49f32eed848a" />

---

## Containment & Post-Incident Activities

- Isolated the affected VM (kylesvm) in Microsoft Defender for Endpoint (MDE).
  
- Performed a full antimalware scan via MDE to detect any post-exploitation activity.
  
- Modified Network Security Group (NSG) rules to block all RDP access from the public internet, allowing only access from a trusted IP address (personal).
  
- Proposed a corporate policy requiring RDP access to all Azure VMs to be restricted by IP address. This can be enforced using Azure Policy.
