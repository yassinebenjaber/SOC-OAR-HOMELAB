# SOC/SOAR Home Lab

## Description
I implemented a Security Operations Center (SOC) home lab with a Security Orchestration, Automation, and Response (SOAR) system. The project includes **Wazuh**, **Shuffle**, **Cortex**, **TheHive**, and **Telegram** to detect, analyze, and respond to security events.  

## Languages and Utilities Used
- **PowerShell**: For Wazuh Agent configuration
- **JSON**: For creating Shuffle workflows and API Calls
- **PuTTY**: To generate an SSH key for our Wazuh endpoint
---
- **VMware**: Virtualized the lab environment's infrastructure.

- **Wazuh**: a Pre-built VM image version of the SIEM to monitor system activities, detected anomalies, and generated security alerts (installed locally).
- **Cortex**: To automate threat intelligence on file hashes using analyzers like VirusTotal (installed locally).
- **TheHive**: For incident case creation, investigation, and response (installed locally).
- **Shuffle**: Automated alert processing with workflows triggered by Wazuh’s webhook (installed locally).
- **Telegram**: Provided real-time security alerts to stakeholders via bot integration.
- **Windows 11**: Acted as the monitored endpoint for real-time file activity detection.
---

## Step-by-Step Implementation with Examples

### 1. Wazuh Configuration on Windows 11 Client
**Objective:** Monitor file activities and generate security alerts.

**Actions & Examples:**
- **Installation & Configuration:**  
  - **Installed** the Wazuh agent on a Windows 11 machine using the MSI installer.
  - **Configured** the agent to connect to the Wazuh manager.  
  - **File Monitoring Setup:** Edited `ossec.conf` to watch critical directories. For example:
    ```xml
    <localfile>
      <log_format>syslog</log_format>
      <location>C:\test\test.txt\</location>
    </localfile>
    ```
  - **Outcome:** Any unauthorized file modifications trigger alerts in Wazuh.

---

### 2. Real-Time Notifications with Telegram
**Objective:** Provide immediate notifications to stakeholders.

**Actions & Examples:**
- **Bot Creation:**  
  - Used Telegram’s BotFather to create a new bot and retrieve its token.
- **Integration via PowerShell:**  
  - Developed a PowerShell script to send alerts using the Telegram API.  
  - **Example Script:**
    ```powershell
    $botToken = "123456789:ABCdefGhIJKlmNoPQRstuVWXyz-abcdefghi"
    $chatId = "233423"
    $message = "Wazuh Alert: Unauthorized file change detected on Windows 11 client."
    $url = "https://api.telegram.org/bot$botToken/sendMessage?chat_id=$chatId&text=$message"
    Invoke-RestMethod -Uri $url -Method Get
    ```
  - **Outcome:** Every time a Wazuh alert is generated, the script dispatches a real-time message via Telegram.

---

### 3. Automation & Orchestration with Shuffle
**Objective:** Automate processing of security alerts.

**Actions & Examples:**
- **Workflow Design:**  
  - Created a workflow in **Shuffle** to handle incoming Wazuh alerts.
- **Example Workflow Steps:**
  1. **Trigger:** A new Wazuh alert is received.
  2. **Extract File Hash:** The workflow parses the alert to extract a file hash.
  3. **Send to Cortex:** The extracted hash is sent via an HTTP POST request.
  - **Example JSON Snippet:**
    ```json
    {
      "trigger": "wazuh_alert_received",
      "actions": [
        {
          "type": "parse",
          "field": "alert.message",
          "output": "file_hash"
        },
        {
          "type": "http_request",
          "method": "POST",
          "url": "http://cortex.example.com/api/analyzer",
          "body": { "hash": "${file_hash}" }
        }
      ]
    }
    ```
  - **Outcome:** Automation reduces manual intervention by processing alerts immediately.

---

### 4. Threat Analysis with Cortex
**Objective:** Enrich file hash data with threat intelligence.

**Actions & Examples:**
- **Integration Setup:**  
  - Configured Cortex with connectors to **Malware Bazaar** and **VirusTotal**.
- **Enrichment Process:**  
  - The workflow sends the file hash to Cortex for analysis.
  - **Example HTTP Request:**
    ```json
    POST /api/analyzer HTTP/1.1
    Host: cortex
    Content-Type: application/json

    {
      "hash": "abcdef1234567890"
    }
    ```
  - **Outcome:** Cortex responds with threat intelligence data (e.g., risk scores, malicious indicators) that guide further actions.

---

### 5. Incident Response Management with TheHive
**Objective:** Automate incident response based on Cortex's findings.

**Actions & Examples:**
- **Integration:**  
  - Configured TheHive to receive threat data from Cortex.
- **Automated Case Creation:**  
  - When Cortex identifies a high-risk threat, an API call is made to create a new case in TheHive.
  - **Example API Call:**
    ```json
    POST /api/case HTTP/1.1
    Host: thehive
    Content-Type: application/json

    {
      "title": "Security Incident: Malicious File Detected",
      "description": "Cortex analysis indicates a high risk for file hash abcdef1234567890.",
      "severity": 3,
      "tags": ["malware", "urgent"]
    }
    ```
- **Outcome:**  
  - Predefined playbooks in TheHive categorize the incident and notify admins automatically, streamlining incident response.

---

## Outcome and Impact
- **Enhanced Monitoring:** Real-time tracking and alerting of file activities using Wazuh.
- **Instant Notifications:** Immediate stakeholder alerts via Telegram.
- **Automated Analysis:** Seamless file hash enrichment and threat intelligence retrieval with Cortex.
- **Streamlined Incident Response:** Automated case creation in TheHive accelerates response times and minimizes manual processes.

---




<h2>Screenshot snippets:</h2>

<p align="center">
Wazuh Interface : <br/>
<img src="https://imgur.com/xGYdGSD.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<p align="center" >
Wazuh agent on Win 11 endpoint machine<br/>
 <img src="https://imgur.com/yADP0VQ.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
<p align="center" >
Real-time alerts bein sent in telegram<br/>
 <img src="https://imgur.com/NyOkuy6.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
<p align="center" >
File created on the monitored endpoint<br/>
 <img src="https://imgur.com/5GsxRTA.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
<p align="center" >
Alerts in Wazuh <br/>
 <img src="https://imgur.com/lx5RsPa.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
<p align="center" >
Automated Workflow in Shuffle <br/>
 <img src="https://imgur.com/UxvfcYC.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
<p align="center" >
Thehive Interface<br/>
 <img src="https://imgur.com/kfYYiBS.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
<p align="center" >
Usecase and observations in thehive<br/>
 <img src="https://imgur.com/30oVqVt.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />
<p align="center" >
Cortex Interface<br/>
 <img src="https://imgur.com/E9MbTDs.png" height="80%" width="80%" alt="Disk Sanitization Steps"/>
<br />
<br />



</p>

<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
