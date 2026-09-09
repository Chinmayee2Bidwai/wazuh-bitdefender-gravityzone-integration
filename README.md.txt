# Bitdefender GravityZone → Wazuh SIEM Integration

A Wazuh integration for monitoring Bitdefender GravityZone security events, extracting the actual endpoint hostname, and generating searchable Wazuh alerts.

> **Reference:** [Wazuh — Integrating Bitdefender GravityZone with Wazuh](https://wazuh.com/blog/integrating-bitdefender-gravityzone-with-wazuh/)
>
> The official Wazuh article was written for an earlier Wazuh release. This repository documents the implementation actually built and tested in this lab on **Wazuh 4.14.7**, including additional customizations.

---

## 1. Project Objective

The objective is to send Bitdefender GravityZone security events to Wazuh and make them available for centralized monitoring and investigation.

The integration provides visibility into:

* Bitdefender endpoint hostname
* Endpoint FQDN
* Detection name
* Action taken
* GravityZone incident number
* Severity score
* Raw CEF event
* Wazuh rule and decoder information

---

## 2. Architecture

```text
                    Bitdefender GravityZone
                            |
              +-------------+-------------+
              |                           |
          CEF Events                 Incidents API
              |                           |
          TCP 514                 Python Polling Script
              |                           |
              +-------------+-------------+
                            |
                       Wazuh Manager
                            |
                 Custom CEF Decoder
                    bd-gz-incident
                            |
                    Custom Wazuh Rules
                    100500 / 100502
                            |
                     Wazuh Indexer
                            |
                    Wazuh Dashboard
                    Threat Hunting
```

### Important hostname behavior

The event is centrally ingested by the Wazuh manager.

Therefore Wazuh may show:

```text
agent.name = user-VMware-Virtual-Platform
agent.id   = 000
```

This is the Wazuh manager identity.

The actual Bitdefender endpoint is stored separately:

```text
data.endpoint_host
data.endpoint_fqdn
```

Example:

```text
agent.name         = user-VMware-Virtual-Platform
data.endpoint_host = VED
data.endpoint_fqdn = ved
```

---

# 3. Lab Environment

| Component               | Value                    |
| ----------------------- | ------------------------ |
| Operating System        | Ubuntu Server 24.04      |
| Wazuh                   | 4.14.7                   |
| Wazuh Manager           | Same Ubuntu VM           |
| Wazuh Indexer           | Same Ubuntu VM           |
| Wazuh Dashboard         | Same Ubuntu VM           |
| Wazuh VM IP used in lab | `192.168.9.75`           |
| Syslog/CEF port         | TCP 514                  |
| Local Wazuh agent       | ID `000`                 |
| Bitdefender             | GravityZone              |
| Test endpoint           | Windows with Bitdefender |
| Safe detection test     | EICAR                    |

> **Security:** Do not commit API keys, passwords, certificates, private keys, customer data, or production logs to a public repository.

---

# 4. Official Wazuh Documentation Followed

The initial implementation was based on:

**Wazuh — Integrating Bitdefender GravityZone with Wazuh**

https://wazuh.com/blog/integrating-bitdefender-gravityzone-with-wazuh/

The official article covers the core integration concepts:

* Bitdefender GravityZone CEF push
* GravityZone connector
* `gz-evpsc`
* Rsyslog
* Wazuh syslog input
* Custom decoder
* Custom rules
* EICAR testing
* Threat Hunting event verification

This project goes beyond the sample implementation with a custom incident decoder and a separate GravityZone API polling mechanism.

---

# 5. Wazuh Syslog Configuration

Wazuh was configured to accept syslog/CEF traffic on TCP port `514`.

File:

```text
/var/ossec/etc/ossec.conf
```

Relevant configuration:

```xml
<remote>
    <connection>syslog</connection>
    <port>514</port>
</remote>
```

Verify:

```bash
sudo grep -nE '514|syslog|<remote>' /var/ossec/etc/ossec.conf
```

Verify the listener:

```bash
sudo ss -lntp | grep ':514'
```

Expected:

```text
0.0.0.0:514
```

---

# 6. Custom GravityZone CEF Decoder

The project uses a custom decoder instead of relying on the original generic CEF decoder.

File:

```text
/var/ossec/etc/decoders/local_decoder.xml
```

Decoder:

```xml
<decoder name="bd-gz-incident">
    <program_name>CEF</program_name>
    <regex type="pcre2">.*?dvchost=(\S+).*?BitdefenderGZComputerFQDN=(\S+).*?BitdefenderGZIncidentId=(\S+).*?BitdefenderGZIncidentNumber=(\d+).*?BitdefenderGZSeverityScore=(\d+).*?BitdefenderGZMainAction=(\S+).*?BitdefenderGZDetectionName=(\S+)</regex>
    <order>endpoint_host,endpoint_fqdn,incident_id,incident_number,severity_score,action,detection_name</order>
</decoder>
```

## Extracted fields

```text
endpoint_host
endpoint_fqdn
incident_id
incident_number
severity_score
action
detection_name
```

This makes the alert much easier to investigate than relying only on the Wazuh source/agent hostname.

---

# 7. Custom Wazuh Rules

File:

```text
/var/ossec/etc/rules/local_rules.xml
```

Current rules:

```xml
<group name="bitdefender,">

    <rule id="100500" level="10">
        <decoded_as>bd-gz-incident</decoded_as>
        <description>Bitdefender GravityZone incident on $(endpoint_fqdn) - $(detection_name) - Action: $(action) - Incident: $(incident_number)</description>
        <group>bitdefender,malware,</group>
    </rule>

    <rule id="100502" level="12">
        <if_sid>100500</if_sid>
        <match>blocked</match>
        <description>Bitdefender GravityZone threat BLOCKED on $(endpoint_fqdn) - $(detection_name) - Incident: $(incident_number)</description>
        <group>bitdefender,malware,blocked,</group>
    </rule>

</group>
```

## Rule purpose

| Rule   | Level | Purpose                                  |
| ------ | ----: | ---------------------------------------- |
| 100500 |    10 | General Bitdefender GravityZone incident |
| 100502 |    12 | Blocked Bitdefender threat               |

The rule IDs are local to this project.

---

# 8. GravityZone API Polling

A second integration path was implemented using the GravityZone Incidents API.

Script:

```text
/usr/local/bin/bitdefender_to_wazuh.py
```

API endpoint:

```text
https://cloud.gravityzone.bitdefender.com/api/v1.2/jsonrpc/incidents
```

The script performs:

1. Authentication using the GravityZone API key.
2. `getIncidentsList` API calls.
3. Incident retrieval.
4. New incident detection.
5. Duplicate prevention.
6. Sending new incidents to Wazuh.
7. Local event logging.

Output:

```text
/var/log/bitdefender/events.log
```

---

# 9. API Key Storage

The API key is stored outside the Python script:

```text
/root/bitdefender-api-key
```

Do not publish this file.

A public GitHub repository should use placeholders such as:

```text
<GRAVITYZONE_API_KEY>
```

---

# 10. Systemd Automation

The API integration is automated with:

```text
/etc/systemd/system/bitdefender-wazuh.service
/etc/systemd/system/bitdefender-wazuh.timer
```

Check the timer:

```bash
sudo systemctl status bitdefender-wazuh.timer --no-pager
```

Check the service:

```bash
sudo systemctl status bitdefender-wazuh.service --no-pager
```

View logs:

```bash
sudo journalctl -u bitdefender-wazuh.service --no-pager
```

Because the service is a `oneshot` service, this can be normal after execution:

```text
Active: inactive (dead)
```

The timer is responsible for recurring execution.

---

# 11. Duplicate Incident State

Previously processed incident IDs are stored in:

```text
/var/lib/bitdefender-wazuh/processed.json
```

This prevents the same API incident from being submitted repeatedly.

Check:

```bash
sudo cat /var/lib/bitdefender-wazuh/processed.json
```

---

# 12. Event Files

## GravityZone API output

```text
/var/log/bitdefender/events.log
```

View:

```bash
sudo tail -20 /var/log/bitdefender/events.log
```

## Wazuh archives

```text
/var/ossec/logs/archives/archives.json
```

Search:

```bash
sudo grep -i 'BitdefenderGZ' /var/ossec/logs/archives/archives.json | tail
```

## Wazuh alerts

```text
/var/ossec/logs/alerts/alerts.json
```

Search:

```bash
sudo grep -i 'BitdefenderGZ' /var/ossec/logs/alerts/alerts.json | tail
```

Search specifically for the custom rule:

```bash
sudo grep '"id":"100502"' /var/ossec/logs/alerts/alerts.json | tail
```

---

# 13. Wazuh Configuration Validation

Before restarting Wazuh:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

Restart:

```bash
sudo systemctl restart wazuh-manager
```

Check:

```bash
sudo systemctl status wazuh-manager --no-pager
```

Expected:

```text
Active: active (running)
```

---

# 14. Decoder Testing

Run:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste a GravityZone CEF event.

Example:

```text
CEF: 0|Bitdefender|GravityZone|6.76.1-1|170000|New Incident|3|BitdefenderGZModule=new-incident dvchost=VED BitdefenderGZComputerFQDN=ved dvc=114.79.161.192 deviceExternalId=... BitdefenderGZIncidentId=... BitdefenderGZIncidentNumber=45840 BitdefenderGZSeverityScore=26 BitdefenderGZAttackEntry=1737733255 BitdefenderGZMainAction=blocked BitdefenderGZDetectionName=URL.Phishing ...
```

Expected decoder:

```text
bd-gz-incident
```

Expected extracted values:

```text
endpoint_host: VED
endpoint_fqdn: ved
incident_number: 45840
severity_score: 26
action: blocked
detection_name: URL.Phishing
```

Expected rule:

```text
100502
```

Expected level:

```text
12
```

---

# 15. Live Integration Verification

The live integration was successfully tested with GravityZone incident `45840`.

Observed CEF data included:

```text
BitdefenderGZComputerFQDN=ved
BitdefenderGZIncidentNumber=45840
BitdefenderGZSeverityScore=26
BitdefenderGZMainAction=blocked
BitdefenderGZDetectionName=URL.Phishing
```

Wazuh generated:

```text
decoder.name = bd-gz-incident
rule.id      = 100502
rule.level   = 12
```

Extracted event data:

```text
data.action           = blocked
data.endpoint_host    = VED
data.endpoint_fqdn    = ved
data.incident_number  = 45840
data.severity_score   = 26
data.detection_name   = URL.Phishing
```

This validates the complete live pipeline.

---

# 16. Safe EICAR Test

Use the EICAR anti-malware test instead of real malware.

Official test page:

https://www.eicar.org/download-anti-malware-testfile/

The test can cause Bitdefender to generate a safe detection event.

After detection, search Wazuh for:

```text
rule.id:100502
```

Then inspect:

```text
data.endpoint_host
data.endpoint_fqdn
data.detection_name
data.action
data.incident_number
data.severity_score
```

Do not use real malware to validate the integration.

---

# 17. Threat Hunting

Open:

```text
Wazuh Dashboard
    → Threat Hunting
    → Events
```

Depending on the dashboard version, the event view may also appear under Discover/Data Explorer.

## All custom Bitdefender incidents

```text
rule.id:100500 OR rule.id:100502
```

## Blocked threats

```text
rule.id:100502
```

## Search by endpoint

```text
data.endpoint_fqdn:"ved"
```

or:

```text
data.endpoint_host:"VED"
```

## Search by detection

```text
data.detection_name:"URL.Phishing"
```

## Search by incident

```text
data.incident_number:"45840"
```

Recommended displayed fields:

```text
timestamp
rule.id
rule.level
agent.name
data.endpoint_host
data.endpoint_fqdn
data.detection_name
data.action
data.incident_number
data.severity_score
```

---

# 18. Understanding the Wazuh Hostname

You may see:

```text
agent.name = user-VMware-Virtual-Platform
```

This does not mean Bitdefender is detecting your Ubuntu VM.

The event is being centrally injected into the Wazuh manager.

The actual protected endpoint is:

```text
data.endpoint_host
data.endpoint_fqdn
```

Example:

```text
Wazuh agent:
user-VMware-Virtual-Platform

Bitdefender endpoint:
VED

Bitdefender FQDN:
ved
```

This distinction is expected with the current architecture.

---

# 19. Troubleshooting

## Wazuh is not listening on TCP 514

```bash
sudo ss -lntp | grep ':514'
```

Check:

```bash
sudo grep -nE '514|syslog|<remote>' /var/ossec/etc/ossec.conf
```

Restart:

```bash
sudo systemctl restart wazuh-manager
```

---

## No Bitdefender events appear in alerts

First check archived events:

```bash
sudo grep -i 'BitdefenderGZ' /var/ossec/logs/archives/archives.json | tail -5
```

Then check alerts:

```bash
sudo grep -i 'BitdefenderGZ' /var/ossec/logs/alerts/alerts.json | tail -5
```

Then test the decoder:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

---

## Check live TCP 514 traffic

```bash
sudo tcpdump -ni any tcp port 514 -A
```

A GravityZone CEF message should contain:

```text
CEF:
Bitdefender
GravityZone
BitdefenderGZIncidentNumber=
```

Example:

```text
CEF: 0|Bitdefender|GravityZone|...
```

---

## Old events still use the old decoder

Historical Wazuh alerts are not automatically re-decoded.

An older event can therefore still show:

```text
decoder = bitdefender-cef
rule    = 100501
```

New events after the custom configuration should show:

```text
decoder = bd-gz-incident
rule    = 100500 or 100502
```

---

## API polling shows zero new incidents

Check:

```bash
sudo journalctl -u bitdefender-wazuh.service --no-pager
```

You may see:

```text
Found 10 incidents
New incidents sent to Wazuh: 0
```

This means the API call succeeded but there were no new incident IDs to send.

---

# 20. Official Documentation vs Custom Implementation

## From the official Wazuh guide

```text
Bitdefender GravityZone
        ↓
CEF / connector
        ↓
Rsyslog
        ↓
Wazuh
        ↓
Custom decoder
        ↓
Custom rules
        ↓
Threat Hunting
```

## Additional work implemented in this lab

```text
GravityZone API polling
Python integration
API key separation
systemd service
systemd timer
processed.json
custom incident decoder
custom rules 100500 / 100502
hostname extraction
FQDN extraction
detection extraction
action extraction
severity extraction
incident number extraction
wazuh-logtest validation
tcpdump validation
EICAR validation
live incident verification
```

---

# 21. Security and GitHub Publishing

Before publishing this project, remove or replace:

```text
API keys
Passwords
Private certificates
Private keys
Customer names
Customer endpoint names
Internal IP addresses
Production incident URLs
Production logs
```

Use placeholders:

```text
<GRAVITYZONE_API_KEY>
<WAZUH_MANAGER_IP>
<ENDPOINT_HOSTNAME>
<COMPANY_ID>
```

Recommended `.gitignore`:

```gitignore
# Secrets
*.key
*.pem
*.crt
*.csr
.env
.env.*
secrets/
credentials/
*-api-key

# Runtime data
processed.json
events.log

# Local files
.DS_Store
Thumbs.db
.vscode/
.idea/
```

---

# 22. Useful Commands

### Wazuh

```bash
sudo systemctl status wazuh-manager --no-pager
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/wazuh-analysisd -t
sudo /var/ossec/bin/wazuh-logtest
```

### TCP 514

```bash
sudo ss -lntp | grep ':514'
sudo tcpdump -ni any tcp port 514 -A
```

### GravityZone API integration

```bash
sudo systemctl status bitdefender-wazuh.timer --no-pager
sudo systemctl status bitdefender-wazuh.service --no-pager
sudo journalctl -u bitdefender-wazuh.service --no-pager
sudo tail -20 /var/log/bitdefender/events.log
sudo cat /var/lib/bitdefender-wazuh/processed.json
```

### Wazuh events

```bash
sudo grep -i 'BitdefenderGZ' /var/ossec/logs/archives/archives.json | tail
```

```bash
sudo grep -i 'BitdefenderGZ' /var/ossec/logs/alerts/alerts.json | tail
```

```bash
sudo grep '"id":"100502"' /var/ossec/logs/alerts/alerts.json | tail
```

---

# 23. Validation Checklist

* [x] Wazuh installed
* [x] Wazuh Manager running
* [x] Wazuh Indexer running
* [x] Wazuh Dashboard accessible
* [x] TCP 514 enabled
* [x] GravityZone CEF event received
* [x] Custom CEF decoder installed
* [x] Custom rules installed
* [x] `wazuh-logtest` validation completed
* [x] Live Bitdefender event received
* [x] Actual endpoint hostname extracted
* [x] Endpoint FQDN extracted
* [x] Detection name extracted
* [x] Action extracted
* [x] Incident number extracted
* [x] Severity extracted
* [x] Rule `100502` generated
* [x] EICAR safe test completed
* [x] Threat Hunting verification completed
* [x] GravityZone API polling implemented
* [x] Duplicate incident state implemented

---

# 24. Example Final Alert

```text
Bitdefender GravityZone threat BLOCKED on ved
Detection: URL.Phishing
Action: blocked
Incident: 45840
Severity: 26
Rule: 100502
Level: 12
```

This confirms that Bitdefender GravityZone security activity is being received by Wazuh and enriched with the actual Bitdefender endpoint information.

---

## References

* Wazuh — Integrating Bitdefender GravityZone with Wazuh
  https://wazuh.com/blog/integrating-bitdefender-gravityzone-with-wazuh/

* EICAR Anti-Malware Testfile
  https://www.eicar.org/download-anti-malware-testfile/
