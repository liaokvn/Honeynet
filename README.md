# Bait & Defend: Building a Cloud SOC with Live Attack Data

## Objective

This project aimed to simulate real-world threat detection by deploying a honeynet Microsoft Azure and integrating log data into a centralized Log Analytics Workspace. Using Microsoft Sentinel as the SIEM, I created detection rules, visualizations, and automated responses to monitor and respond to live malicious activity.

To evaluate the effectiveness of security measures, the environment was first exposed without controls for 24 hours to capture baseline threats. After implementing security hardening, such as access restrictions and firewal rules, I monitored the secured environment for another 24 hours. This allowed me to assess improvements in threat visibility, detection accuracy, and incident response efficiency. 

Key log sources collected included:
- SecurityEvent (Windows Event Logs)
- Syslog (Linux Event Logs)
- SecurityAlert (Log Analytics Alerts Triggered)
- SecurityIncident (Incidents created by Sentinel)
- AzureNetworkAnalytics_CL (Malicious Flows allowed into our honeynet)

## Architecture Before Hardening / Security Controls
![image](https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/efa182b3-afe3-46d6-b431-84fe61c1daff)


## Architecture After Hardening / Security Controls
![image](https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/bda2d085-3471-4d51-8373-404e5dbd3371)


The architecture of the mini honeynet in Azure consists of the following components:

- Virtual Network (VNet)
- Network Security Group (NSG)
- Virtual Machines (2 windows, 1 linux)
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel


## Attack Maps Before Hardening / Security Controls
<img width="735" alt="Capture1" src="https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/6201e7a7-6e1e-4759-bca5-c820e125190c">
<br><br>
<img width="593" alt="Capture2" src="https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/ccefa380-5948-4dd6-b52c-f303648fb68e">
<br><br>
<img width="598" alt="Capture3" src="https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/3406fac0-c152-4684-bc3a-236ff35a9eb4">
<br><br>

## Metrics Before Hardening / Security Controls

The following table shows the metrics we measured in our insecure environment for 24 hours:
<br>
| Start Time 2024-04-13 13:53:48
<br>
| Stop Time 2024-04-14 13:53:48

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 7671
| Syslog                   | 833
| SecurityAlert            | 4
| SecurityIncident         | 59
| AzureNetworkAnalytics_CL | 620

## Attack Maps After Hardening / Security Controls

<img width="231" alt="noresults" src="https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/031e52cf-266f-40de-a1b1-d8ff313aa746">
<br><br>

```All map queries actually returned no results due to no instances of malicious activity for the 24 hour period after hardening.```

## Metrics After Hardening / Security Controls

The following table shows the metrics we measured in our environment for another 24 hours, but after we have applied security controls:
<br>
| Start Time 2024-04-15 11:50:28
<br>
| Stop Time 2024-04-16 11:50:28

| Metric                   | Count
| ------------------------ | -----
| SecurityEvent            | 3894
| Syslog                   | 6
| SecurityAlert            | 0
| SecurityIncident         | 0
| AzureNetworkAnalytics_CL | 0

![image](https://github.com/kphillip1/azure-soc-honeynet/assets/165929885/3d5a9f41-fd9f-4e0c-bfa1-85da4b249939)


## Summary

This project focused on building a cloud-based honeynet and SOC simulation in Microsoft Azure to monitor, detect, and response to live cyber threats. By ingesting logs from sources into a Log Analytics Workspace and analyzing them using Microsoft Sentinel, I was able to simulate real-world attack scenarios and create alerts and incidents in response to suspicious activity. 

This simulations mirrors real-world environments where live threat data must be continuously analyzed, and responses must be quick and accurate. It reinforced the importance of visibility, detection capabilities and incident response workflows critical components in protecting today's cloud-based infrastructure from evolving cyber threats. 

## KQL Queries

| Metric                                       | Query                                                                                                                                            |
|----------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------|
| Start/Stop Time                              | range x from 1 to 1 step 1<br>\| project StartTime = ago(24h), StopTime = now()                                                                  |
| Security Events (Windows VMs)                | SecurityEvent<br>\| where TimeGenerated>= ago(24h)<br>\| count                                                                                   |
| Syslog (Linux VMs)                           | Syslog<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                                         |
| SecurityAlert (Microsoft Defender for Cloud) | Security Alert<br>\| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"<br>\| where TimeGenerated >= ago(24h)<br>\| count |
| Security Incident (Sentinel Incidents)       | SecurityIncident<br>\| where TimeGenerated >= ago(24h)<br>\| count                                                                               |
| NSG Inbound Malicious Flows Allowed          | AzureNetworkAnalytics_CL<br>\| where FlowType_s == "Mal
