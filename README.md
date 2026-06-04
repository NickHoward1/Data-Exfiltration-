<h1>Data Exfiltration Through DNS Tunneling</h1>

<h2>Objective</h2>
Investigate suspicious DNS activity and determine whether DNS was being used as a covert channel for data exfiltration.

<h2>Scenario</h2>
An alert was raised regarding abnormal DNS traffic. The objective was to analyse network traffic and identify whether sensitive data was being exfiltrated through DNS queries.

<h2>Tools Used</h2>
<ul>
  <li>Wireshark</li>
  <li>DNS Analysis</li>
  <li>Packet Capture (PCAP)</li>
  <li>Threat Hunting Methodology</li>
</ul>

<h2>Investigation Process</h2>

Step 1 - Detecting through Wireshark

Filter1: `dns` 
Filter2: `dns.flags.response == 0` (This filter show me all the DNS outbound requests)
Filter3: `dns && frame.len > 70` to identify DNS packets larger than typical DNS requests.
Filter4: `dns && dns.qry.name contains Tunnelcorp.net` (This shows all the DNS requests coming from a suspicious domain name)

<img src= "https://github.com/NickHoward1/Data-Exfiltration-/blob/0209c2e130cf154ef6ad4d6bdcf1cfa375097eaf/Screenshot%202026-06-04%20at%2011.35.11.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

Step 2 - Detecting through Splunk

Filter1: `index=data_exfil sourcetype=DNS_logs` (These are filter that show the logs for this lab) <b>Note:</b> In the DNS logs, we need to look at the suspicious looking domains with a huge query count from multiple hosts or from one host (suspicious if the domain is untrusted). 
Filter2: `index="data_exfil" sourcetype="DNS_logs" | stats count by src_ip` this filter let's me run the following search query to display the stats of DNS queries generated per source IP.
Filter3: `index="data_exfil" sourcetype="dns_logs" | stats count by query | sort -count` this query will display any odd looking DNS queries. What to look for: single hosts generating far more DNS requests than normal.
Filter4: `index="data_exfil" sourcetype="DNS_logs" | where len(query) > 30`

<img src= "https://github.com/NickHoward1/Data-Exfiltration-/blob/c79f3433275bf8896e5b595f6bb7a092678d4f58/Screenshot%202026-06-04%20at%2011.55.09.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "https://github.com/NickHoward1/Data-Exfiltration-/blob/064982aaf68e52ab7ce2cd32ea5f36bd7df64b2e/Screenshot%202026-06-04%20at%2012.21.57.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

<h2>Findings</h2>

With the following indicators, we were able to identify the data exfiltration attempts through DNS tunneling: A Large number of DNS requests with no response. Large length of the DNS query.

<h2>Indicators of Compromise</h2>

<ul>
  <li>Multiple internal hosts are compromised.</li>
  <li>Large length of the DNS query.</li>
  <li>There is only one external domain identified as the one receiving the DNS queries.</li>
  <li>A Large number of DNS requests with no response.</li>
</ul>

<h2>MITRE ATT&CK Mapping</h2>
<ul>
 <li>T1048 – Exfiltration Over Alternative Protocol</li>
 <li>T1071.004 – Application Layer Protocol: DNS</li>
</ul>

<h2>Recommendations</h2>

<b>Confirm the incident</b><br>
<b>Escalate</b><br>
<b>Contain</b><br>
</li>Block domain</li><br>
</li>Block IP<</li>br>
<b>Isolate device</b><br>
<b>Investigate scope</b><br>
<li>What data was taken?</li><br>
</li>Which users/devices are affected?</li><br>
<b>Eradicate</b><br>
</li>AV scan</li><br>
</li>Remove malware</li><br>
</li>Reset credentials if needed</li><br>
<b>Recovery</b><br>
<b>Lessons Learned</b><br>

<h2>Lessons Learned</h2>

This investigation improved my understanding of DNS traffic analysis, packet inspection, threat hunting and identifying data exfiltration techniques within network traffic.

<h2>Indicators of attack</h2> 

<b>When analysing DNS traffic for possible indicators of data exfiltration, we should look for:</b>
<ul>
<li>Many DNS queries are sent to a single external domain, especially with very high counts compared to the baseline.</li>
<li>Long subdomain labels or unusually long full query names (> 60–100 characters).</li>
<li>High entropy or Base32/Base64-like patterns in the query name (lots of mixed case letters, digits, -, = signs for base64).</li>
<li>Rare record types (TXT, NULL) or many large TXT responses.</li>
<li>Unusual response behavior: frequent NXDOMAIN (if attacker uses exfil-by-query without answering), or TCP/large UDP fragments for DNS.</li>
<li>Queries at regular intervals (beaconing behaviour).</li>
</ul>
