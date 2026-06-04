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

Step 1 - 

Step 2 - 

Step 3 - 

Step 4 -

<h2>Findings</h2>

<h2>Indicators of Compromise</h2>

<ul>
  <li></li>
  <li></li>
  <li>)</li>
  <li></li>
</ul>

<h2>MITRE ATT&CK Mapping</h2>

<h2>Recommendations</h2>

<h2>Lessons Learned</h2>

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
