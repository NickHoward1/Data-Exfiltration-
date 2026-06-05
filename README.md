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
<b>Contain</b>
<li>Block domain</li>
<li>Block IP</li>
<li>Isolate device</li>
<b>Eradicate</b>
<li>AV scan</li>
<li>Remove malware</li>
<li>Reset credentials if needed</li>
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





<h1>Data Exfiltration Through FTP</h1>

<h2>Objective</h2>
Investigate suspicious FTP traffic to determine whether sensitive data is being exfiltrated from the network through unauthorised file uploads. Identify the source host, destination server, transferred files, and assess the potential impact to the organisation.

<h2>Scenario</h2>
Multiple FTP file upload operations were detected using the FTP STOR command. The activity indicates that files may be transferred from an internal host to an external FTP server, potentially resulting in unauthorised data exfiltration.

<h2>Tools Used</h2>
<ul>
  <li>Wireshark</li>
  <li>Packet Capture (PCAP)</li>
  <li>Threat Hunting Methodology</li>
</ul>

<h2>Investigation Process</h2>

Step 1 - Detecting through Wireshark

Filter1: `ftp || ftp-data` This filter will alow me filter for ftp sessions and isolate the ftp control traffic.
Filter2: `ftp.request.command == "USER" || ftp.request.command == "PASS"` from the output, we can look for suspicious usernames or weak passwords.
Filter3: `ftp contains "STOR"` searches for ftp packets containing the command:STOR, It's an FTP command used to upload a file from the client to the FTP server.
Filter4: `ftp contains "csv"` I can look at suspicious files by filtering on the file extensions like PDF, csv, TXT etc.
Filter5: `ftp && frame.len > 90` then `Packet - Follow - TCP stream`

<img src= "https://github.com/NickHoward1/Data-Exfiltration-/blob/f337f3581073019f75ef0225123a0b903349e24e/Screenshot%202026-06-04%20at%2014.24.34.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "https://github.com/NickHoward1/Data-Exfiltration-/blob/1735e2184bb57744216d3c60b3970544e31c9651/Screenshot%202026-06-04%20at%2014.27.47.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<img src= "https://github.com/NickHoward1/Data-Exfiltration-/blob/24d9cf6bb0fb5596a16787d11e733c5672f7eb9f/Screenshot%202026-06-04%20at%2014.33.28.png" width="300" height="300"/> 

<h2>Findings</h2>

Internal passwords are being exfiltrated via STOR internal_passwords.csv
Customer Data is being exfiltrated via STOR customer_data.xlsx

<h2>Indicators of Compromise</h2>

<ul>
  <li>I found suspicious CSV files within the PCAP</li>
  <li>Anomalies in Filenames or Credentials</li>
  <li>suspicious IP connected as Guest account has transferred some sensitive csv files to a supicious external IP</li>
</ul>

<h2>MITRE ATT&CK Mapping</h2>

 T1048 – Exfiltration Over Alternative Protocol
 TA0010 – Exfiltration


<h2>Recommendations</h2>

Validate whether the FTP destination is authorised.
Identify the user and host responsible for the upload.
Review transferred filenames and data volume.
Block the FTP destination if malicious.
Isolate affected endpoint if compromise is suspected.
Escalate according to incident response procedures.
Perform additional investigation for malware or credential compromise.

<h2>Lessons Learned</h2>
I've learnt to check for large frames, and commands such as STOR, using various filters to retrieve the data i need for a TP for data exfiltration via FTP. 

<h2>Indicators of attack</h2> 

<b>How adversaries use FTP for exfiltration:</b><br>
Use legitimate FTP servers (public or misconfigured internal servers) to stage/transfer data.<br>
Use compromised credentials (service accounts, user creds).<br>
Use non-standard ports or tunneling to blend with other traffic.<br>

<ul>
<li>USER and PASS commands (cleartext credentials).</li>
<li>STOR (upload) and RETR (download) commands: repeated or large transfers.</li>
<li>Large data connections to unusual external IPs, especially outside business hours.</li>
<li>Data channel openings on ephemeral ports (PASV) paired with large payloads.</li>
</ul>






<h1>Data Exfiltration Through ICMP</h1>

<h2>Objective</h2>


<h2>Scenario</h2>


<h2>Tools Used</h2>
<ul>
  <li>Wireshark</li>
  <li>Packet Capture (PCAP)</li>
  <li>Threat Hunting Methodology</li>
</ul>

<h2>Investigation Process</h2>

Step 1 

Filter1: 
Filter2: 
Filter3: 
Filter4: 
Filter5: 

<img src= "" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

<h2>Findings</h2>

<h2>Indicators of Compromise</h2>

<ul>
  <li></li>
  <li></li>
  <li></li>
</ul>

<h2>MITRE ATT&CK Mapping</h2>

 T1048 – Exfiltration Over Alternative Protocol
 TA0010 – Exfiltration


<h2>Recommendations</h2>

<h2>Lessons Learned</h2>


<h2>Indicators of attack</h2> 

<ul>
<li></li>
<li></li>
<li></li>
<li></li>
</ul>




<h1>Data Exfiltration Through HTTP</h1>

<h2>Objective</h2>
Investigate suspicious HTTP traffic to determine whether sensitive data is being exfiltrated from the network through HTTP communications. Identify the affected host, destination server, transferred data, and assess the potential impact to the organisation. Determine whether the activity is legitimate business traffic or malicious data exfiltration.

<h2>Scenario</h2>
Suspicious outbound HTTP traffic has been detected between an internal host and an external web server. Analysis indicates a large volume of data being transferred over HTTP, which may represent unauthorised data exfiltration.

<h2>Tools Used</h2>
<ul>
  <li>Wireshark</li>
  <li>Packet Capture (PCAP)</li>
  <li>Threat Hunting Methodology</li>
</ul>

<h2>Investigation Process</h2>

Step 1 

Filter1: 
Filter2: 
Filter3: 
Filter4: 
Filter5: 

<img src= "" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

<h2>Findings</h2>

<h2>Indicators of Compromise</h2>

<ul>
  <li></li>
  <li></li>
  <li></li>
</ul>

<h2>MITRE ATT&CK Mapping</h2>

TA0010 – Exfiltration<br>
T1041 – Exfiltration Over C2 Channel<br>
T1071.001 – Application Layer Protocol: Web Protocols

<h2>Recommendations</h2>

<h2>Lessons Learned</h2>


<h2>Indicators of attack</h2> 

<ul>
<li>Unusually large HTTP POST requests to external/unexpected hosts.</li>
<li>HTTP requests to domains with low reputation / rarely seen in baseline traffic.</li>
<li>Frequent small requests (beaconing) to the same host, followed by large uploads.</li>
<li>Chunked or multipart transfers where multiple requests compose a larger file.</li>
</ul>

<h3>How adversaries use HTTP for data exfiltration</h3>

<ul>
<li>POST uploads to external servers: Bulk data is sent to attacker-controlled hosts or cloud storage in POST request bodies.</li>
<li>GET requests with encoded data: Attacker squeezes small chunks into query strings or path segments (useful for low-and-slow exfiltration).</li>
<li>Use of common services / CDN: Exfiltration disguised as uploads to popular services or attacker-controlled subdomains under reputable domains.</li>
<li>Custom headers: Data placed in headers (e.g., X-Data: <base64>) may bypass some string-based DLP.</li>
<li>Chunked transfer / multipart: Large payloads split into multiple requests to avoid size thresholds.</li>
<li>HTTPS/TLS tunneling: The encrypted channel hides the payload; detection requires TLS inspection, SNI analysis, or metadata-based detection.</li>
<li>Staging via cloud services: The attacker uploads to Dropbox/GitHub/Gist and then fetches externally.</li>
</ul>

<b>Why it matters</b>
<ul>
<li>HTTP is very common; attackers hide exfiltration in the noise of legitimate web usage.</li>
<li>Successful detection stops data breaches and helps trace attacker activity post-compromise.</li>
<li>Organizations must detect and respond to protect sensitive data and meet compliance requirements.</li>
</ul>
