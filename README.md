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

Filter1: `dns` <br>
Filter2: `dns.flags.response == 0` (This filter show me all the DNS outbound requests)<br>
Filter3: `dns && frame.len > 70` to identify DNS packets larger than typical DNS requests.<br>
Filter4: `dns && dns.qry.name contains Tunnelcorp.net` (This shows all the DNS requests coming from a suspicious domain name)<br>

<img src= "https://github.com/NickHoward1/Data-Exfiltration-/blob/0209c2e130cf154ef6ad4d6bdcf1cfa375097eaf/Screenshot%202026-06-04%20at%2011.35.11.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

Step 2 - Detecting through Splunk

Filter1: `index=data_exfil sourcetype=DNS_logs` (These are filter that show the logs for this lab) <b>Note:</b> In the DNS logs, we need to look at the suspicious looking domains with a huge query count from multiple hosts or from one host (suspicious if the domain is untrusted). <br>
Filter2: `index="data_exfil" sourcetype="DNS_logs" | stats count by src_ip` this filter let's me run the following search query to display the stats of DNS queries generated per source IP.<br>
Filter3: `index="data_exfil" sourcetype="dns_logs" | stats count by query | sort -count` this query will display any odd looking DNS queries. What to look for: single hosts generating far more DNS requests than normal.<br>
Filter4: `index="data_exfil" sourcetype="DNS_logs" | where len(query) > 30`<br>

<img src= "https://github.com/NickHoward1/Data-Exfiltration-/blob/c79f3433275bf8896e5b595f6bb7a092678d4f58/Screenshot%202026-06-04%20at%2011.55.09.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "https://github.com/NickHoward1/Data-Exfiltration-/blob/064982aaf68e52ab7ce2cd32ea5f36bd7df64b2e/Screenshot%202026-06-04%20at%2012.21.57.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

<h2>Findings</h2>

I identify the data exfiltration attempts through DNS tunneling: A Large number of DNS requests with no response. Large length of the DNS query.

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

<b>When analysing DNS traffic for possible indicators of data exfiltration, look for:</b>
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
Investigate suspicious ICMP traffic to determine whether the ICMP protocol is being abused to exfiltrate data from the network. Identify the affected host, destination IP address, data transfer patterns, and assess the potential impact to the organisation.

<h2>Scenario</h2>
Unusual ICMP traffic has been detected between an internal host and an external IP address. Analysis indicates an abnormal volume of ICMP packets and payload sizes that may suggest the ICMP protocol is being used as a covert channel for data exfiltration.

<h2>Tools Used</h2>
<ul>
  <li>Wireshark</li>
  <li>Packet Capture (PCAP)</li>
  <li>Threat Hunting Methodology</li>
</ul>

<h2>Investigation Process</h2>

Step 1 - Looking for large payloads within the network traffic anything larger than 70 bytes is suspicious.

Filter1: `icmp` - The filter below isolates all ICMP packets. Look for unusually frequent or large ICMP Echo Requests/Replies.<br>
Filter2: `icmp.type == 8` - this filter isolates ICMP Echo Request packets<br>
Filter3: `icmp.type == 8 and frame.len > 100 this filter on the ICMP requests and focus on the frame length over 100<br>

<img src= "https://github.com/NickHoward1/Data-Exfiltration-/blob/011afd419d1aa86ad34c86798314e180496c81e8/Screenshot%202026-06-05%20at%2010.25.39.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

<h2>Findings</h2>

Flags packets with unusually large payloads. Normal pings are ~74 bytes total. Anything over 100 is suspicious.

<h2>Indicators of Compromise</h2>

<ul>
  <li>Packets that show large payloads</li>
  <li>Echo Pings over 70 bytes</li>
</ul>

<h2>MITRE ATT&CK Mapping</h2>

 T1048 – Exfiltration Over Alternative Protocol
 TA0010 – Exfiltration

<h2>Recommendations</h2>
Escalate the incident in accordance with incident response procedures.<br>
Block communication to the malicious IP address.<br>
Isolate affected endpoints if compromise is suspected.<br>
Investigate the originating process responsible for generating ICMP traffic.<br>
Conduct malware and endpoint analysis.<br>
Document findings and support remediation activities.<br>

<h2>Lessons Learned</h2>

After carrying out the investigation in Wireshark i spotted large payloads using the ICMP protocol using echo ping request. This is an indicatior that data is being exfiltrated. 

<h2>Indicators of attack</h2> 

<h3>Indicators of attack in Wireshark</h3> 

<ul>
<li>CMP packet volumes: a single host sending many ICMP echo requests to an external IP.</li>
<li>Large frame.len or icmp.payload: pings with payloads much larger than typical (e.g., > 64 bytes).</li>
<li>ICMP type/code unusual values: e.g., unusual use of timestamp(13/14) or custom codes.</li>
<li>Regular timing (periodicity): evenly spaced ICMP packets carrying similar-sized payloads.</li>
<li>Fragments with reassembly: multiple ICMP fragments from the same src/dst pair.</li>
</ul>

<b>How adversaries use ICMP for exfiltration</b>

Common techniques:

ICMP echo (type 8) / reply (type 0) tunneling: attackers place encoded (base64, hex) chunks of files inside ICMP payloads. <br>
The remote server collects and decodes them.<br>
Custom ICMP types/codes: using uncommon ICMP types or non-zero codes to avoid signature-based detections. <br>
Fragmentation and reassembly: large payloads are split across multiple packets.<br>
Encryption/obfuscation: Encrypting or encrypting payloads (base64 is common) to look like random data.<br>

Indicators that something may be malicious:

Persistent ICMP sessions to an external host not used for legitimate monitoring.<br>
Unusually large ICMP payloads or frequent ICMP with payload > typical ping size.<br>
ICMP payloads that contain high-entropy data or patterns consistent with base64/hex.<br>
Bursts of ICMP are immediately followed by no other legitimate application traffic from the same host.<br>






<h1>Data Exfiltration Through HTTP</h1>

<h2>Objective</h2>
Investigate suspicious HTTP traffic to determine whether sensitive data is being exfiltrated from the network through HTTP communications. Identify the affected host, destination server, transferred data, and assess the potential impact to the organisation. Determine whether the activity is legitimate business traffic or malicious data exfiltration.

<h2>Scenario</h2>
Suspicious outbound HTTP traffic has been detected between an internal host and an external web server. Analysis indicates a large volume of data being transferred over HTTP, which may represent unauthorised data exfiltration.

<h2>Tools Used</h2>
<ul>
  <li>Wireshark</li>
  <li>Splunk</li>
  <li>Packet Capture (PCAP)</li>
  <li>Threat Hunting Methodology</li>
</ul>

<h2>Investigation Process</h2>

Step 1 - Check logs for suspicious activity in Splunk

Filter1: `index="data_exfil" sourcetype="http_logs"` this searches for the logs that were ingested into Splunk for this project. <br>
Filter2: `index="data_exfil" sourcetype="http_logs" method=POST` <br>
Filter3: `index="data_exfil" sourcetype="http_logs" method=POST | stats count avg(bytes_sent) max(bytes_sent) min(bytes_sent) by domain | sort - count`<br>
Filter4: `index="data_exfil" sourcetype="http_logs" method=POST bytes_sent > 600 | table _time src_ip uri domain dst_ip bytes_sent | sort - bytes_sent`<br>

<img src= "https://github.com/NickHoward1/Data-Exfiltration-/blob/e1f45244c17ddd621f950c68866231baf10468dd/Screenshot%202026-06-05%20at%2008.35.53.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; 

Step 2 - Check for suspicious network traffic in Wireshark

Filter1: `http`<br>
Filter2: `http.request.method == "POST"`<br>
Filter3: `http.request.method == "POST" and frame.len > 500` This bring back POST requests and frames larger than 500, there was to much noise over 1600 packets displayed so to reduce this I increased the frame size to 750<br>
Filter4: `http.request.method == "POST" and frame.len > 750` This brought back one packet, after following the process of `packet - follow - HTTP stream` gave me the info on data that has been exfiltrated which is the (Internal Access Credentials - Finance Department)<br>

<img src= "https://github.com/NickHoward1/Data-Exfiltration-/blob/298c5dea94192c5308686fd1aacc7ed6799400be/Screenshot%202026-06-05%20at%2007.36.54.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; <img src= "https://github.com/NickHoward1/Data-Exfiltration-/blob/e5cc6ab5a20eaa6dc8c695bfe91f934d2e7522f5/Screenshot%202026-06-05%20at%2007.39.43.png" width="300" height="300"/> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;

<h2>Findings</h2>

After checking the network traffic and logs in Splunk, it is clear that data has been exfiltrated, this was disguised via HTTP through POST requests, we had to filter out the noise and benign activity to get find the right packet containing the Finance Department credentials. 

<h2>Indicators of Compromise</h2>

<ul>
  <li>Unusually large HTTP POST requests to external/unexpected hosts.</li>
  <li><Large bytes being sent over the network/li>
</ul>

<h2>MITRE ATT&CK Mapping</h2>

TA0010 – Exfiltration<br>
T1041 – Exfiltration Over C2 Channel<br>
T1071.001 – Application Layer Protocol: Web Protocols

<h2>Recommendations</h2>

Escalate the incident in accordance with incident response procedures.<br>
Block the malicious domain or IP address if confirmed malicious.<br>
Isolate affected endpoints if compromise is suspected.<br>
Investigate for malware, web shells, or unauthorised tools.<br>
Reset compromised credentials if required.<br>
Document findings and support remediation and recovery efforts.<br>

<h2>Lessons Learned</h2>

This investigation improved my knowledge on how attackers abuse the HTTP protocol to disguise and exfiltrate data. During the investigation, I learned how to identify indicators of data exfiltration by analysing HTTP requests, reviewing outbound network connections, and investigating large volumes of data being transferred to external destinations. I also gained experience using Wireshark filters to isolate suspicious HTTP traffic and distinguish legitimate business communications from potentially malicious activity.

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
