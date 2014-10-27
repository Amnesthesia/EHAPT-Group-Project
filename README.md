EHAPT-Group-Project
===================


# OpenBSD 4.x
---------

## Services & Ports

| Port | Protocol | Service 		|
|:----:|:--------:|-------------|
|13		 | tcp			|	daytime 		|
|22		 | tcp			| OpenSSH 5.6 |
|37		 | tcp			|  time(32bit)|
|113	 | tcp			| ident				|

# Ubuntu 10.04.3
---------

## Services & Ports

| Port | Protocol | Service 		|
|:----:|:--------:|-------------|
|23		 | tcp			|	telnetd 		|
|80		 | tcp			| lighttpd 1.4.26 |


## Scan Report (OpenVAS)

This document reports on the results of an automatic security scan. The
report first summarises the results found. Then, for each host, the
report describes every issue found. Please consider the advice given in
each description, in order to rectify the issue.

Vendor security updates are not trusted.

Overrides are off. Even when a result has an override, this report uses
the actual threat of the result.

Notes are included in the report.

This report might not show details of all issues that were found. It
only lists hosts that produced issues. It shows issues that contain the
search phrase "192.168.248.129". Issues with the threat level "Low" are
not shown. Issues with the threat level "Log" are not shown. Issues with
the threat level "Debug" are not shown. Issues with the threat level
"False Positive" are not shown.

This report contains all 2 results selected by the filtering described
above. Before filtering there were 77 results.

--------------- 
Scan started:   **Mon Oct 27 02:13:47 2014**

Scan ended:     **Mon Oct 27 03:05:42 2014**
---------------

### Host Summary
------------

| Host            |  Start  				 |  End      		    |  High   |  Medium |  Low    |  Log    | False Positive |
|:---------------:|:----------------:|:----------------:|:-------:|:-------:|:-------:|:-------:|:--------------:|
|192.168.248.129  |Oct 27, (02:14:02)|Oct 27, (02:58:57)|  1      |   1     |    0    |     0   |      0				 |
|									|									 |									|					|					|					|					|								 |
|Total: 1					|									 |                  |  1      |   1     |    0    |     0   |      0         |
-------------------


### Port Summary for Host 192.168.248.129


| Service (Port) |  Threat Level |
|:---------------|---------------|
|  general/tcp   | Medium				 |
|  http (80/tcp) | High          |



### Security Issues for Host 192.168.248.129
----------------------------------------

| Issue | Info														|
|:------|:--------------------------------|
|NVT:   | TCP timestamps
|OID:    |1.3.6.1.4.1.25623.1.0.80091
|Threat: |Medium (CVSS: 2.6)
|Port:   |general/tcp

|**Description**|
|:--------------|
|It was detected that the host implements RFC1323.|
|The following timestamps were retrieved with a delay of 1 seconds in-between:|
|Paket 1: 1776245 |
|Paket 2: 1776498 |

<table>
	<tr>
		<th colspan="2">References</th>
	</tr>
	<tr><td>URL:</td><td> http://www.ietf.org/rfc/rfc1323.txt</td></tr>
</table>

---------------------


| Issue | Info														|
|:------|:--------------------------------|
|NVT:   | Lighttpd Multiple vulnerabilities|
|OID:   | 1.3.6.1.4.1.25623.1.0.802072 		|
|Threat:| High (CVSS: 7.5)								|
|Port:  | http (80/tcp)										|

<table>
	<tr>
		<th colspan="2">References</th>
	</tr>
	<tr><td>CVE:</td><td> CVE-2014-2323,CVE-2014-2324</td></tr>
	<tr><td>BID:</td><td> 66153,66157</td></tr>
	<tr><td>URL:</td><td> http://osvdb.org/104381</td></tr>
	<tr><td>URL:</td><td> http://osvdb.org/104382</td></tr>
	<tr><td>URL:</td><td> http://seclists.org/oss-sec/2014/q1/561</td></tr>
	<tr><td>URL:</td><td> http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2014_01.txt</td></tr>
</table>




# Windows Vista Business (build 6000)
---------

## Services & Ports

| Port | Protocol | Service 		|
|:----:|:--------:|-------------|
|135		 | tcp			|	msrpc 		|
|139		 | tcp			| netbios-ssn |
|445		 | tcp			| netbios-ssn |
|49152		 | tcp			|	msrpc 		|
|49153		 | tcp			|	msrpc 		|
|49154		 | tcp			|	msrpc 		|
|49155		 | tcp			|	msrpc 		|
|49156		 | tcp			|	msrpc 		|
|49157		 | tcp			|	msrpc 		|

## Scan Results (OpenVAS)
This document reports on the results of an automatic security scan.
The report first summarises the results found.
Then, for each host, the report describes every issue found.
Please consider the advice given in each description, in order to rectify
the issue.

Vendor security updates are not trusted.

Overrides are off.  Even when a result has an override, this report uses
the actual threat of the result.

Notes are included in the report.

This report might not show details of all issues that were found.
It only lists hosts that produced issues.
It shows issues that contain the search phrase "192.168.248.131".
Issues with the threat level "Low" are not shown.
Issues with the threat level "Log" are not shown.
Issues with the threat level "Debug" are not shown.
Issues with the threat level "False Positive" are not shown.

This report contains all 5 results selected by the
filtering described above.  Before filtering there were 77 results.

-----------
Scan started: **Mon Oct 27 02:13:47 2014 UTC**

Scan ended:   **Mon Oct 27 03:05:42 2014 UTC**
-----------

### Host Summary
------------

| Host            |  Start  				 |  End      		    |  High   |  Medium |  Low    |  Log    | False Positive |
|:---------------:|:----------------:|:----------------:|:-------:|:-------:|:-------:|:-------:|:--------------:|
|192.168.248.131  |Oct 27, (02:13:47)|Oct 27, (03:05:42)|  1      |   4     |    0    |     0   |      0				 |
|									|									 |									|					|					|					|					|								 |
|Total: 1					|									 |                  |  1      |   4     |    0    |     0   |      0         |
-------------------


### Security Issues for Host 192.168.248.131
----------------------------------------


|Issue | Info |
|:-----|:-----|
|NVT:  |  DCE Services Enumeration |
|OID:  |  1.3.6.1.4.1.25623.1.0.10736|
|Threat:| Medium (CVSS: 5.0)|
|Port: |  epmap (135/tcp)|

|**Description:**|
|:---------------|
|Distributed Computing Environment (DCE) services running on the remote host <br>can be enumerated by connecting on port 135 and doing the appropriate queries. <br> An attacker may use this fact to gain more knowledge <br>about the remote host.
|**Solution:** |
|Filter incoming traffic to this port.|


|Issue| Info|
|:----|:----|
|NVT: |   DCE Services Enumeration|
|OID: |   1.3.6.1.4.1.25623.1.0.10736|
|Threat:| Medium (CVSS: 5.0)|
|Port: |  epmap (135/tcp)|

<table>
<tr><th colspan="2">Description:</th></tr>
<tr><td colspan="2">Distributed Computing Environment (DCE) services running on the remote host
can be enumerated by connecting on port 135 and doing the appropriate queries.
An attacker may use this fact to gain more knowledge
about the remote host.</td></tr>
<tr><td colspan="2">Here is the list of DCE services running on this host:</td></tr>
<tr>
	<td>Port:</td> <td>49152/tcp</td>
</tr>
<tr>
	<td></td>
	<td><table><tr>
		<td>UUID:</td><td>d95afe70-a6d5-4259-822e-2c84da1ddb0d, version 1</td>
    <td>Endpoint:</td><td>ncacn_ip_tcp:192.168.248.131[49152]</td>
	</tr></table></td>
</tr>

<tr>
	<td>Port:</td> <td>49153/tcp</td>
</tr>
<tr>
	<td></td>
	<td><table>
		<tr><td>UUID:</td><td>f6beaff7-1e19-4fbb-9f8f-b89e2018337c, version 1</td></tr>
    <tr><td>Endpoint:</td><td>ncacn_ip_tcp:192.168.248.131[49153]</td></tr>
		<tr><td>Annotation:</td><td>Event log TCPIP</td></tr>
		
		<tr><td>UUID:</td><td>3c4728c5-f0ab-448b-bda1-6ce01eb0a6d5, version 1</td></tr>
    <tr><td>Endpoint:</td><td>ncacn_ip_tcp:192.168.248.131[49153]</td></tr>
		<tr><td>Annotation:</td><td>DHCP Client LRPC Endpoint</td></tr>

		<tr><td>UUID:</td><td>3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6, version 1</td></tr>
    <tr><td>Endpoint:</td><td>ncacn_ip_tcp:192.168.248.131[49153]</td></tr>
		<td>Annotation:</td><td>DHCPv6 Client LRPC Endpoint</td></tr>

		<tr><td>UUID:</td><td>3c4728c5-f0ab-448b-bda1-6ce01eb0a6d6, version 1</td></tr>
    <tr><td>Endpoint:</td><td>ncacn_ip_tcp:192.168.248.131[49153]</td></tr>
		<tr><td>Annotation:</td><td>DHCPv6 Client LRPC Endpoint</td></tr>

		<tr><td>UUID:</td><td>06bba54a-be05-49f9-b0a0-30f790261023, version 1</td></tr>
    <tr><td>Endpoint:</td><td>ncacn_ip_tcp:192.168.248.131[49153]</td></tr>
		<tr><td>Annotation:</td><td>Security Center</td></tr>
	</table></td>
</tr>

<tr>
	<td>Port:</td> <td>49154/tcp</td>
</tr>
<tr>
	<td></td>
	<td><table>
		<tr><td>UUID:</td><td>7ea70bcf-48af-4f6a-8968-6a440754d5fa, version 1</td></tr>
    <tr><td>Endpoint:</td><td>ncacn_ip_tcp:192.168.248.131[49154]</td></tr>
		<tr><td>Annotation:</td><td>NSI server endpoint</td></tr>
		
		<tr><td>UUID:</td><td>4b112204-0e19-11d3-b42b-0000f81feb9f, version 1</td></tr>
    <tr><td>Endpoint:</td><td>ncacn_ip_tcp:192.168.248.131[49154]</td></tr>
		<tr><td>Named pipe:</td><td>ssdpsrv</td></tr>
		<tr><td>Win32 service/process:</td><td>ssdpsrv</td></tr>
		<tr><td>Description:</td><td>SSDP service</td></tr>

	</table></td>
</tr>

<tr>
	<td>Port:</td> <td>49155/tcp</td>
</tr>
<tr>
	<td></td>
	<td><table>
		<tr><td>UUID:</td><td>86d35949-83c9-4044-b424-db363231fd0c, version 1</td></tr>
    <tr><td>Endpoint:</td><td>ncacn_ip_tcp:192.168.248.131[49155]</td></tr>
		
		
		<tr><td>UUID:</td><td>a398e520-d59a-4bdd-aa7a-3c1e0303a511, version 1</td></tr>
    <tr><td>Endpoint:</td><td>ncacn_ip_tcp:192.168.248.131[49155]</td></tr>
		<tr><td>Annotation:</td><td>IKE/Authip API</td></tr>

	</table></td>
</tr>

<tr>
	<td>Port:</td> <td>49156/tcp</td>
</tr>
<tr>
	<td></td>
	<td><table>
		<tr><td>UUID:</td><td>12345778-1234-abcd-ef00-0123456789ac, version 1</td></tr>
    <tr><td>Endpoint:</td><td>ncacn_ip_tcp:192.168.248.131[49156]</td></tr>
		<tr><td>Named pipe:</td><td>lsass</td></tr>
		<tr><td>Win32 service/process:</td><td>lsass.exe</td></tr>
		<tr><td>Description:</td><td>SAM access</td></tr>

	</table></td>
</tr>

<tr>
	<td>Port:</td> <td>49157/tcp</td>
</tr>
<tr>
	<td></td>
	<td><table>
		<tr><td>UUID:</td><td>367abb81-9844-35f1-ad32-98f038001003, version 2</td></tr>
    <tr><td>Endpoint:</td><td>ncacn_ip_tcp:192.168.248.131[49157]</td></tr>

	</table></td>
</tr>
<tr>
<th>Solution:</th><td>Filter incoming traffic to these ports</td>
</tr>
</table>

----------------------------------------

|Issue| Info|
|:----|:----|
|NVT: | Source routed packets |
|OID: | 1.3.6.1.4.1.25623.1.0.11834 |
|Threat:| Medium (CVSS: 3.3) |
|Port:| general/tcp |

|**Description:**|
|:---------------|
|The remote host accepts loose source routed IP packets. |
|The feature was designed for testing purpose. |
|An attacker may use it to circumvent poorly designed IP filtering and exploit another flaw.|
| However, it is not dangerous by itself.|

|**Solution:**|
|:------------|
|Drop source routed packets on this host or on other ingress routers or firewalls.|


--------------------------------


|Issue| Info|
|:----|:----|
|NVT: |   TCP timestamps|
|OID: |   1.3.6.1.4.1.25623.1.0.80091|
|Threat:| Medium (CVSS: 2.6) |
|Port: |  general/tcp |

|**Description:**|
|:---------------|
|It was detected that the host implements RFC1323.|
|The following timestamps were retrieved with a delay of 1 seconds in-between:|
|Paket 1: 831744|
|Paket 2: 831845|

<table>
	<tr>
		<th colspan="2">References</th>
	</tr>
	<tr><td>URL:</td><td> http://www.ietf.org/rfc/rfc1323.txt</td></tr>
</table>

------------------------------

|Issue| Info|
|:----|:----|
|NVT: |   Microsoft Windows SMB Server NTLM Multiple Vulnerabilities (971468)|
|OID: |   1.3.6.1.4.1.25623.1.0.902269|
|Threat:| High (CVSS: 10.0)|
|Port:|   microsoft-ds (445/tcp)|

|**Description:**|
|:---------------|
|This host is missing a critical security update according to Microsoft Bulletin MS10-012.|
|**Vulnerability Insight:**|
|<ul><li> An input validation error exists while processing SMB requests and can<br>be exploited to cause a buffer overflow via a specially crafted SMB packet.</li><li> An error exists in the SMB implementation while parsing SMB packets during<br>the Negotiate phase causing memory corruption via a specially crafted SMB<br>packet.</li><li> NULL pointer dereference error exists in SMB while verifying the 'share'<br>and 'servername' fields in SMB packets causing denial of service.</li><li> A lack of cryptographic entropy when the SMB server generates challenges<br>during SMB NTLM authentication and can be exploited to bypass the<br>authentication mechanism.</li>|
|**Impact:**|
| Successful exploitation will allow remote attackers to execute arbitrary<br>code or cause a denial of service or bypass the authentication mechanism<br>via brute force technique.|
|**Impact Level:** System/Application|
| Affected Software/OS: <br><ul><li>Microsoft Windows 7 </li><li>Microsoft Windows 2000 Service Pack and prior</li><li>Microsoft Windows XP Service Pack 3 and prior</li><li>Microsoft Windows Vista Service Pack 2 and prior</li><li>Microsoft Windows Server 2003 Service Pack 2 and prior</li><li>Microsoft Windows Server 2008 Service Pack 2 and prior</li>
|**Solution:**|
| Run Windows Update and update the listed hotfixes or download and<br>update mentioned hotfixes in the advisory from the below link,<br>http://www.microsoft.com/technet/security/bulletin/ms10-012.mspx|

<table>
	<tr>
		<th colspan="2">References</th>
	</tr>
	<tr><td>CVE:</td><td> CVE-2010-0020,CVE-2010-0021,CVE-2010-0022,CVE-2010-0231</td>
  <tr><td>URL:</td><td>http://secunia.com/advisories/38510/</td></tr>
  <tr><td>URL:</td><td>http://support.microsoft.com/kb/971468</td></tr>
  <tr><td>URL:</td><td>http://www.vupen.com/english/advisories/2010/0345</td></tr>
  <tr><td>URL:</td><td>http://www.microsoft.com/technet/security/bulletin/ms10-012.mspx</td></tr>
</table>
