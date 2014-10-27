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
It shows issues that contain the search phrase "192.168.248.129".
Issues with the threat level "Low" are not shown.
Issues with the threat level "Log" are not shown.
Issues with the threat level "Debug" are not shown.
Issues with the threat level "False Positive" are not shown.

This report contains all 2 results selected by the
filtering described above.  Before filtering there were 77 results.

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

|**References:**|
|:--------------|
|URL: http://www.ietf.org/rfc/rfc1323.txt|


| Issue | Info														|
|:------|:--------------------------------|
|NVT:   | Lighttpd Multiple vulnerabilities|
|OID:   | 1.3.6.1.4.1.25623.1.0.802072 		|
|Threat:| High (CVSS: 7.5)								|
|Port:  | http (80/tcp)										|

|**References:**|
|:--------------|:--|
|CVE:| CVE-2014-2323,CVE-2014-2324|
|BID:| 66153,66157 |
|URL:| http://osvdb.org/104381|
|URL:| http://osvdb.org/104382|
|URL:| http://seclists.org/oss-sec/2014/q1/561]|
|URL:| http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2014_01.txt|




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
