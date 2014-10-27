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

---
title: Scan Report


Summary
=======

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

  --------------- ------------------------------
  Scan started:   **Mon Oct 27 02:13:47 2014**
  Scan ended:     Mon Oct 27 03:05:42 2014
  --------------- ------------------------------

Host Summary
------------

  --------- --------- --------- --------- --------- --------- --------- ---------
  Host      Start     End       High      Medium    Low       Log       False
                                                                        Positive

  [192.168. Oct 27,   Oct 27,   1         1         0         0         0
  248.129]( 02:14:02  02:58:57                                          
  #192.168.                                                             
  248.129)                                                              

  Total: 1                      1         1         0         0         0
  --------- --------- --------- --------- --------- --------- --------- ---------

Results per Host
================

Host 192.168.248.129 {#192.168.248.129}
--------------------

  ----------------------------------- ----------------------
  Scanning of this host started at:   2014-10-27T02:14:02Z
  Number of results:                  2
  ----------------------------------- ----------------------

### Port Summary for Host 192.168.248.129

  ---------------- --------------
  Service (Port)   Threat Level
  general/tcp      Medium
  http (80/tcp)    High
  ---------------- --------------

### Security Issues for Host 192.168.248.129


**Medium** (CVSS: 2.6)

NVT: TCP timestamps (OID: 1.3.6.1.4.1.25623.1.0.80091)

It was detected that the host implements RFC1323.
                                                                                                                                                                                                                           The following timestamps were retrieved with a delay of 1 seconds in-between:
                                                                                                                                                                                                                           Paket 1: 1776245
                                                                                                                                                                                                                           Paket 2: 1776498
                                                                                                                                                                                                                           

**References**\
Other:
URL:http://www.ietf.org/rfc/rfc1323.txt

http (80/tcp)

**High** (CVSS: 7.5)

NVT: Lighttpd Mul

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
