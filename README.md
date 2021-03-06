![alt tag](https://raw.githubusercontent.com/lateralblast/osse/master/osse.png)

> A spirit of the sea in the service of Ulmo, Ossë guarded the waters around Middle-earth.

OSSE
====

Oracle Solaris Simple Explorer

Introduction
------------

A simple Perl script to check Oracle Solaris Explorer files for specific values.
Useful for auditing purposes where you have access to Explorer files but not the systems.
Output can be done as HTML.

This doesn't have much functionality at the moment, it's just an example.

License
-------

This software is licensed as CC-BA (Creative Commons By Attrbution)

http://creativecommons.org/licenses/by/4.0/legalcode

Usage
-----

```
$ osse.pl -[hABEHJPRSVZc:f:m:o:s:]

-V: Print version information
-h: Print help
-J: Report which machines have JASS installed
-P: Report which machines have Puppet installed
-B: Report which machines have BSM enabled
-K: Report which machines have Kerberos enabled
-R: Report which machines have RSA SecurID PAM agent installed
-E: Report which machines have Explorer installed
-S: Run security check against explorers
-Z: Run services check against explorers
-z: Show status of Zones
-A: Output individual reports for each explorer/client
-H: Generate HTML report
-s: String based search
-f: Explorer file to search
-c: Explorer client to search (by default all explorers are processed)
-m: Message to display (e.g. Installed/Enabled)
-o: Output to file rather than STDOUT
```

Examples
--------

Ouput which machines have SUNWjass installed:

```
$ osse.pl -J
host01: SUNWjass Not Installed
host02: SUNWjass Not Installed
host03: SUNWjass Installed
host04: SUNWjass Not Installed
```

Ouput which machine have SUNWjass installed in HTML to a file:

```
$ osse.pl -J -H -o jass.html
```

A Generic search of "/etc/pam.conf" for "krb5.so.1"

```
$ osse.pl -s "krb5.so.1" -f "/etc/pam.conf"
```

