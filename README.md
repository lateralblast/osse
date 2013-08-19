expcheck
========

A simple Perl script to check Oracle Solaris Explorer files for specific values.
Useful for auditing purposes where you have access to Explorer files but not the systems.
Output can be done as HTML.

This doesn't have much functionality at the moment, it's just an example.

Usage
=====

	$ expcheck.pl -[hBHJPRSVc:f:m:o:s:]

	-V: Print version information
	-h: Print help
	-J: Report which machines have JASS installed
	-P: Report which machines have Puppet installed
	-B: Report which machines have BSM enabled
	-K: Report which machines have Kerberos enabled
	-R: Report which machines have RSA SecurID PAM agent installed
	-S: Run security check against explorers
	-H: Generate HTML report
	-s: String based search
	-f: Explorer file to search
	-c: Explorer client to search (by default all explorers are processed)
	-m: Message to display (e.g. Installed/Enabled)
	-o: Output to file rather than STDOUT

Examples:
=========

Ouput which machines have SUNWjass installed:

	$ expcheck.pl -J
	host01: SUNWjass Not Installed
	host02: SUNWjass Not Installed
	host03: SUNWjass Installed
	host04: SUNWjass Not Installed

Ouput which machine have SUNWjass installed in HTML to a file:

	$ expcheck -J -H -o jass.html

A Generic search of "/etc/pam.conf" for "krb5.so.1"

	$ expcheck -s "krb5.so.1" -f "/etc/pam.conf"

