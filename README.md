expcheck
========

A simple Perl script to check Oracle Solaris Explorer files for specific values.
Useful for auditing purposes where you have access to Explorer files but not the systems.
Output can be done as HTML.

This doesn't have much functionality at the moment, it's just an example.

Usage
=====

	$ expcheck.pl -[hVJHo:]

	-V: Print version information
	-h: Print help
	-J: Report which machines have JASS installed
	-H: Generate HTML report
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
