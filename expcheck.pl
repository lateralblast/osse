#!/usr/bin/env perl

use strict;
use HTML::Template;
use Getopt::Std;
use File::Basename;

# Name:         expcheck.pl
# Version:      0.0.9
# Release:      1
# License:      Open Source 
# Group:        System
# Source:       Lateral Blast
# URL:          N/A
# Distribution: Solaris
# Vendor:       UNIX
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  Script to generate report on status of various systems via explorer

# Changes       0.0.1
#               Initial version
#               0.0.2 Sun 18 Aug 2013 10:31:30 EST
#               Initial package reporting
#               0.0.3 Sun 18 Aug 2013 11:12:39 EST
#               Cleaned up template creation
#               0.0.4 Sun 18 Aug 2013 11:37:58 EST
#               Updated getopts code
#               0.0.5 Mon 19 Aug 2013 06:20:58 EST
#               Added RSA, BSM and Puppet tests
#               0.0.6 Mon 19 Aug 2013 08:38:07 EST
#               Added Kerberos and individual explorer file support
#               0.0.7 Mon 19 Aug 2013 08:57:22 EST
#               Added check to make sure host isn't duplicated (old explorers)
#               0.0.8 Mon 19 Aug 2013 10:21:21 EST
#               Converted search to array to avoid multiple file opens of the same file
#               0.0.9 Mon 19 Aug 2013 11:26:26 EST
#               Added initial security check

my $script_name=$0;
my $script_version=`cat $script_name | grep '^# Version' |awk '{print \$3}'`;
my $explorer_dir="explorers";
my %option=();
my $options="hBHJPRSVc:f:m:o:s:";

if ($#ARGV == -1) {
  print_usage();
}
else {
  getopts($options,\%option);
}

# If given -h print usage

if ($option{'h'}) {
  print_usage();
  exit;
}

sub print_version {
  print "$script_version";
  return;
}

# Print script version

if ($option{'V'}) {
  print_version();
  exit;
}

# Print usage

sub print_usage {
  print "\n";
  print "Usage: $script_name -[$options]\n";
  print "\n";
  print "-V: Print version information\n";
  print "-h: Print help\n";
  print "-J: Report which machines have JASS installed\n";
  print "-P: Report which machines have Puppet installed\n";
  print "-B: Report which machines have BSM enabled\n";
  print "-K: Report which machines have Kerberos enabled\n";
  print "-R: Report which machines have RSA SecurID PAM agent installed\n";
  print "-S: Run security check against explorers\n";
  print "-H: Generate HTML report\n";
  print "-s: String based search\n";
  print "-f: Explorer file to search\n";
  print "-c: Explorer client to search (by default all explorers are processed)\n";
  print "-m: Message to display (e.g. Installed/Enabled)\n";
  print "-o: Output to file rather than STDOUT\n";
  print "\n";
  return;
}

if ($option{'s'}) {
  if (!$option{'f'}) {
    print "File to search within Explorer must be specified\n";
    exit;
  }
  if (!$option{'m'}) {
    $option{'m'}="Installed/Enabled"
  }
  search_explorers($option{'f'},$option{'s'},$option{'m'},$option{'c'});
}

if ($option{'S'}) {
  security_check($option{'c'});
  exit;
}

if ($option{'K'}) {
  krb_status($option{'c'});
  exit;
}

if ($option{'R'}) {
  rsa_status($option{'c'});
  exit;
}

if ($option{'B'}) {
  bsm_status($option{'c'});
  exit;
}

if ($option{'J'}) {
  jass_status($option{'c'});
  exit;
}

if ($option{'P'}) {
  puppet_status($option{'c'});
  exit;
}

sub security_check {
  my $search_client=$_[0];
  my $search_message="Set";
  my $search_string;
  my $search_file;
  $search_string="^DISABLETIME=3600,^SYSLOG=YES,^SYSLOG_FAILED_LOGINS=0";
  $search_file="etc/default/login";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string="^MAXWEEKS=48,^MAXREPEATS=0";
  $search_file="etc/default/passwd";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string="^ENABLE_NOBODY_KEYS=YES";
  $search_file="etc/default/keyserv";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string="^TCP_STRONG_ISS=2";
  $search_file="etc/default/inetinit";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string="^PMCHANGEPERM=-,^CPRCHANGEPERM=-";
  $search_file="etc/default/power";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string="^PERMS=-";
  $search_file="etc/default/sys-suspend";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string="^LOG_FOR_REMOTE=NO";
  $search_file="etc/default/syslogd";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string="^BANNER=\"Authorized Use Only\"";
  $search_file="etc/default/telnetd";
  search_explorers($search_file,$search_string,$search_message,$search_client);
}

sub create_template {
  my $html=do { local $/; <DATA> };
  my $template=HTML::Template->new(
    scalarref         => \$html,
    loop_context_vars => 1,
  );
  return($template);
}

sub get_explorer_list {
  my $search_client=$_[0];
  my @explorer_list;
  if ($search_client=~/[a-z]/) {
    chomp($search_client);
    @explorer_list=`find $explorer_dir -name "*exp*$search_client*.gz" |sort -rn |uniq`;
  }
  else {
    @explorer_list=`find $explorer_dir -name "*exp*.gz" |sort -rn |uniq`;

  }
  return(@explorer_list);
}

sub krb_status {
  my $search_client=$_[0];
  my $search_string="other[[:space:]]*auth[[:space:]]*sufficient[[:space:]]*pam_krb5.so.1";
  my $search_file="etc/pam.conf";
  my $search_message="Installed";
  search_explorers($search_file,$search_string,$search_message,$search_client);
}

sub jass_status {
  my $search_client=$_[0];
  my $search_string="SUNWjass";
  my $search_file="patch+pkg/pkginfo-l.out";
  my $search_message="Installed";
  search_explorers($search_file,$search_string,$search_message,$search_client);
}

sub puppet_status {
  my $search_client=$_[0];
  my $search_string="puppet";
  my $search_file="patch+pkg/pkginfo-l.out";
  my $search_message="Installed";
  search_explorers($search_file,$search_string,$search_message,$search_client);
}

sub bsm_status {
  my $search_client=$_[0];
  my $search_string="audit";
  my $search_file="etc/system";
  my $search_message="Enabled";
  search_explorers($search_file,$search_string,$search_message,$search_client);
}

sub rsa_status {
  my $search_client=$_[0];
  my $search_string="securid";
  my $search_file="etc/pam.conf";
  my $search_message="Enabled";
  search_explorers($search_file,$search_string,$search_message,$search_client);
}

sub search_explorers {
  my $search_file=$_[0];
  my $search_string=$_[1];
  my $search_message=$_[2];
  my $search_client=$_[3];
  my @explorer_list=get_explorer_list($search_client);
  my @search_string;
  my @host_list;
  my $hostname;
  my $pkg_file;
  my $explorer;
  my $filename;
  my @line;
  my $year;
  my @loop;
  my @pkg_info;
  my $pkg_test;
  my $command;
  my $template;
  my $output_file;
  if ($search_string=~/\,/) {
    @search_string=split(",",$search_string);
  }
  else {
    @search_string[0]=$search_string; 
  }
  $search_string="";
  $search_file=~s/^\///g;
  if ($option{'H'}) {
    $template=create_template();
  }
  if ($option{'o'}) {
    $output_file=$option{'o'};
    open(FILE,">$output_file"); 
  }
  foreach $explorer (@explorer_list) {
    chomp($explorer);
    @line=split(/\./,$explorer);
    $hostname=@line[2];
    ($hostname,$year)=split("-",$hostname);
    ($hostname,$year)=split(/\-/,$hostname);
    $filename=basename($explorer,".tar.gz");
    $filename="$filename/$search_file";
    $command="gtar -xpzf $explorer $filename -O";
    @pkg_info=`$command`;
    if (!grep /$hostname/,@host_list) {
      foreach $search_string (@search_string) {
        if (grep /$search_string/,@pkg_info) {
          $search_string=~s/^\^//g;
          if ($option{'H'}) {
            my %row=(hostname=>"$hostname", value=>"<font color=\"green\">$search_string $search_message</font>");
            push(@loop,\%row);
          }
          else {
            if ($option{'o'}) {
              print FILE "$hostname: $search_string $search_message\n";
            }
            else {
              print "$hostname: $search_string $search_message\n";
            }
          }
        }
        else {
          $search_string=~s/^\^//g;
          if ($option{'H'}) {
            my %row=(hostname=>"$hostname", value=>"<font color=\"red\">$search_string Not $search_message</font>");
            push(@loop,\%row);
          }
          else {
            if ($option{'o'}) {
              print FILE "$hostname: $search_string Not $search_message\n";
            }
            else {
              print "$hostname: $search_string Not $search_message\n";
            }
          }
        }
      }
      push(@host_list,$hostname);
    }
  }
  if ($option{'H'}) {
    $template->param(explorer_data => \@loop);
    if ($option{'o'}) {
      print FILE $template->output();
    }
    else {
      print $template->output();
    }
  }
  return;
}

__DATA__
<HTML>
  <HEAD>
    <TITLE>Explorer Data</TITLE>
  </HEAD>
  <BODY>
    <H1>Host Information</H1>
      <TABLE BORDER=1>
        <TR>
          <TD><B>Hostname</B></TD><TD><B>Information</B></TD>
        </TR>
      <TMPL_LOOP NAME="explorer_data">
        <TR>
          <TD><TMPL_VAR NAME="hostname"></TD><TD><TMPL_VAR NAME="value"></TD>
        </TR>
      </TMPL_LOOP>
    </TABLE>
  </BODY>
</HTML>