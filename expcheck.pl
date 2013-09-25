#!/usr/bin/env perl

use strict;
use HTML::Template;
use Getopt::Std;
use File::Basename;

# Name:         expcheck.pl
# Version:      0.2.5
# Release:      1
# License:      Open Source 
# Group:        System
# Source:       Lateral Blast
# URL:          N/A
# Distribution: Solaris
# Vendor:       UNIX
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  Script to generate report on status of various systems via explorer

my $script_name=$0;
my $script_version=`cat $script_name | grep '^# Version' |awk '{print \$3}'`;
my $explorer_dir="explorers";
my %option=();
my $options="hvwABCEHJKPRSUVZc:f:m:o:s:";
my @loop;
my $template;
my $html=do { local $/; <DATA> };

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
  print "-E: Report which machines have Explorer installed\n";
  print "-w: Report which machines have file sharing enabled (apache/ftp)\n";
  print "-S: Run security check against explorers\n";
  print "-U: Report which version of sudo is installed\n";
  print "-Z: Run services check against explorers\n";
  print "-A: Output individual reports for each explorer/client\n";
  print "-H: Generate HTML report\n";
  print "-C: Generate CSV report\n";
  print "-s: String based search\n";
  print "-f: Explorer file to search\n";
  print "-c: Explorer client to search (by default all explorers are processed)\n";
  print "-m: Message to display (e.g. Installed/Enabled)\n";
  print "-o: Output to file rather than STDOUT\n";
  print "-v: Verbose mode\n";
  print "\n";
  return;
}

if ($option{'A'}) {
  individual_reports();
  exit; 
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

sub individual_reports {
  my @explorer_list=get_explorer_list(); 
  my $explorer_file;
  my $hostname;
  my $output_file; 
  foreach $explorer_file (@explorer_list) {
    if ($option{'H'}) {
      create_template();
    }
    if ($option{'o'}) {
      $output_file=$option{'o'};
      open(FILE,">$output_file"); 
    }
    $hostname=get_hostname($explorer_file);
    handle_reports($hostname)
  }
}
if (!$option{'A'}) {
  handle_reports($option{'c'});
}

sub handle_reports {
  my $hostname=$_[0];
  my $output_file; 
  if ($option{'H'}) {
    create_template();
  }
  if ($option{'o'}) {
    $output_file=$option{'o'};
    open(FILE,">$output_file"); 
    if ($option{'A'}) {
      $output_file="$hostname\_$output_file"
    }
  }
  if ($option{'E'}) {
    explorer_status($hostname);
  }
  if ($option{'S'}) {
    security_status($hostname);
  }
  if ($option{'K'}) {
    krb_status($hostname);
  }
  if ($option{'R'}) {
    rsa_status($hostname);
  }
  if ($option{'B'}) {
    bsm_status($hostname);
  }
  if ($option{'J'}) {
    jass_status($hostname);
  }
  if ($option{'P'}) {
    puppet_status($hostname);
  }
  if ($option{'U'}) {
    sudo_status($hostname);
  }
  if ($option{'Z'}) {
    services_status($hostname);
  }
  if ($option{'w'}) {
    share_status($hostname);
  }
  if ($option{'H'}) {
    print_template();
  }
  if (!$option{'A'}) {
    exit;
  }
}

sub explorer_status {
  my $search_client=$_[0];
  my $search_message="Installed";
  my $search_string;
  my $search_file;
  $search_string="SUNWexplo";
  $search_file="patch+pkg/pkginfo-l.out";
  $search_message="Installed";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string="/opt/SUNWexplo/bin/explorer";
  $search_file="var/cron/root";
  $search_message="Enabled";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  return;
}

sub sudo_status {
  my $search_client=$_[0];
  my $search_message="Installed";
  my $search_string;
  my $search_file;
  $search_string="sudo";
  $search_file="patch+pkg/pkginfo-l.out";
  $search_message="Installed";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  return;
}

sub services_status {
  my $search_client=$_[0];
  my $search_message;
  my $search_string;
  my $search_file; 
  $search_message="Disabled";
  $search_string ="offline.*svc:/application/management/snmpdx:default";
  $search_file="sysconfig/svcs-av.out";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  return;
}

sub share_status {
  my $search_client=$_[0];
  my $search_message;
  my $search_string;
  my $search_file; 
  $search_message="Enabled";
  $search_string ="online.*svc:/network/http:apache2,";
  $search_string.="online.*svc:/network/ftp:default,";
  $search_string.="online.*svc:/network/samba:default";
  $search_file="sysconfig/svcs-av.out";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  return;
}

sub security_status {
  my $search_client=$_[0];
  my $search_message="Set";
  my $search_string;
  my $search_file;
  $search_string ="^DISABLETIME=3600,^SYSLOG=YES,^SYSLOG_FAILED_LOGINS=0,";
  $search_string.="^UMASK=022,^RETRIES=3,^CONSOLE=/dev/console,^PASSREQ=YES";
  $search_file="etc/default/login";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string ="^MAXWEEKS=8,^MAXREPEATS=0|^MAXREPEATS=2,";
  $search_string.="^MINALPHA=2|^MINALPHA=1,^MINDIFF=3|^MINDIFF=1";
  $search_string.="^MINDIGIT=1,^MINSPECIAL=0,^MINUPPER=1,^MINLOWER=1,";
  $search_string.="^WHITESPACE=NO,^NAMECHECK=YES,^PASSLENGTH=7|^PASSLENGTH=8,";
  $search_string.="^DICTIONDBDIR=/var/passwd,^DICTIONLIST=/usr/share/dict/words,";
  $search_string.="^MINWEEKS=2,^HISTORY=26|^HISTORY=10";
  $search_file="etc/default/passwd";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string ="^ENABLE_NOBODY_KEYS=NO";
  $search_file="etc/default/keyserv";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string ="^ACCEPT6TO4RELAY=NO,^RELAY6TO4ADDR=\"192.168.99.1\",";
  $search_string.="^TCP_STRONG_ISS=2";
  $search_file="etc/default/inetinit";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string ="^PMCHANGEPERM=-,^CPRCHANGEPERM=-";
  $search_file="etc/default/power";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string ="^PERMS=-";
  $search_file="etc/default/sys-suspend";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string ="^LOG_FROM_REMOTE=NO";
  $search_file="etc/default/syslogd";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string ="^BANNER=\"Authorized Use Only\"";
  $search_file="etc/default/telnetd";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string ="^audit.notice[[:space:]]*/var/log/userlog";
  $search_file="etc/syslog.conf";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string ="^set c2audit:audit_load = 1,^set noexec_user_stack_log=1,";
  $search_string.="^set noexec_user_stack=1,^set nfssrv:nfs_portmon=1";
  $search_file="etc/system";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  $search_string ="^CRYPT_DEFAULT=6,^CRYPT_ALGORITHMS_ALLOW";
  $search_file="/etc/security/policy.conf";
  search_explorers($search_file,$search_string,$search_message,$search_client);
  return;
}

sub create_template {
  if ($option{'H'}) {
    $template=HTML::Template->new(
      scalarref         => \$html,
      loop_context_vars => 1,
    );
    return;
  }
}

sub print_template {
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
  my $search_string="[A-Z]puppet";
  my $search_file="patch+pkg/pkginfo-l.out";
  my $search_message="Installed";
  search_explorers($search_file,$search_string,$search_message,$search_client);
}

sub bsm_status {
  my $search_client=$_[0];
  my $search_string="^set c2audit:audit_load = 1";
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

sub get_hostname {
  my $explorer_file=$_[0];
  my @line=split(/\./,$explorer_file);
  my $year;
  my $hostname=@line[2];
  ($hostname,$year)=split("-",$hostname);
  ($hostname,$year)=split(/\-/,$hostname);
  return($hostname);
}

sub search_explorers {
  my $search_file=$_[0];
  my $search_string=$_[1];
  my $search_message=$_[2];
  my $search_client=$_[3];
  my @explorer_list=get_explorer_list($search_client);
  my @search_string;
  my $search_result;
  my @host_list;
  my $hostname;
  my $pkg_file;
  my $explorer_file;
  my $filename;
  my @line;
  my $year;
  my $junk;
  my $spacer;
  my @pkg_info;
  my $pkg_test;
  my $command;
  my $output_file;
  my @file_list;
  my @zone_list;
  my $zone_name;
  my $zone_dir;
  my $message_file=$search_file;
  my $other_info;
  my $zone_file="etc/zones/index";
  $message_file=~s/\.out//g;
  if ($search_string=~/\,/) {
    @search_string=split(",",$search_string);
  }
  else {
    @search_string[0]=$search_string; 
  }
  if ($option{'C'}) {
    $spacer=",";
  }
  else {
    $spacer=" ";
  }
  $search_string="";
  $search_file=~s/^\///g;
  foreach $explorer_file (@explorer_list) {
    @file_list=();
    @zone_list=();
    chomp($explorer_file);
    $hostname=get_hostname($explorer_file);
    $filename=basename($explorer_file,".tar.gz");
    $filename="$hostname,$filename/$search_file";
    push(@file_list,$filename);
    $command="gtar -xpzf $explorer_file $zone_file -O 2>&1";
    @zone_list=`$command |grep installed |cut -f3 -d:`;
    foreach $zone_dir (@zone_list) {
      chomp($zone_dir);
      if ($zone_dir=~/[a-z]/) {
        $zone_name=basename($zone_dir);
        push(@file_list,"$zone_name,$zone_dir/$search_file");
      }
    }
    foreach $filename (@file_list) {
      ($hostname,$filename)=split(",",$filename);
      $command="gtar -xpzf $explorer_file $filename -O 2>&1";
      if ($option{'v'}) {
        print "Checking $hostname file $filename\n";
        print "Executing: $command\n";
      }
      @pkg_info=`$command`;
      if (!grep /$hostname/,@host_list) {
        foreach $search_string (@search_string) {
          if ($option{'v'}) {
            print "Searching $filename for $search_string\n"; 
          }
          if (grep /$search_string/,@pkg_info) {
            if ($filename=~/patch/) {
              $search_result=(grep /$search_string$/,@pkg_info)[0];
              chomp($search_result);
              ($junk,$search_result)=split(": ",$search_result);
              $other_info=join("\n",@pkg_info);
              @pkg_info=split("PKGINST:",$other_info);
              @pkg_info=(grep /$search_string/,@pkg_info);
              $other_info=@pkg_info[0];
              @pkg_info=split("\n",$other_info);
              $other_info=@pkg_info[8];
              ($junk,$other_info)=split(":  ",$other_info);
              chomp($other_info);
              $search_result="$search_result $other_info";
              $search_result=~s/\[A\-Z\]//g;
            }
            else {
              $search_result=$search_string;
              $search_result=~s/\^//g;
              $search_result=~s/\|/ or /g;
              $search_result=~s/^offline\.\*//g;
              $search_result=~s/^online\.\*//g;
              $search_result=~s/\[\[\:space\:\]\]\*/ /g;
            }
            if ($option{'H'}) {
              my %row=(hostname=>"$hostname", value=>"<font color=\"green\">$search_result $search_message</font>");
              push(@loop,\%row);
            }
            else {
              if ($option{'o'}) {
                print FILE "$hostname: $search_result$spacer$search_message in /$message_file\n";
              }
              else {
                print "$hostname: $search_result$spacer$search_message in /$message_file\n";
              }
            }
          }
          else {
            $search_result=$search_string;
            $search_result=~s/\^//g;
            $search_result=~s/\|/ or /g;
            $search_result=~s/^offline\.\*//g;
            $search_result=~s/^online\.\*//g;
            $search_result=~s/\[\[\:space\:\]\]\*/ /g;
            $search_result=~s/\[A\-Z\]//g;
            if ($option{'H'}) {
              my %row=(hostname=>"$hostname", value=>"<font color=\"red\">$search_result Not $search_message</font>");
              push(@loop,\%row);
            }
            else {
              if ($option{'o'}) {
                print FILE "$hostname: $search_result$spacer";
                print FILE "Not $search_message in /$message_file\n";
              }
              else {
                print "$hostname: $search_result$spacer";
                print "Not $search_message in /$message_file\n";
              }
            }
          }
        }
      }
      push(@host_list,$hostname);
    }
  }
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