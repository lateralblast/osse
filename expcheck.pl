#!/usr/bin/env perl

use strict;
use HTML::Template;
use Getopt::Std;
use File::Basename;

# Name:         expcheck.pl
# Version:      0.0.5
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

my $script_name=$0;
my $script_version=`cat $script_name | grep '^# Version' |awk '{print \$3}'`;
my $explorer_dir="explorers";
my %option=();
my $options="hBHJPRVo:";

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
  print "-R: Report which machines have RSA SecurID PAM agent installed\n";
  print "-H: Generate HTML report\n";
  print "-o: Output to file rather than STDOUT\n";
  print "\n";
  return;
}

if ($option{'R'}) {
  rsa_status();
  exit;
}

if ($option{'B'}) {
  bsm_status();
  exit;
}

if ($option{'J'}) {
  jass_status();
  exit;
}

if ($option{'P'}) {
  puppet_status();
  exit;
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
  my @explorer_list=`find $explorer_dir -name "*exp*.gz" |sort -rn |uniq`;
  return(@explorer_list);
}

sub jass_status {
  my $search_string="SUNWjass";
  my $search_file="patch+pkg/pkginfo-l.out";
  my $search_message="Installed";
  search_explorers($search_file,$search_string,$search_message);
}

sub puppet_status {
  my $search_string="puppet";
  my $search_file="patch+pkg/pkginfo-l.out";
  my $search_message="Installed";
  search_explorers($search_file,$search_string,$search_message);
}

sub bsm_status {
  my $search_string="audit";
  my $search_file="etc/system";
  my $search_message="Enabled";
  search_explorers($search_file,$search_string,$search_message);
}

sub rsa_status {
  my $search_string="securid";
  my $search_file="etc/pam.conf";
  my $search_message="Enabled";
  search_explorers($search_file,$search_string,$search_message);
}

sub search_explorers {
  my $search_file=$_[0];
  my $search_string=$_[1];
  my $search_message=$_[2];
  my @explorer_list=get_explorer_list();
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
    if (grep /$search_string/,@pkg_info) {
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