#!/usr/bin/perl -w


BEGIN {
	use FindBin;
	unshift(@INC, "${FindBin::RealBin}/modules"); # add custom Modules path at the first of position in @INC
};



use strict;
use warnings;
use Switch;
use Socket;
use IO::Socket::INET;
use Net::DHCP::Packet; # in local modules dir
use Net::DHCP::Constants; # in local modules dir
use threads;
use threads::shared;
use POSIX qw(setsid setuid strftime ceil :signal_h);
use DBI;
use DBD::mysql;
use Math::BigInt;
use Data::Dumper;
#use Log::Syslog::Fast ':all'; # in local modules dir

#print "HINT: ". DHO_NETBIOS_NODE_TYPE() ."\n";
#exit;

# Unbuffer output
$| = 1;

use constant LOG_STDOUT		=> 1; # 0 - Off, 1 - ON
use constant DEBUG		=> 2; # 0 - SYS INFO & ERRORS, 1 - DHCP INFO, 2 - DHCP WARN, 3 - DHCP PKT DEBUG
use constant DAEMON_MODE	=> 1;
use constant BIND_ADDR		=> '1.2.3.4';
use constant SERVER_PORT	=> 67;
use constant PID_FILE		=> '/var/run/dhcpd_server.pid';
use constant LOG_FILE		=> '/var/log/dhcpd_server.log';
use constant CLIENT_PORT	=> 68;
use constant THREADS		=> 1;

use constant DB_HOST		=> '4.3.2.1';
use constant DB_PORT		=> 3306;
use constant DB_LOGIN		=> 'db_user';
use constant DB_PASSWD		=> 'db_passwd';
use constant DB_NAME		=> 'db_name';

use constant DHCP_DOMAIN	=> 'corp.net';

use constant MIRROR_ENABLED	=> 0;
use constant MIRROR_HOST	=> '11.22.33.44'; # traffic analyse host
use constant MIRROR_PORT	=> 10067;

use constant RSYSLOG_ENABLED	=> 0;
use constant RSYSLOG_HOST	=> '22.33.44.55';

use constant CONF_DHCP_LEASE_TIME	=> 24 * 3600;
use constant CONF_DHCP_RENEWAL_TIME	=> ceil(CONF_DHCP_LEASE_TIME * 0.5);
use constant CONF_DHCP_REBINDING_TIME	=> ceil(CONF_DHCP_LEASE_TIME * 0.87);


# Global scope variables (for visibility from subs)
my ($RUNNING, $SOCKET_RCV, $RSyslog);
share ($RUNNING);

# Load self program modules
use request_handler;

if ( RSYSLOG_ENABLED ) {
	$RSyslog = Log::Syslog::Fast->new(LOG_UDP, RSYSLOG_HOST, 514, LOG_LOCAL0, LOG_INFO, "DHCP-Server-v2", "");
	#$RSyslog->set_pid('');
}


# -------- Only check and read PID file
my $pid = 0;
if ( -e PID_FILE ) {
	print "WARN: PID file exists.\n";
	open(PIDF, PID_FILE) || die "ERROR: PID file '". PID_FILE ."' read error: $!"; # opening for read only
	$pid = <PIDF>;
	close(PIDF);
}

if ( $pid && -e "/proc/$pid/stat" ) { # Is proccess number already running by OS KERNEL?
	die "ERROR: My process is already exists (PID $pid). Exiting.\n"; 
}
# ---


# Catch terminating signals
$SIG{INT} = $SIG{TERM} = $SIG{HUP} = \&signal_handler;
$SIG{PIPE} = 'IGNORE';


# -------- Create PID file
open(PIDNF, ">".PID_FILE) || die "ERROR: PID file '".PID_FILE."' write error: $!";
print(PIDNF "$$"); # write current PID in to file 
close(PIDNF);
# ---


&daemonize();

# this keeps the program alive or something after exec'ing perl scripts
END() { }
BEGIN() { }

{
	no warnings; 
	*CORE::GLOBAL::exit = sub { die "fakeexit\nrc=".shift()."\n"; };
};
eval q{exit};
if ($@) { exit unless $@ =~ /^fakeexit/; };








sub signal_handler { # exit signal received. Stopping threads from main process
	logger("TERMINATE signal catched. Program exiting!");
	$RUNNING = 0;

	#foreach (threads->list()) {
	#	logger("Stopping thread (". $_->tid() .")");
	#	$_->kill('KILL')->detach();
	#}
}

sub thread_exit($) { # may called from thread only
	logger("threat_exit() called from thread [". threads->tid() ."]. Program exiting!");
	$RUNNING = 0;
	threads->exit() if threads->can('exit');
	#threads->detach();

	# kill other worked threads
	#foreach (threads->list()) {
	#	logger("Stopping thread (". $_->tid() .")");
	#	$_->detach();
	#}
	#$RUNNING = 0; 
	#print "Test\n";
	exit($_[0]);
}


# sample logger
sub logger {
	my $tid = threads->tid(); # thread ID
	#if ( !DEBUG ) { return; }
	open MYLOG, ">> ".LOG_FILE || die "Log file open error: $!";
	my $curr_time = strftime("%d/%m/%y %H:%M:%S", localtime);
	#$tid = ( $tid != 0 ) ? "[$tid]" : "";
	if ( LOG_STDOUT && DAEMON_MODE != 1 ) { print STDOUT "[$curr_time][$tid] ". $_[0] ."\n"; }
	print MYLOG "[$curr_time][$tid] ". $_[0] ."\n";
	close MYLOG;
	if ( RSYSLOG_ENABLED ) { $RSyslog->set_pid($tid); $RSyslog->send($_[0]); }
}

sub daemonize {
	#$SIG{INT} = $SIG{TERM} = $SIG{HUP} = \&signal_handler;
	# trap or ignore $SIG{PIPE}

	# Daemon behaviour
	# ignore any PIPE signal: standard behaviour is to quit process
	#$SIG{PIPE} = 'IGNORE';

	$RUNNING = 1;

	logger("BIND_ADDR: ".BIND_ADDR.", PORT: ".SERVER_PORT.", THREADS: ".THREADS.", PIDFILE: ".PID_FILE );

	if (DAEMON_MODE) {
		# disable STDOUT logging (LOGFILE only)
		#$LOG_STDOUT = 0;
		delete @ENV{qw(IFS CDPATH ENV BASH_ENV)}; # Make %ENV safer
		#setuid(65534)          or die "Can't set uid: $!\n"; # nobody

		open(STDIN,  "+>/dev/null") or die "Can't open STDIN: $!\n";
		open(STDOUT, "+>&STDIN") or die "Can't open STDOUT: $!\n";
		open(STDERR, "+>&STDIN") or die "Can't open STDERR: $!\n";
		defined(my $tm = fork)  or die "Can't fork: $!\n";
		exit if $tm;
		setsid() or die "Can't start a new session: $!\n";
		umask 0;
		logger("Entering Daemon mode. DAEMON_MODE=1");

		# ---- Updating PID_FILE with new PID
		if ( open(PIDNF, ">".PID_FILE) ) {
			print(PIDNF "$$"); # write in to file current PID
		} else {
			logger("ERROR: PID file '".PID_FILE."' write error after daemonizing: $!");
			$RUNNING = 0;
		}
		close(PIDNF);
	}

	logger("INFO: Script PID is $$");
	# write PID to file
	#if ( !open (FILE, "> ".PID_FILE) ) { $RUNNING=0; logger("PID file save error: $!") };
	#print FILE "$$\n";
	#close FILE;

	#$RUNNING = 1;

	# open listening socket
	#socket($SOCKET_RCV, PF_INET, SOCK_DGRAM, getprotobyname('udp')) || die "Socket creation error: $@\n";
	if ( !socket($SOCKET_RCV, PF_INET, SOCK_DGRAM, getprotobyname('udp')) ) { $RUNNING=0; logger("Socket creation error: $@"); }
	#bind($SOCKET_RCV, sockaddr_in(SERVER_PORT, inet_aton(BIND_ADDR)) ) || die "bind: $!\n";
	if ( !bind($SOCKET_RCV, sockaddr_in(SERVER_PORT, inet_aton(BIND_ADDR)) ) ) { $RUNNING=0; logger("bind: $!"); }

	# start threads
	if ( $RUNNING == 1 ) {
		for my $i (1..THREADS) {
			threads->create({'context' => 'void'}, \&request_loop);
		}

		### Collect the bits and pieces! ...
		#$_->join foreach threads->list();
		#$_->detach foreach threads->list();

		# and handle request with other threads
		#request_loop();

		while ($RUNNING == 1) {
			# noop :)
			sleep 1;
		}

		foreach (threads->list()) {
			logger("Stopping thread [". $_->tid() ."]");
			$_->kill('KILL')->detach();
		}
	}

	logger("Stopping main process PID $$");
	#close MYLOG;
	close $SOCKET_RCV;
	unlink(PID_FILE);
}


sub request_loop() {
	my $tid = threads->tid(); # thread ID

	my ($recv_udp_pkt, $fromaddr, $dhcpreq, $client_mac, $ciaddr, $relay_ip);
	my ($dbh, $sth, $data, $user_conf);
	my ($vlan_id, $port_id, $vport_id, $device_mac);
	my $request_message_type;

	logger("Thread [$tid]: STARTed");

	#thread_exit(1) if ($tid == 2);
	#print "there\n";

	# Each thread make own DB connection
	$dbh = DBI->connect("DBI:mysql:database=".DB_NAME.";host=".DB_HOST.";port=".DB_PORT, DB_LOGIN, DB_PASSWD);
	if ( defined($dbh) == 0 ) {
		logger("ERROR: Could not connect to database: ". $DBI::errstr);
		thread_exit(1); # this check only at first start of a threads
	}
	$dbh->{mysql_auto_reconnect} = 1;

	if ($tid != 0) {
		# disable signals receiving on creted threads and set handler for KILL signal
		my $sigset = POSIX::SigSet->new(SIGINT(), SIGTERM(), SIGHUP());    # define the signals to block
		my $old_sigset = POSIX::SigSet->new;        # where the old sigmask will be kept
		unless (defined sigprocmask(SIG_BLOCK(), $sigset, $old_sigset)) { die "Could not unblock SIGINT\n"; }
		$SIG{KILL} = sub { logger("Thread ($tid): END by sig handler"); thread_exit(0); };
	}

	while ($RUNNING == 1) {
		$recv_udp_pkt = undef;
		$fromaddr = undef;
		$dhcpreq = undef;
		$client_mac = undef;
		$ciaddr = undef;
		$relay_ip = undef;
		$sth = undef;
		$data = undef;
		$user_conf = undef;

		$vlan_id = undef;
		$port_id = undef;
		$vport_id = undef;
		$device_mac = undef;

		$request_message_type = undef;

	#eval {
		# 16384
		$fromaddr = recv($SOCKET_RCV, $recv_udp_pkt, 1024, 0) || logger("Thread ($tid) UDP packet recv err: $!");

		# send copy of packet to mirror, if specified
		if ( MIRROR_ENABLED ) {
			send($SOCKET_RCV, $recv_udp_pkt, 0, sockaddr_in(MIRROR_PORT, inet_aton(MIRROR_HOST)) ) || logger("ERROR: Send copy of Request packet to mirror error: $!");
		}

		# filter to small packets
		if ( length($recv_udp_pkt) < 236 ) { 
			logger("WARN: Received to small UDP packet! From $fromaddr, length=".length($recv_udp_pkt)."b") if (DEBUG > 1); # WARN
			next;
		}

		# parce data to dhcp structes
		$dhcpreq = Net::DHCP::Packet->new($recv_udp_pkt);

		if (DEBUG > 2) { # DHCP DEBUG
			logger("============== RECIEVED PACKET  ========================");
			logger( $dhcpreq->toString() );
			logger("========================================================\n");
		}

		#logger("DEBUG: recv message type is ". $dhcpreq->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) ) if (DEBUG > 2);

		# filter bad params in head
		next if ( $dhcpreq->op() != BOOTREQUEST || $dhcpreq->isDhcp() == 0 );
		next if ( $dhcpreq->htype() != HTYPE_ETHER || $dhcpreq->hlen() != 6 );

		# bad DHCP message!
		next if ( defined($dhcpreq->getOptionRaw(DHO_DHCP_MESSAGE_TYPE())) == 0 );
		switch( $dhcpreq->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) ){
			case DHCPDISCOVER { $request_message_type = 'DISCOVER'; }
			case DHCPREQUEST { $request_message_type = 'REQUEST'; }
			case DHCPDECLINE { $request_message_type = 'DECLINE'; }
			case DHCPRELEASE { $request_message_type = 'RELEASE'; }
			case DHCPINFORM { $request_message_type = 'INFORM'; }
		}

		# Is message for us?
		next if ( defined($dhcpreq->getOptionRaw(DHO_DHCP_SERVER_IDENTIFIER())) && $dhcpreq->getOptionValue(DHO_DHCP_SERVER_IDENTIFIER()) ne BIND_ADDR );

		# RRAS client, ignory them
		next if ( defined($dhcpreq->getOptionRaw(DHO_USER_CLASS())) && $dhcpreq->getOptionRaw(DHO_USER_CLASS()) eq "RRAS.Microsoft" );

		#if ( defined($dhcpreq->getOptionRaw(DHO_DHCP_REQUESTED_ADDRESS)) ) {
		#	print $dhcpreq->getOptionValue(DHO_DHCP_REQUESTED_ADDRESS)."\n";
		#}

		$client_mac = FormatMAC( $dhcpreq->chaddr() );
		$ciaddr = $dhcpreq->ciaddr();

		# Not a RELAY
		if ( $dhcpreq->giaddr() eq '0.0.0.0') {
			logger("WARN: Packet NOT from a Relay! giaddr is 0.0.0.0, ciaddr $ciaddr, client mac $client_mac, req $request_message_type") if (DEBUG > 1); # WARN
			next;
		}

		$relay_ip = $dhcpreq->giaddr();

		# Opt82 not defined
		if ( defined($dhcpreq->getOptionRaw(DHO_DHCP_AGENT_OPTIONS())) == 0 ) {
			logger("WARN: Packet NO ANY opt82 data detected - Bad snoop! Relay giaddr $relay_ip, ciaddr $ciaddr, client mac $client_mac, req $request_message_type") if (DEBUG > 1); # WARN
			# no options, return
			next;
		}

		# Get Option 82
		($vlan_id, $port_id, $vport_id, $device_mac) = GetRelayAgentOptions($dhcpreq);
		$device_mac = FormatMAC($device_mac);

		
		# Port num greather than 24
		#next if ( $port_id > 24 );
		

		logger("DEBUG: preparing MySQL query") if (DEBUG > 2);


		$sth = $dbh->prepare("(SELECT
				service_lan.id AS id,
				service_lan.uid AS uid,
				service_lan.account_id AS account_id,
				INET_NTOA(service_lan.ip) AS user_ip,
				INET_NTOA(service_lan.mask) AS user_mask,
				INET_NTOA(service_lan.gateway) AS user_gw,
				INET_NTOA(service_lan.dns1) AS dns1,
				INET_NTOA(service_lan.dns2) AS dns2,
				'IP' AS where_found
			FROM service_lan
			WHERE service_lan.switch_ip=INET_ATON('$relay_ip') AND service_lan.switch_port='$port_id' AND IF($vport_id = -1, 1, service_lan.switch_vport=$vport_id) LIMIT 1)
			UNION
			(SELECT
				service_lan.id AS id,
				service_lan.uid AS uid,
				service_lan.account_id AS account_id,
				INET_NTOA(service_lan.ip) AS user_ip,
				INET_NTOA(service_lan.mask) AS user_mask,
				INET_NTOA(service_lan.gateway) AS user_gw,
				INET_NTOA(service_lan.dns1) AS dns1,
				INET_NTOA(service_lan.dns2) AS dns2,
				'MAC' AS where_found
			FROM service_lan
			WHERE service_lan.relay_mac=".mac2long($device_mac)." AND service_lan.switch_port='$port_id' AND IF($vport_id = -1, 1, service_lan.switch_vport=$vport_id) LIMIT 1)

			LIMIT 1;
		");



		$sth->execute() or print("ERROR: Can't execute SQL statement: ".$DBI::errstr);

		unless ( $data = $sth->fetchrow_hashref() ) { # DHCP INFO
			#logger("NOTHING, Giaddr $relay_ip, device mac $device_mac, vlan $vlan_id, port $port_id, ". ($vport_id>-1 ? "vport $vport_id, ":''). "client mac $client_mac") if (DEBUG > 0);
			logger("NOTHING, Giaddr $relay_ip, device mac $device_mac, vlan $vlan_id, port $port_id, vport $vport_id, client mac $client_mac") if (DEBUG > 0);
			next;
		}

		$user_conf->{'row_id'} = $data->{'id'};
		$user_conf->{'uid'} = $data->{'uid'};
		$user_conf->{'aid'} = $data->{'account_id'};
		$user_conf->{'ip'} = $data->{'user_ip'};
		$user_conf->{'mask'} = $data->{'user_mask'};
		$user_conf->{'gw'} = $data->{'user_gw'};
		$user_conf->{'dns1'} = $data->{'dns1'};
		$user_conf->{'dns2'} = $data->{'dns2'};
		$user_conf->{'where_found'} = $data->{'where_found'};


		$dbh->do("UPDATE service_lan SET lastRequest_date=UNIX_TIMESTAMP(), lastRequest_mac='".mac2long($client_mac)."', relay_ip=INET_ATON('$relay_ip'), relay_vlan=$vlan_id WHERE id=".$user_conf->{'row_id'}." LIMIT 1;");


#		switch( $dhcpreq->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) ){
#			case DHCPDISCOVER { $request_message_type = 'DISCOVER'; }
#			case DHCPREQUEST { $request_message_type = 'REQUEST'; }
#			case DHCPDECLINE { $request_message_type = 'DECLINE'; }
#			case DHCPRELEASE { $request_message_type = 'RELEASE'; }
#			case DHCPINFORM { $request_message_type = 'INFORM'; }
#		}

		logger("FOUND by AP ".$user_conf->{'where_found'}.", uid ".$user_conf->{'uid'}.", aid ".$user_conf->{'aid'}.", ip ".$user_conf->{'ip'}.": from relay $relay_ip, vlan $vlan_id, port $port_id, ".($vport_id>-1 ? "vport $vport_id, ":'')."client mac $client_mac, $request_message_type") if (DEBUG > 0);
		#$dbh->do("INSERT INTO dhcp_log SET date_unix=UNIX_TIMESTAMP(), thread_id=$tid, uid=".$data->{'uid'}.", ap_ip=INET_ATON('$relay_ip'), vlan_id=$vlan_id, port_num=$port_id, client_mac=".mac2long($client_mac).", req_type='discover';");

		# handle packet
		switch( $dhcpreq->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) ){
			case DHCPDISCOVER { #-> DHCPOFFER
				#logger("FOUND uid ". $data->{'uid'} .": from relay $relay_ip, vlan $vlan_id, port $port_id, ". ($vport_id>-1 ? "vport $vport_id, ":''). "client mac $client_mac, DISCOVER") if (DEBUG > 0);
				#$dbh->do("INSERT INTO dhcp_log SET date_unix=UNIX_TIMESTAMP(), thread_id=$tid, uid=".$data->{'uid'}.", ap_ip=INET_ATON('$relay_ip'), vlan_id=$vlan_id, port_num=$port_id, client_mac=".mac2long($client_mac).", req_type='discover';");
				handle_discover($dbh, $user_conf, $dhcpreq);
			}
			case DHCPREQUEST { #-> DHCPACK / DHCPNAK
				#logger("FOUND uid ". $data->{'uid'} .": from relay $relay_ip, vlan $vlan_id, port $port_id, ". ($vport_id>-1 ? "vport $vport_id, ":''). "client mac $client_mac, REQUEST (rep ".$data->{'user_ip'}.")") if (DEBUG > 0);
				#$dbh->do("INSERT INTO dhcp_log SET date_unix=UNIX_TIMESTAMP(), thread_id=$tid, uid=".$data->{'uid'}.", ap_ip=INET_ATON('$relay_ip'), vlan_id=$vlan_id, port_num=$port_id, client_mac=".mac2long($client_mac).", req_type='request', reply_ip=INET_ATON('".$data->{'user_ip'}."');");
				handle_request($dbh, $user_conf, $dhcpreq);
			}
			case DHCPDECLINE {
				#logger("FOUND uid ". $data->{'uid'} .": from relay $relay_ip, vlan $vlan_id, port $port_id, ". ($vport_id>-1 ? "vport $vport_id, ":''). "client mac $client_mac, DECLINE") if (DEBUG > 0);
				handle_decline($dbh, $user_conf, $dhcpreq);
			}
			case DHCPRELEASE {
				#logger("FOUND uid ". $data->{'uid'} .": from relay $relay_ip, vlan $vlan_id, port $port_id, ". ($vport_id>-1 ? "vport $vport_id, ":''). "client mac $client_mac, RELEASE") if (DEBUG > 0);
				handle_release($dbh, $user_conf, $dhcpreq);
			}
			case DHCPINFORM { #-> DHCPACK
				#logger("FOUND uid ". $data->{'uid'} .": from relay $relay_ip, vlan $vlan_id, port $port_id, ". ($vport_id>-1 ? "vport $vport_id, ":''). "client mac $client_mac, INFORM") if (DEBUG > 0);
				#$dbh->do("INSERT INTO dhcp_log SET date_unix=UNIX_TIMESTAMP(), thread_id=$tid, uid=".$data->{'uid'}.", ap_ip=INET_ATON('$relay_ip'), vlan_id=$vlan_id, port_num=$port_id, client_mac=".mac2long($client_mac).", req_type='inform';");
				handle_inform($dbh, $user_conf, $dhcpreq);
			}
		}
	#};
	#if ($@) {
	#    logger("Thread $tid: Caught error in main loop: $@");
	#}
	}

	$dbh->disconnect();
	thread_exit(0);
}



#-----------------------------------------------------

sub GetRelayAgentOptions($$) {
	my $dhcpreq = $_[0];
	my $format_type = $_[1];
	my @RelayOptions;

	my $vlan_id = 0;
	my $port_id = -1;
	my $vport_id = -1;
	my $device_mac = ''; # Switch MAC

	my $cid_field_len = 0;
	my $rid_field_len = 0;

	#my $ttt = '';

	# no any options
	return 0 if ( defined($dhcpreq->getOptionRaw(DHO_DHCP_AGENT_OPTIONS)) == 0 );

	@RelayOptions = $dhcpreq->decodeRelayAgent( $dhcpreq->getOptionRaw(DHO_DHCP_AGENT_OPTIONS()) );
	# @RelayOptions is Opt82 suboption array (subopt 1 -> HEX, subopt 2 -> HEX, subopt 9 -> HEX)
	# print Dumper(\@RelayOptions) if (DEBUG > 2);

	# [ 1,      option 1
	# 'data1',  option 1 data 
	# 2,        option 2
	# 'data2' ] option 2 data

	# $RelayOptions[1] - option 1 data
	# $RelayOptions[3] - option 2 data

	#switch($format_type) {

	# Searching for primary SubOption 1 - Circuit ID (later needed for detecting AP device model [relay type] by CID field length)
	for ( my $i = 0; defined($RelayOptions[$i]); $i += 2 ) {
		#switch ( $RelayOptions[$i] ){
		if ( $RelayOptions[$i] == 1 ) { # SubOption 1 - Circuit-ID
			$cid_field_len = length($RelayOptions[$i+1]);
			logger("Giaddr ".$dhcpreq->giaddr().", detected opt82 SubOpt1 Circuit-ID: length is ". $cid_field_len ." byte") if (DEBUG > 1);

			#if ($format_type eq 'bdcom-pon') {
			if ( $cid_field_len == 5 ) { # Bdcom PON Switch
				$vlan_id = unpack('n', substr($RelayOptions[$i+1], -5, 2));
				$port_id = unpack('C', substr($RelayOptions[$i+1], -2, 1)); # physical port epon0/1 - 7, epon0/2 - 8, epon0/3 - 9,
				$vport_id = unpack('C', substr($RelayOptions[$i+1], -1, 1)); # virtual pon port (subport) [epon0/1]:1

			} elsif ( $cid_field_len == 6 ) { # Dlink DES3200 or Huawei S2300
				$vlan_id = unpack('n', substr($RelayOptions[$i+1], -4, 2) ); # may be 's'
				$port_id = unpack('C', substr($RelayOptions[$i+1], -1, 1) );

				#$ttt = unpack('H', substr($RelayOptions[$i+1], -2, 1) );
				#print "$ttt \n";
			} elsif ( $cid_field_len == 3 ) { # Huawei S2300 custom opt82 format for GigabitEthernet ports
				# S2300 port config: dhcp option82 circuit-id format user-defined %svlan 25
				$vlan_id = unpack('n', substr($RelayOptions[$i+1], -3, 2) );
				$port_id = unpack('C', substr($RelayOptions[$i+1], -1, 1) );
				#print "TEST vlan_id:$vlan_id, port_id:$port_id\n";
			}
		}
	}

	# Searching for secondary SubOption 2 - Remote-ID
	for ( my $i = 0; defined($RelayOptions[$i]); $i += 2 ) {
		if ( $RelayOptions[$i] == 2 ) { # SubOption 2 - Remote-ID
			$rid_field_len = length($RelayOptions[$i+1]);
			#logger("Detected opt82 SubOpt2 Remote-ID: length is ". $rid_field_len ." byte") if (DEBUG > 1);
			logger("Giaddr ".$dhcpreq->giaddr().", detected opt82 SubOpt2 Remote-ID: length is ". $rid_field_len ." byte") if (DEBUG > 1);

			if ( $cid_field_len == 5 && $rid_field_len == 6 ) { # CID 5 and RID 6 byte len = may be BDCOM P3300 opt82
				$device_mac = unpack('H*', substr($RelayOptions[$i+1], -6, 6));
				logger("Giaddr ".$dhcpreq->giaddr().", len CID=5b, len RID=6b -> BDCOM P3300, device MAC: ".FormatMAC($device_mac) ) if (DEBUG > 1);
			}

			elsif ( $cid_field_len == 6 && $rid_field_len == 6 ) { # 6 byte len = may be Huawei S2300 opt82 extended
				# Huawei s2300 'dhcp option82 format extend':
				# Indicates the extended format of the Option 82 field.
				#   CircuitID: CID format: circuit-id type (1 byte = 1 dec) + length (1 byte = 4) + SVLAN ID (2 bytes) + slot ID (5 bits) + subslot ID (3 bits) + port (1 byte), in hexadecimal notation
				#   RemoteID: RID format: remote-id type (1 byte = 1 dec) + length (1 byte = 6) + device MAC address (6 bytes), in hexadecimal notation
				# In the CID and RID formats, the values without a unit are fixed values of the fields; the values with a unit indicate the field lengths.
				# s2326 mac: ...
				$device_mac = unpack('H*', substr($RelayOptions[$i+1], -6, 6));
				logger("Giaddr ".$dhcpreq->giaddr().", len CID=6b, len RID=6b -> Huawei S2300, device MAC: ".FormatMAC($device_mac) ) if (DEBUG > 1);
			}

			elsif ( $cid_field_len == 6 && $rid_field_len == 8 ) { # CID 6 and RID 8 byte len = may be D-Link DES-3200 opt82
				$device_mac = unpack('H*', substr($RelayOptions[$i+1], -6, 6));
				logger("Giaddr ".$dhcpreq->giaddr().", len CID=6b, len RID=8b -> D-Link DES-3200, device MAC: ".FormatMAC($device_mac) ) if (DEBUG > 1);
			}
			
			elsif ( $cid_field_len == 3 && $rid_field_len == 8 ) { # CID 3 and RID 8 byte len = may be S2300 custom port opt82 config for GigabitEthernet
				$device_mac = unpack('H*', substr($RelayOptions[$i+1], -6, 6));
				logger("Giaddr ".$dhcpreq->giaddr().", len CID=3b, len RID=8b -> Huawei S2300 custom opt82, device MAC: ".FormatMAC($device_mac) ) if (DEBUG > 1);
			}

			else {
				$device_mac = '000000000000';
				logger("WARN: Giaddr ".$dhcpreq->giaddr().", detecting opt82 SubOption2 format failed. device_mac setting to $device_mac");
			}
		}
	}

	return ($vlan_id, $port_id, $vport_id, $device_mac);
}

# change mac addr format from "abcdefg" to "a:b:c:d:e:f:g"
sub FormatMAC {
	$_[0] =~ /([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})?([0-9a-f]{2})/i;
	return(lc(join(':', $1, $2, $3, $4, $5, $6)));
}


sub send_reply {
	my $dhcpresp = $_[0];
	my ($toaddr, $dhcpresppkt);
	my $reply_message_type;
	
	if ( $dhcpresp->giaddr() eq '0.0.0.0' ) {
		# client is local, not relayed
		logger("ERROR: Can't send Reply to Giaddr 0.0.0.0 = client is local, not relayed.");
		return 0;
	} else {# send to relay
		$toaddr = sockaddr_in('67', inet_aton($dhcpresp->giaddr()) );
	}
	
	$dhcpresppkt = $dhcpresp->serialize();

	# FOR TESTS. Uncomment this!
	send($SOCKET_RCV, $dhcpresppkt, 0, $toaddr) || logger("send error: $!");

	if ( DEBUG > 2 ) {
		my ($port, $addr) = unpack_sockaddr_in($toaddr);
		my $ipaddr = inet_ntoa($addr);

		logger("=== SENDED PACKET to = $ipaddr:$port length = ".length($dhcpresppkt)." ===");
		logger( $dhcpresp->toString() );
		logger("========================================================\n");
	}

	# send copy of packet to mirror, if specified
	if ( MIRROR_ENABLED ) {
		send($SOCKET_RCV, $dhcpresppkt, 0, sockaddr_in(MIRROR_PORT, inet_aton(MIRROR_HOST)) ) || logger("ERROR: Send copy of Reply packet to mirror error: $!");
	}

	switch( $dhcpresp->getOptionValue(DHO_DHCP_MESSAGE_TYPE()) ) {
		case DHCPOFFER { $reply_message_type = 'OFFER'; }
		case DHCPACK { $reply_message_type = 'ACK'; }
		case DHCPNAK { $reply_message_type = 'NAK'; }
		$reply_message_type = 'Undefined';
	}

	#logger("FOUND uid ". $data->{'uid'} .": from relay $relay_ip, vlan $vlan_id, port $port_id, ". ($vport_id>-1 ? "vport $vport_id, ":''). "client mac $client_mac, DISCOVER") if (DEBUG > 0);
	logger("Sending: $reply_message_type, yiaddr ". $dhcpresp->yiaddr() ) if (DEBUG > 0);

}


# Syntax: mk_routes($net, $prefixlen, $gw)
# example: mk_routes('192.168.1.0', 24, '192.168.0.254')
sub mk_routes {
	#my $net = $_[0];
	#my $prefixlen = $_[1];
	#my $gw = $_[2];
	my $str;

	$str = pack('C', $_[1]);

	if ($_[1] > 0) {
		my ($s1, $s2, $s3, $s4) = split(/\./, $_[0]);
		$str .= pack('C', $s1);
		$str .= pack('C', $s2) if ($_[1] > 8);
		$str .= pack('C', $s3) if ($_[1] > 16);
		$str .= pack('C', $s4) if ($_[1] > 24);
	}

	$str .= pack('CCCC', split(/\./, $_[2]));
	return($str);
}

sub mac2long($) {
	my $mac = $_[0];
	$mac =~ s/[^a-fA-F0-9]++//g;
	$mac = substr($mac, 0, 12);
	if ( length($mac) == 0 ) { return 0; }
	return Math::BigInt->new("0x".$mac);
}

