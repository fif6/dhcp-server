use Switch;

sub handle_discover($$$) {
	my $dbh = $_[0];
	my $user_conf = $_[1];
	my $dhcpreq = $_[2];

	$dhcpresp = GenDHCPRespPkt($dhcpreq);


	$dhcpresp->yiaddr( $user_conf->{'ip'} );
	$dhcpresp->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPOFFER);

	$dhcpresp->addOptionValue(DHO_SUBNET_MASK(), $user_conf->{'mask'} ); # opt 1
	$dhcpresp->addOptionValue(DHO_ROUTERS(), $user_conf->{'gw'} ); # opt 3
	$dhcpresp->addOptionValue(DHO_ROUTER_DISCOVERY(), '0'); # ?
	$dhcpresp->addOptionValue(DHO_DOMAIN_NAME_SERVERS(), $user_conf->{'dns1'} ." ". $user_conf->{'dns2'} ); # opt 6
	$dhcpresp->addOptionValue(DHO_DOMAIN_NAME(), DHCP_DOMAIN ); # opt 15
	$dhcpresp->addOptionValue(DHO_NETBIOS_NODE_TYPE(), '8'); # ?
	
	$dhcpresp->addOptionValue(DHO_DHCP_LEASE_TIME(), CONF_DHCP_LEASE_TIME ); # opt 51
	
	
	if ( defined($dhcpreq->getOptionRaw(DHO_AUTO_CONFIGURE)) && $dhcpreq->getOptionValue(DHO_AUTO_CONFIGURE()) != 0 ) {
		$dhcpresp->addOptionValue(DHO_AUTO_CONFIGURE(), 0);
	}
	
	if ( defined($dhcpreq->getOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS)) ) {
		$dhcpresp->addOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS(), $dhcpreq->getOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS) );
	}

	if ( defined($dhcpreq->getOptionRaw(DHO_DHCP_AGENT_OPTIONS)) ) {
		$dhcpresp->addOptionRaw(DHO_DHCP_AGENT_OPTIONS(), $dhcpreq->getOptionRaw(DHO_DHCP_AGENT_OPTIONS) );
	}

	send_reply($dhcpresp);
}



sub handle_request($$$) {
	my $dbh = $_[0];
	my $user_conf = $_[1];
	my $dhcpreq = $_[2];

	#print "Received REQUEST\n";
	#return 0;
	$dhcpresp = GenDHCPRespPkt($dhcpreq);


	# NAK
	if (	(defined($dhcpreq->getOptionRaw(DHO_DHCP_REQUESTED_ADDRESS())) && $dhcpreq->getOptionValue(DHO_DHCP_REQUESTED_ADDRESS()) ne $user_conf->{'ip'}) ||
		(defined($dhcpreq->getOptionRaw(DHO_DHCP_REQUESTED_ADDRESS())) == 0 && $dhcpreq->ciaddr() ne $user_conf->{'ip'}) ) {
			# NAK if requested addr not equal IP addr in DB
			$dhcpresp->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPNAK);
			$dhcpresp->ciaddr('0.0.0.0');
			$dhcpresp->yiaddr('0.0.0.0');

			send_reply($dhcpresp);
			return;
	}

	# else ACK
	$dhcpresp->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPACK);

	$dhcpresp->ciaddr('0.0.0.0');
	$dhcpresp->yiaddr( $user_conf->{'ip'} );
	$dhcpresp->addOptionValue(DHO_SUBNET_MASK(), $user_conf->{'mask'} );
	$dhcpresp->addOptionValue(DHO_ROUTERS(), $user_conf->{'gw'} );
	$dhcpresp->addOptionValue(DHO_DOMAIN_NAME_SERVERS(), $user_conf->{'dns1'} ." ". $user_conf->{'dns2'} );
	$dhcpresp->addOptionValue(DHO_DOMAIN_NAME(), DHCP_DOMAIN );

	$dhcpresp->addOptionValue(DHO_DHCP_LEASE_TIME(), CONF_DHCP_LEASE_TIME );
	$dhcpresp->addOptionValue(DHO_DHCP_RENEWAL_TIME(), CONF_DHCP_RENEWAL_TIME );
	$dhcpresp->addOptionValue(DHO_DHCP_REBINDING_TIME(), CONF_DHCP_REBINDING_TIME );

	$dhcpresp->addOptionValue(DHO_ROUTER_DISCOVERY(), '0');
	$dhcpresp->addOptionValue(DHO_NETBIOS_NODE_TYPE(), '8');


	if ( defined($dhcpreq->getOptionRaw(DHO_AUTO_CONFIGURE)) && $dhcpreq->getOptionValue(DHO_AUTO_CONFIGURE()) != 0 ) {
		$dhcpresp->addOptionValue(DHO_AUTO_CONFIGURE(), 0);
	}
	
	if ( defined($dhcpreq->getOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS)) ) {
		$dhcpresp->addOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS(), $dhcpreq->getOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS) );
	}

	if ( defined($dhcpreq->getOptionRaw(DHO_DHCP_AGENT_OPTIONS)) ) {
		$dhcpresp->addOptionRaw(DHO_DHCP_AGENT_OPTIONS(), $dhcpreq->getOptionRaw(DHO_DHCP_AGENT_OPTIONS) );
	}

	send_reply($dhcpresp);
}


sub handle_decline($$$) {
	my $dbh = $_[0];
	my $user_conf = $_[1];
	my $dhcpreq = $_[2];

	#print "Received DECLINE\n";
}

sub handle_release($$$) {
	my $dbh = $_[0];
	my $user_conf = $_[1];
	my $dhcpreq = $_[2];
	
	#print "Received RELEASE\n";
}

sub handle_inform($$$) {
	my $dbh = $_[0];
	my $user_conf = $_[1];
	my $dhcpreq = $_[2];

	#print "Received INFORM\n";

	$dhcpresp = GenDHCPRespPkt($dhcpreq);
	$dhcpresp->{options}->{DHO_DHCP_MESSAGE_TYPE()} = pack('C', DHCPACK);

	$dhcpresp->ciaddr('0.0.0.0');
	$dhcpresp->addOptionValue(DHO_SUBNET_MASK(), $user_conf->{'mask'} );
	$dhcpresp->addOptionValue(DHO_ROUTERS(), $user_conf->{'gw'} );
	$dhcpresp->addOptionValue(DHO_ROUTER_DISCOVERY(), '0');
	$dhcpresp->addOptionValue(DHO_DOMAIN_NAME_SERVERS(), $user_conf->{'dns1'} ." ". $user_conf->{'dns2'} );
	$dhcpresp->addOptionValue(DHO_DOMAIN_NAME(), DHCP_DOMAIN );
	$dhcpresp->addOptionValue(DHO_NETBIOS_NODE_TYPE(), '8');


	if ( defined($dhcpreq->getOptionRaw(DHO_AUTO_CONFIGURE)) && $dhcpreq->getOptionValue(DHO_AUTO_CONFIGURE()) != 0 ) {
		$dhcpresp->addOptionValue(DHO_AUTO_CONFIGURE(), 0);
	}
	
	if ( defined($dhcpreq->getOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS)) ) {
		$dhcpresp->addOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS(), $dhcpreq->getOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS) );
	}

	if ( defined($dhcpreq->getOptionRaw(DHO_DHCP_AGENT_OPTIONS)) ) {
		$dhcpresp->addOptionRaw(DHO_DHCP_AGENT_OPTIONS(), $dhcpreq->getOptionRaw(DHO_DHCP_AGENT_OPTIONS) );
	}

	send_reply($dhcpresp);
}


sub GenDHCPRespPkt($) {
	my $dhcpreq = $_[0];
	my $dhcpresp = new Net::DHCP::Packet(
		Op => BOOTREPLY(),
		Htype => $_[0]->htype(),
		Hlen => $_[0]->hlen(),
		# Hops => $_[0]->hops(), # - not copyed in responce
		Xid => $_[0]->xid(),
		Secs => $_[0]->secs(),
		Flags => $_[0]->flags(),
		Ciaddr => $_[0]->ciaddr(),
		#Yiaddr => $SERVER_IP,
		Siaddr => $_[0]->siaddr(),
		Giaddr => $_[0]->giaddr(),
		Chaddr => $_[0]->chaddr(),
		DHO_DHCP_MESSAGE_TYPE() => DHCPACK, # must be owerwritten
		DHO_DHCP_SERVER_IDENTIFIER() => BIND_ADDR
	);

#	if ( defined($dhcpreq->getOptionRaw(DHO_AUTO_CONFIGURE)) && $dhcpreq->getOptionValue(DHO_AUTO_CONFIGURE()) != 0 ) {
#		$dhcpresp->addOptionValue(DHO_AUTO_CONFIGURE(), 0);
#	}
	
#	if ( defined($dhcpreq->getOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS)) ) {
#		$dhcpresp->addOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS(), $dhcpreq->getOptionRaw(DHO_VENDOR_ENCAPSULATED_OPTIONS) );
#	}

#	if ( defined($dhcpreq->getOptionRaw(DHO_DHCP_AGENT_OPTIONS)) ) {
#		$dhcpresp->addOptionRaw(DHO_DHCP_AGENT_OPTIONS(), $dhcpreq->getOptionRaw(DHO_DHCP_AGENT_OPTIONS) );
#	}


	return($dhcpresp);
}



1;
