SET ROLE machine_manager;

CREATE DOMAIN hostname         AS varchar(32)  CHECK (VALUE ~ '\A[-_a-z0-9]+\Z');
CREATE DOMAIN netname          AS varchar(32)  CHECK (VALUE ~ '\A[-_a-z0-9]+\Z');
CREATE DOMAIN machine_type     AS varchar(10)  CHECK (VALUE = 'debian' OR VALUE = 'edgerouter');
CREATE DOMAIN port             AS integer      CHECK (VALUE > 0 AND VALUE <= 65536);
CREATE DOMAIN wireguard_key    AS bytea        CHECK (length(VALUE) = 44);
 -- Match default /etc/adduser.conf NAME_REGEX
CREATE DOMAIN username         AS varchar(32)  CHECK (VALUE ~ '\A[a-z][-a-z0-9_]{1,31}\Z');

CREATE TABLE networks (
	name   netname NOT NULL PRIMARY KEY,
	parent netname REFERENCES networks(name) CHECK (parent != name)
);

CREATE TABLE machines (
	-- Preserved information
	hostname          hostname                 NOT NULL PRIMARY KEY,
	type              machine_type             NOT NULL,
	wireguard_ip      inet,
	wireguard_port    port                     CHECK ((wireguard_ip IS NOT NULL AND wireguard_port    IS NOT NULL) OR (wireguard_ip IS NULL AND wireguard_port    IS NULL)),
	wireguard_privkey wireguard_key            CHECK ((wireguard_ip IS NOT NULL AND wireguard_privkey IS NOT NULL) OR (wireguard_ip IS NULL AND wireguard_privkey IS NULL)),
	wireguard_pubkey  wireguard_key            CHECK ((wireguard_ip IS NOT NULL AND wireguard_pubkey  IS NOT NULL) OR (wireguard_ip IS NULL AND wireguard_pubkey  IS NULL)),
	wireguard_expose  netname                  REFERENCES networks(name) CHECK (wireguard_expose IS NULL OR wireguard_ip IS NOT NULL),
	ssh_port          port                     NOT NULL,
	ssh_user          username                 NOT NULL,
	ssh_expose        netname                  REFERENCES networks(name),
	country           character(2)             NOT NULL CHECK (country ~ '\A[a-z]{2}\Z'),
	release           varchar(10)              NOT NULL CHECK (release ~ '\A[a-z]{2,10}\Z'),
	boot              varchar(14)              NOT NULL CHECK (boot ~ '\A[a-z]{3,14}\Z'),
	added_time        timestamp with time zone NOT NULL DEFAULT now(),

	-- Probed information
	ram_mb            int4                      CHECK (ram_mb > 0),
	cpu_model_name    varchar(64)               CHECK (cpu_model_name ~ '\A[^\x00-\x1F]+\Z'),
	cpu_architecture  varchar(8)                CHECK (cpu_architecture ~ '\A[^\x00-\x20]+\Z'),
	core_count        int2                      CHECK (core_count > 0),
	thread_count      int2                      CHECK (thread_count > 0),
	kernel            varchar(80)               CHECK (kernel ~ '\A[^\x00-\x1F]+\Z'),
	boot_time         timestamp with time zone,
	last_probe_time   timestamp with time zone,
	time_offset       decimal,

	UNIQUE (wireguard_ip),
	UNIQUE (wireguard_privkey),
	UNIQUE (wireguard_pubkey)
);

CREATE TABLE machine_tags (
	hostname hostname NOT NULL REFERENCES machines,
	tag      varchar  NOT NULL CHECK (tag ~ '\A[^\x00-\x20]+\Z'),
	PRIMARY KEY (hostname, tag)
);

CREATE TABLE machine_pending_upgrades (
	hostname    hostname NOT NULL REFERENCES machines,
	package     varchar  NOT NULL CHECK (package ~ '\A[^\x00-\x20]+\Z'),
	old_version varchar  NOT NULL,
	new_version varchar  NOT NULL,
	PRIMARY KEY (hostname, package)
);

CREATE TABLE machine_addresses (
	hostname hostname NOT NULL REFERENCES machines,
	network  netname  NOT NULL REFERENCES networks(name),
	address  inet     NOT NULL,
	PRIMARY KEY (hostname, network, address),
	UNIQUE (network, address)
);

CREATE TABLE machine_forwards (
	hostname          hostname NOT NULL REFERENCES machines,
	port              port     NOT NULL,
	type              bytea    NOT NULL CHECK (type = 'ssh' OR type = 'wireguard'),
	next_destination  hostname NOT NULL REFERENCES machines(hostname) CHECK (next_destination != hostname),
	final_destination hostname NOT NULL REFERENCES machines(hostname) CHECK (final_destination != hostname),
	PRIMARY KEY (hostname, port, type),
	UNIQUE (hostname, type, final_destination)
);

/*
ubnt  905  wireguard  ra     ra
ubnt  906  wireguard  plato  plato
ubnt  907  wireguard  ra     elk
ra    908  wireguard  elk    elk

ubnt->ra->elk

How do we know dest port of (ubnt 907 wireguard ra elk)?
Look for (ra DEST_PORT wireguard _ elk)

How do we know dest port of (ra 908 wireguard elk elk)?
Look up wireguard_port in machines table for elk

*/
