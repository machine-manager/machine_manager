SET ROLE machine_manager;

CREATE DOMAIN hostname         AS varchar(32)  CHECK (VALUE ~ '\A[-_a-z0-9]+\Z');
CREATE DOMAIN netname          AS varchar(32)  CHECK (VALUE ~ '\A[-_a-z0-9]+\Z');
CREATE DOMAIN port             AS integer      CHECK (VALUE > 0 AND VALUE <= 65536);
CREATE DOMAIN wireguard_key    AS bytea        CHECK (length(VALUE) = 44);

CREATE TABLE machines (
	-- Access information
	hostname                        hostname      NOT NULL PRIMARY KEY,
	wireguard_ip                    inet          NOT NULL,
	wireguard_port                  port          NOT NULL,
	wireguard_privkey               wireguard_key NOT NULL,
	wireguard_pubkey                wireguard_key NOT NULL,
	ssh_port                        port          NOT NULL,
	country                         character(2)  NOT NULL CHECK (country ~ '\A[a-z]{2}\Z'),
	release                         varchar(10)   NOT NULL CHECK (release ~ '\A[a-z]{2,10}\Z'),
	boot                            varchar(14)   NOT NULL CHECK (boot ~ '\A[a-z]{3,14}\Z'),

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

	-- Metadata
	added_time        timestamp with time zone NOT NULL DEFAULT now(),

	UNIQUE (wireguard_ip),
	UNIQUE (wireguard_privkey),
	UNIQUE (wireguard_pubkey)
);

CREATE TABLE machine_tags (
	hostname  hostname NOT NULL REFERENCES machines,
	tag       varchar  NOT NULL CHECK (tag ~ '\A[^\x00-\x20]+\Z'),
	PRIMARY KEY (hostname, tag)
);

CREATE TABLE machine_pending_upgrades (
	hostname     hostname NOT NULL REFERENCES machines,
	package      varchar  NOT NULL CHECK (package ~ '\A[^\x00-\x20]+\Z'),
	old_version  varchar  NOT NULL,
	new_version  varchar  NOT NULL,
	PRIMARY KEY (hostname, package)
);

CREATE TABLE networks (
	name    netname NOT NULL PRIMARY KEY,
	parent  netname REFERENCES networks(name) CHECK (parent != name)
);

CREATE TABLE machine_addresses (
	hostname  hostname NOT NULL REFERENCES machines,
	network   netname  NOT NULL REFERENCES networks(name),
	address   inet     NOT NULL,
	PRIMARY KEY (hostname, network, address),
	UNIQUE (network, address)
);

CREATE TABLE forwards (
	hostname    hostname     NOT NULL REFERENCES machines,
	type        bytea        NOT NULL CHECK (type = 'ssh' OR type = 'wireguard'),
	port        port         NOT NULL,
	destination hostname     NOT NULL REFERENCES machines(hostname) CHECK (destination != hostname),
	PRIMARY KEY (hostname, type, port)
);
