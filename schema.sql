/**
 * Notes:
 * "put 8-byte columns first then 4-bytes, 2-bytes and 1-byte columns last"
 * http://stackoverflow.com/questions/2966524/calculating-and-saving-space-in-postgresql
 *
 * We use `timestamp with time zone` because it still uses 8 bytes like
 * `timestamp without time zone`
 */

SET ROLE machine_manager;

CREATE DOMAIN hostname         AS varchar(32)  CHECK(VALUE ~ '\A[-_a-z0-9]+\Z');
CREATE DOMAIN port             AS integer      CHECK(VALUE > 0 AND VALUE <= 65536);
CREATE DOMAIN int4_gt0         AS integer      CHECK(VALUE > 0);
CREATE DOMAIN int2_gt0         AS integer      CHECK(VALUE > 0);
CREATE DOMAIN tag              AS varchar      CHECK(VALUE ~ '\A[^\x00-\x20]+\Z');
CREATE DOMAIN package          AS varchar      CHECK(VALUE ~ '\A[^\x00-\x20]+\Z');
CREATE DOMAIN kernel           AS varchar(80)  CHECK(VALUE ~ '\A[^\x00-\x1F]+\Z');
CREATE DOMAIN cpu_model_name   AS varchar(64)  CHECK(VALUE ~ '\A[^\x00-\x1F]+\Z');
CREATE DOMAIN cpu_architecture AS varchar(8)   CHECK(VALUE ~ '\A[^\x00-\x20]+\Z');
CREATE DOMAIN wireguard_key    AS bytea        CHECK(length(VALUE) = 44);

CREATE TABLE machines (
	-- Access information
	hostname          hostname      NOT NULL PRIMARY KEY,
	public_ip         inet          NOT NULL,
	wireguard_ip      inet          NOT NULL,
	wireguard_port    port          NOT NULL,
	wireguard_privkey wireguard_key NOT NULL,
	wireguard_pubkey  wireguard_key NOT NULL,
	ssh_port          port          NOT NULL,
	host_machine      hostname,

	-- Probed information
	ram_mb            int4_gt0,
	cpu_model_name    cpu_model_name,
	cpu_architecture  cpu_architecture,
	core_count        int2_gt0,
	thread_count      int2_gt0,
	kernel            kernel,
	boot_time         timestamp with time zone,
	last_probe_time   timestamp with time zone,
	time_offset       decimal,

	-- Metadata
	added_time        timestamp with time zone NOT NULL DEFAULT now(),

	UNIQUE (public_ip, ssh_port),
	UNIQUE (wireguard_ip),
	UNIQUE (wireguard_privkey),
	UNIQUE (wireguard_pubkey),
	FOREIGN KEY (host_machine) references machines(hostname)
);

CREATE INDEX host_machine_idx ON machines (host_machine);

CREATE TABLE machine_tags (
	hostname  hostname NOT NULL REFERENCES machines,
	tag       tag      NOT NULL,
	PRIMARY KEY(hostname, tag)
);

CREATE TABLE machine_pending_upgrades (
	hostname    hostname NOT NULL REFERENCES machines,
	package     package  NOT NULL,
	old_version varchar  NOT NULL,
	new_version varchar  NOT NULL,
	PRIMARY KEY(hostname, package)
);
