/**
 * Notes:
 * "put 8-byte columns first then 4-bytes, 2-bytes and 1-byte columns last"
 * http://stackoverflow.com/questions/2966524/calculating-and-saving-space-in-postgresql
 *
 * We use `timestamp with time zone` because it still uses 8 bytes like
 * `timestamp without time zone`
 */

SET ROLE machine_manager;

CREATE DOMAIN hostname         AS character varying(32) CHECK(VALUE ~ '\A[-_a-z0-9]+\Z');
CREATE DOMAIN country          AS character(2)          CHECK(VALUE ~ '\A[a-z]{2}\Z');
CREATE DOMAIN ssh_port         AS integer               CHECK(VALUE > 0 AND VALUE <= 65536);
CREATE DOMAIN int4_gt0         AS integer               CHECK(VALUE > 0);
CREATE DOMAIN int2_gt0         AS integer               CHECK(VALUE > 0);
CREATE DOMAIN tag              AS character varying     CHECK(VALUE ~ '\A[^\x00-\x20]+\Z');
CREATE DOMAIN package          AS character varying     CHECK(VALUE ~ '\A[^\x00-\x20]+\Z');
CREATE DOMAIN kernel           AS character varying(64) CHECK(VALUE ~ '\A[^\x00-\x1F]+\Z');
CREATE DOMAIN cpu_model_name   AS character varying(64) CHECK(VALUE ~ '\A[^\x00-\x1F]+\Z');
CREATE DOMAIN cpu_architecture AS character varying(8)  CHECK(VALUE ~ '\A[^\x00-\x20]+\Z');

CREATE TABLE machines (
	-- Access information
	hostname          hostname NOT NULL PRIMARY KEY,
	ip                inet     NOT NULL,
	ssh_port          ssh_port NOT NULL,
	country           country,

	-- Hardware information
	ram_mb            int4_gt0,
	cpu_model_name    cpu_model_name,
	cpu_architecture  cpu_architecture,
	core_count        int2_gt0,
	thread_count      int2_gt0,

	-- OS information
	kernel            kernel,
	boot_time         timestamp with time zone,
	needs_reboot      boolean,

	-- Metadata
	added_time        timestamp with time zone NOT NULL DEFAULT now(),
	last_probe_time   timestamp with time zone
);
-- tags are like
-- state:mess, boot:ovh_vps, dc:ovh_bhs, role:custom_packages_server
-- state = {mess,zygote,converged,needs_converge,decommissioning}

CREATE TABLE machine_pending_upgrades (
	hostname  hostname NOT NULL REFERENCES machines,
	package   package  NOT NULL,
	PRIMARY KEY(hostname, package)
);

CREATE TABLE machine_tags (
	hostname  hostname NOT NULL REFERENCES machines,
	tag       tag      NOT NULL,
	PRIMARY KEY(hostname, tag)
);
