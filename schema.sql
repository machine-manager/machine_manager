/**
 * Notes:
 * "put 8-byte columns first then 4-bytes, 2-bytes and 1-byte columns last"
 * http://stackoverflow.com/questions/2966524/calculating-and-saving-space-in-postgresql
 *
 * We use `timestamp with time zone` because it still uses 8 bytes like
 * `timestamp without time zone`
 */

/* As user postgres:
CREATE ROLE machine_manager LOGIN;
CREATE DATABASE machine_manager;
GRANT ALL PRIVILEGES ON DATABASE machine_manager TO machine_manager;
ALTER DATABASE machine_manager SET bytea_output TO 'escape';
*/

SET ROLE machine_manager;

DROP DOMAIN country CASCADE;
CREATE DOMAIN country AS character(2) CHECK(
	length(VALUE) = 2 AND
	lower(VALUE) = VALUE
);

DROP DOMAIN ssh_port CASCADE;
CREATE DOMAIN ssh_port AS integer CHECK(
	VALUE > 0 AND VALUE <= 65536
);

DROP DOMAIN ram_mb CASCADE;
CREATE DOMAIN ram_mb AS integer CHECK(
	VALUE > 0
);

DROP TABLE machines;
CREATE TABLE machines (
	id                serial8 NOT NULL PRIMARY KEY,
	hostname          character varying(32) NOT NULL,
	ip                inet NOT NULL,
	ssh_port          ssh_port NOT NULL,
	country           country,
	ram_mb            ram_mb,
	boot_time         timestamp with time zone NOT NULL,
	kernel            bytea,
	pending_upgrades  character varying[],
	needs_reboot      boolean,
	tags              character varying[]
);
-- tags are like
-- state:mess, boot:ovh_vps, dc:ovh_bhs, role:custom_packages_server
-- state = {mess,zygote,converged,needs_converge,decommissioning}
