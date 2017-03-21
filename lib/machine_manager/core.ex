defmodule MachineManager.TooManyRowsError do
	defexception [:message]
end

defmodule MachineManager.UpgradeError do
	defexception [:message]
end

defmodule MachineManager.ConfigureError do
	defexception [:message]
end

defmodule MachineManager.ProbeError do
	defexception [:message]
end

defmodule MachineManager.Core do
	alias MachineManager.{ScriptWriter, Parallel, Repo, TooManyRowsError, UpgradeError, ConfigureError, ProbeError}
	alias Gears.StringUtil
	import Ecto.Query

	def list(hostname_regexp) do
		# We need to do our aggregations in subqueries to prevent rows from multiplying.
		# The Ecto below is an the equivalent of the SQL:
		_ = """
		SELECT    machines.hostname, ip, ssh_port, t.tags, u.pending_upgrades, last_probe_time, boot_time,
		          datacenter, country, cpu_model_name, cpu_architecture, ram_mb, core_count, thread_count, kernel
		FROM      machines
		LEFT JOIN (SELECT hostname, array_agg(tag::varchar)     AS tags             FROM machine_tags             GROUP BY 1) t USING (hostname)
		LEFT JOIN (SELECT hostname, array_agg(package::varchar) AS pending_upgrades FROM machine_pending_upgrades GROUP BY 1) u USING (hostname);
		"""

		tags_aggregate =
			from("machine_tags")
			|> select([t], %{
					hostname: t.hostname,
					tags:     fragment("array_agg(?::varchar)", t.tag)
				})
			|> group_by([t], t.hostname)

		pending_upgrades_aggregate =
			from("machine_pending_upgrades")
			|> select([u], %{
					hostname:         u.hostname,
					pending_upgrades: fragment("array_agg(?::varchar)", u.package)
				})
			|> group_by([u], u.hostname)

		machines_matching_regexp(hostname_regexp)
		|> select([m, t, u], %{
				hostname:         m.hostname,
				public_ip:        m.public_ip,
				wireguard_ip:     m.wireguard_ip,
				ssh_port:         m.ssh_port,
				tags:             t.tags,
				pending_upgrades: u.pending_upgrades,
				last_probe_time:  m.last_probe_time,
				boot_time:        m.boot_time,
				datacenter:       m.datacenter,
				country:          m.country,
				cpu_model_name:   m.cpu_model_name,
				cpu_architecture: m.cpu_architecture,
				ram_mb:           m.ram_mb,
				core_count:       m.core_count,
				thread_count:     m.thread_count,
				kernel:           m.kernel,
			})
		|> join(:left, [m], t in subquery(tags_aggregate),             t.hostname == m.hostname)
		|> join(:left, [m], u in subquery(pending_upgrades_aggregate), u.hostname == m.hostname)
		|> order_by(asc: :hostname)
		|> Repo.all
		|> fix_aggregate(:tags)
		|> fix_aggregate(:pending_upgrades)
	end

	defp fix_aggregate(rows, col) do
		Enum.map(rows, fn row ->
			fixed = case row[col] do
				nil   -> []
				other -> other
			end
			%{row | col => fixed}
		end)
	end

	def ssh_config() do
		rows =
			from("machines")
			|> order_by(asc: :hostname)
			|> select([:hostname, :public_ip, :ssh_port])
			|> Repo.all
		for row <- rows do
			:ok = IO.write(sql_row_to_ssh_config_entry(row) <> "\n")
		end
	end

	defp sql_row_to_ssh_config_entry(row) do
		"""
		Host #{row.hostname}
		  Hostname #{inet_to_ip(row.public_ip)}
		  Port #{row.ssh_port}
		"""
	end

	def configure_many(hostname_regexp, handle_configure_result, handle_waiting, show_progress) do
		hostnames =
			machines_matching_regexp(hostname_regexp)
			|> select([m], m.hostname)
			|> Repo.all
		if show_progress and hostnames |> length > 1 do
			raise ConfigureError, message: "Can't show progress when configuring more than one machine"
		end
		wrapped_configure = fn hostname ->
			try do
				configure(hostname, show_progress)
			rescue
				e in ConfigureError -> {:configure_error, e.message}
			end
		end
		task_map =
			hostnames
			|> Enum.map(fn hostname -> {hostname, Task.async(fn -> wrapped_configure.(hostname) end)} end)
			|> Map.new
		Parallel.block_on_tasks(task_map, handle_configure_result, handle_waiting, 2000)
	end

	def configure(hostname, show_progress \\ false) do
		{:ok, {ip, ssh_port, tags}} = Repo.transaction(fn ->
			row =
				machine(hostname)
				|> select([:public_ip, :ssh_port])
				|> Repo.all
				|> one_row
			tags = get_tags(hostname)
			{inet_to_ip(row.public_ip), row.ssh_port, tags}
		end)
		roles        = ScriptWriter.roles_for_tags(tags)
		script_cache = Path.expand("~/.cache/machine_manager/script_cache")
		basename     = roles |> Enum.sort |> Enum.join(",")
		output_file  = Path.join(script_cache, basename)
		File.mkdir_p!(script_cache)
		ScriptWriter.write_script_for_roles(roles, output_file)
		case transfer_file(output_file, "root", hostname, ".cache/machine_manager/script",
		                   before_rsync: "mkdir -p .cache/machine_manager") do
			{"", 0}          -> nil
			{out, exit_code} ->
				raise ConfigureError, message:
					"Uploading configuration script to machine #{inspect hostname} failed with exit code #{exit_code}; output:\n\n#{out}"
		end
		arguments    = [".cache/machine_manager/script"] ++ tags
		for arg <- arguments do
			if arg |> String.contains?(" ") do
				raise ConfigureError, message:
					"Argument list #{inspect arguments} contains an argument with a space: #{inspect arg}"
			end
		end
		case show_progress do
			true  ->
				exit_code = ssh_no_capture("root", ip, ssh_port, arguments |> Enum.join(" "))
				case exit_code do
					0 -> nil
					_ -> raise ConfigureError, message:
						"Configuring machine #{inspect hostname} failed with exit code #{exit_code}"
				end
			false ->
				{out, exit_code} = ssh("root", ip, ssh_port, arguments |> Enum.join(" "))
				case exit_code do
					0 -> nil
					_ -> raise ConfigureError, message:
						"Configuring machine #{inspect hostname} failed with exit code #{exit_code}; output:\n\n#{out}"
				end
		end
		:configured
	end

	# Transfer file `source` using rsync to user@host:dest
	#
	# If opts[:before_rsync] is non-nil, the given command is executed on the
	# remote before the rsync transfer.  This can be used to create a directory
	# needed for the transfer to succeed.
	defp transfer_file(source, user, hostname, dest, opts) do
		before_rsync = opts[:before_rsync]
		args = case before_rsync do
			nil -> []
			_   -> ["--rsync-path", "#{before_rsync} && rsync"]
		end ++ \
		["--protect-args", "--executability", source, "#{user}@#{hostname}:#{dest}"]
		System.cmd("rsync", args)
	end

	def probe_many(hostname_regexp, handle_probe_result, handle_waiting) do
		hostnames =
			machines_matching_regexp(hostname_regexp)
			|> select([m], m.hostname)
			|> Repo.all
		wrapped_probe = fn hostname ->
			try do
				{:probed, probe(hostname)}
			rescue
				e in ProbeError -> {:probe_error, e.message}
			end
		end
		task_map =
			hostnames
			|> Enum.map(fn hostname -> {hostname, Task.async(fn -> wrapped_probe.(hostname) end)} end)
			|> Map.new
		Parallel.block_on_tasks(task_map, handle_probe_result, handle_waiting, 2000)
	end

	def exec_many(hostname_regexp, command, handle_exec_result, handle_waiting) do
		hostnames =
			machines_matching_regexp(hostname_regexp)
			|> select([m], m.hostname)
			|> Repo.all
		task_map =
			hostnames
			|> Enum.map(fn hostname -> {hostname, Task.async(fn -> run_on_machine(hostname, command) end)} end)
			|> Map.new
		Parallel.block_on_tasks(task_map, handle_exec_result, handle_waiting, 2000)
	end

	defp write_probe_data_to_db(hostname, data) do
		Repo.transaction(fn -> 
			machine(hostname)
			|> Repo.update_all(set: [
				ram_mb:           data.ram_mb,
				cpu_model_name:   data.cpu_model_name,
				cpu_architecture: data.cpu_architecture,
				core_count:       data.core_count,
				thread_count:     data.thread_count,
				country:          data.country,
				kernel:           data.kernel,
				boot_time:        data.boot_time_ms |> DateTime.from_unix!(:millisecond),
				last_probe_time:  DateTime.utc_now(),
			])

			# Clear out existing pending upgrades
			from("machine_pending_upgrades")
			|> where([u], u.hostname == ^hostname)
			|> Repo.delete_all

			Repo.insert_all("machine_pending_upgrades",
				data.pending_upgrades |> Enum.map(fn package ->
					[hostname: hostname, package: package]
				end),
				on_conflict: :nothing
			)
		end)
	end

	def upgrade_many(hostname_regexp, handle_upgrade_result, handle_waiting) do
		hostnames =
			machines_matching_regexp(hostname_regexp)
			|> select([m], m.hostname)
			|> Repo.all
		wrapped_upgrade = fn hostname ->
			try do
				upgrade(hostname)
			rescue
				e in UpgradeError   -> {:upgrade_error,   e.message}
				e in ConfigureError -> {:configure_error, e.message}
			end
		end
		task_map =
			hostnames
			|> Enum.map(fn hostname -> {hostname, Task.async(fn -> wrapped_upgrade.(hostname) end)} end)
			|> Map.new
		Parallel.block_on_tasks(task_map, handle_upgrade_result, handle_waiting, 2000)
	end

	def upgrade(hostname) do
		packages = get_pending_upgrades_for_machine(hostname)
		case packages do
			[] -> :no_pending_upgrades
			_  ->
				# TODO: if disk is very low, first run
				# apt-get clean
				# apt-get autoremove --quiet --assume-yes
				command = """
				wait-for-dpkg-lock || true;
				apt-get update > /dev/null 2>&1 &&
				env \
					DEBIAN_FRONTEND=noninteractive \
					APT_LISTCHANGES_FRONTEND=none \
					APT_LISTBUGS_FRONTEND=none \
					apt-get install \
						-y --no-install-recommends --only-upgrade \
						-o Dpkg::Options::=--force-confdef \
						-o Dpkg::Options::=--force-confold \
						-- \
						#{packages |> Enum.map(&inspect/1) |> Enum.join(" ")} &&
				apt-get autoremove --quiet --assume-yes
				"""
				{output, exit_code} = run_on_machine(hostname, command)
				if exit_code != 0 do
					raise UpgradeError, message:
						"""
						Upgrade of #{hostname} failed with exit code #{exit_code}; output:

						#{output}
						"""
				end
				# Because packages upgrades can do things we don't like (e.g. install
				# files in /etc/cron.d), configure immediately after upgrading.
				configure(hostname)
				# Probe the machine so that we don't have obsolete 'pending upgrade' list
				probe(hostname)
				:upgraded
		end
	end

	def reboot_many(hostname_regexp, handle_exec_result, handle_waiting) do
		command = "nohup sh -c 'sleep 2; systemctl reboot' > /dev/null 2>&1 < /dev/null &"
		exec_many(hostname_regexp, command, handle_exec_result, handle_waiting)
	end

	def shutdown_many(hostname_regexp, handle_exec_result, handle_waiting) do
		command = "nohup sh -c 'sleep 2; systemctl poweroff' > /dev/null 2>&1 < /dev/null &"
		exec_many(hostname_regexp, command, handle_exec_result, handle_waiting)
	end

	@doc """
	Probe a machine and write the probe data to the database.
	"""
	def probe(hostname) do
		data = get_probe_data(hostname)
		write_probe_data_to_db(hostname, data)
		nil
	end

	@doc """
	Get probe data from a machine.
	"""
	def get_probe_data(hostname) do
		# machine_probe expects that we already ran an `apt-get update` when
		# it determines which packages can be upgraded.
		#
		# wait-for-dpkg-lock is included in the machine_probe package, but if
		# it's not installed, we continue anyway.
		command = """
		wait-for-dpkg-lock || true;
		apt-get update > /dev/null 2>&1;
		apt-get install -y --upgrade machine_probe > /dev/null 2>&1;
		machine_probe
		"""
		{output, exit_code} = run_on_machine(hostname, command)
		case exit_code do
			0 ->
				json = output |> get_json_from_probe_output
				case Poison.decode(json, keys: :atoms!) do
					{:ok, data}    -> data
					{:error, _err} ->
						raise ProbeError, message:
							"Probing machine #{inspect hostname} failed because JSON was corrupted:\n\n#{json}"
				end
			_ -> raise ProbeError, message:
				"Probing machine #{inspect hostname} failed with exit code #{exit_code}; output:\n\n#{output}"
		end
	end

	defp get_json_from_probe_output(s) do
		# Skip past any warnings like
		# "warning: the VM is running with native name encoding of latin1"
		s
		|> StringUtil.grep(~r/^\{/)
		|> hd
	end

	def _atoms() do
		# Make sure these atoms are in the atom table for our Poison.decode!
		[:ram_mb, :cpu_model_name, :cpu_architecture, :core_count, :thread_count,
		 :datacenter, :country, :kernel, :boot_time_ms, :pending_upgrades]
	end

	@spec run_on_machine(String.t, String.t) :: {String.t, integer}
	defp run_on_machine(hostname, command) do
		row =
			machine(hostname)
			|> select([:public_ip, :ssh_port])
			|> Repo.all
			|> one_row
		ssh("root", inet_to_ip(row.public_ip), row.ssh_port, command)
	end

	@doc """
	Runs `command` on machine at `ip` and `ssh_port` with user `user`, returns
	`{output, exit_code}`.  Output includes both stdout and stderr.
	"""
	@spec ssh(String.t, String.t, integer, String.t) :: {String.t, integer}
	def ssh(user, ip, ssh_port, command) do
		System.cmd("ssh", ["-q", "-p", "#{ssh_port}", "#{user}@#{ip}", command],
		           stderr_to_stdout: true,
		           # Make sure DISPLAY and SSH_ASKPASS are unset so that
		           # ssh-askpass or similar doesn't pop up.
		           env: [{"DISPLAY", ""}, {"SSH_ASKPASS", ""}])
	end

	@doc """
	Runs `command` on machine at `ip` and `ssh_port` with user `user`; outputs
	command's stdout and stderr to stdout in this terminal.  Returns `exit_code`.
	"""
	@spec ssh_no_capture(String.t, String.t, integer, String.t) :: integer
	def ssh_no_capture(user, ip, ssh_port, command) do
		%Porcelain.Result{status: exit_code} = \
			Porcelain.exec("ssh", ["-q", "-p", "#{ssh_port}", "#{user}@#{ip}", command],
			               out: {:file, Process.group_leader},
			               # "when using `Porcelain.Driver.Basic`, the only supported values
			               # are `nil` (stderr will be printed to the terminal) and `:out`."
			               err: nil,
			               # Make sure DISPLAY and SSH_ASKPASS are unset so that
			               # ssh-askpass or similar doesn't pop up.
			               env: [{"DISPLAY", ""}, {"SSH_ASKPASS", ""}])
		exit_code
	end

	@doc """
	Adds a machine from the database.
	"""
	@spec add(String.t, String.t, integer, String.t, [String.t]) :: nil
	def add(hostname, public_ip, ssh_port, datacenter, tags) do
		{:ok, _} = Repo.transaction(fn ->
			Repo.insert_all("machines", [[
				hostname:     hostname,
				public_ip:    ip_to_inet(public_ip),
				wireguard_ip: ip_to_inet(get_unused_wireguard_ip()),
				datacenter:   datacenter,
				ssh_port:     ssh_port,
			]])
			tag(hostname, tags)
		end)
	end

	@doc """
	Remove machines from the database.
	"""
	@spec rm_many(String.t) :: nil
	def rm_many(hostname_regexp) do
		{:ok, _} = Repo.transaction(fn ->
			from("machine_tags")             |> hostname_matching_regexp(hostname_regexp) |> Repo.delete_all
			from("machine_pending_upgrades") |> hostname_matching_regexp(hostname_regexp) |> Repo.delete_all
			machines_matching_regexp(hostname_regexp) |> Repo.delete_all
		end)
	end

	@doc """
	Add tags in enumerable `new_tags` to machine with hostname `hostname`.
	"""
	@spec tag(String.t, [String.t]) :: nil
	def tag(hostname, new_tags) do
		Repo.insert_all("machine_tags",
			new_tags |> Enum.map(fn tag ->
				[hostname: hostname, tag: tag]
			end),
			on_conflict: :nothing
		)
	end

	@doc """
	Add tags in enumerable `new_tags` to machine with hostnames matching `hostname_regexp`.
	"""
	@spec tag_many(String.t, [String.t]) :: nil
	def tag_many(hostname_regexp, new_tags) do
		Repo.transaction(fn ->
			hostnames =
				machines_matching_regexp(hostname_regexp)
				|> select([m], m.hostname)
				|> Repo.all
			Repo.insert_all("machine_tags",
				cartesian_product(hostnames, new_tags)
				|> Enum.map(fn {hostname, tag} ->
					[hostname: hostname, tag: tag]
				end),
				on_conflict: :nothing
			)
		end)
		nil
	end

	@spec cartesian_product(Enum.t, Enum.t) :: [{term, term}]
	defp cartesian_product(a, b) do
		for x <- a, y <- b, do: {x, y}
	end

	@doc """
	Remove tags in enumerable `remove_tags` from machine with hostnames matching `hostname_regexp`.
	"""
	@spec untag_many(String.t, [String.t]) :: nil
	def untag_many(hostname_regexp, remove_tags) do
		from("machine_tags")
		|> hostname_matching_regexp(hostname_regexp)
		|> where([t], t.tag in ^remove_tags)
		|> Repo.delete_all
		nil
	end

	@spec set_public_ip(String.t, String.t) :: nil
	def set_public_ip(hostname, public_ip) do
		from("machines")
		|> where([m], m.hostname == ^hostname)
		|> Repo.update_all(set: [public_ip: ip_to_inet(public_ip)])
		nil
	end

	@spec set_ssh_port_many(String.t, integer) :: nil
	def set_ssh_port_many(hostname_regexp, ssh_port) do
		machines_matching_regexp(hostname_regexp)
		|> Repo.update_all(set: [ssh_port: ssh_port])
		nil
	end

	def write_script_for_machine(hostname, output_file, opts) do
		tags  = get_tags(hostname)
		roles = ScriptWriter.roles_for_tags(tags)
		ScriptWriter.write_script_for_roles(roles, output_file, opts)
	end

	@spec get_tags(String.t) :: [String.t]
	def get_tags(hostname) do
		from("machine_tags")
		|> where([hostname: ^hostname])
		|> select([m], m.tag)
		|> Repo.all
	end

	@spec get_pending_upgrades_for_machine(String.t) :: [String.t]
	def get_pending_upgrades_for_machine(hostname) do
		from("machine_pending_upgrades")
		|> where([hostname: ^hostname])
		|> select([m], m.package)
		|> Repo.all
	end

	defp machine(hostname) do
		from("machines")
		|> where([hostname: ^hostname])
	end

	defp machines_matching_regexp(hostname_regexp) do
		from("machines")
		|> hostname_matching_regexp(hostname_regexp)
	end

	defp hostname_matching_regexp(queryable, hostname_regexp) do
		anchored_regexp = anchor_regexp(hostname_regexp)
		queryable
		|> where([t], fragment("? ~ ?", t.hostname, ^anchored_regexp))
	end

	defp anchor_regexp(hostname_regexp) do
		"^#{hostname_regexp}$"
	end

	defp one_row(rows) do
		case rows do
			[row] -> row
			_     -> raise TooManyRowsError, message: "Expected just one row, got #{rows |> length} rows"
		end
	end

	def get_unused_wireguard_ip() do
		existing_ips    = from("machines")
			|> select([m], m.wireguard_ip)
			|> Repo.all
			|> Enum.map(&inet_to_tuple/1)
			|> MapSet.new
		wireguard_start = {10, 10, 0,   0}
		wireguard_end   = {10, 10, 255, 255}
		ip_candidates   = Stream.iterate(wireguard_start, fn ip -> increment_ip_tuple(ip, wireguard_end) end)
		Enum.find(ip_candidates, fn ip -> not MapSet.member?(existing_ips, ip) end)
	end

	def make_wireguard_privkey() do
		{privkey_base64, 0} = System.cmd("wg", ["genkey"])
		privkey_base64
			|> String.trim_trailing("\n")
			|> Base.decode64!
	end

	def make_wireguard_pubkey(privkey) do
		# `wg pubkey` waits for EOF, but Erlang can't close stdin, so use some
		# bash that reads a single line and pipes it into `wg pubkey`.
		# https://github.com/alco/porcelain/issues/37
		%Porcelain.Result{status: 0, out: pubkey_base64} =
			Porcelain.exec("bash", ["-c", "head -n 1 | wg pubkey"], in: (privkey |> Base.encode64) <> "\n")
		pubkey_base64
			|> String.trim_trailing("\n")
			|> Base.decode64!
	end

	@typep ip_tuple :: {integer, integer, integer, integer}

	@spec increment_ip_tuple(ip_tuple, ip_tuple) :: ip_tuple
	def increment_ip_tuple(ip_tuple = {a, b, c, d}, maximum \\ {255, 255, 255, 255}) when ip_tuple != maximum do
		d = d + 1
		{c, d} = if d == 256, do: {c + 1, 0}, else: {c, d}
		{b, c} = if c == 256, do: {b + 1, 0}, else: {b, c}
		{a, b} = if b == 256, do: {a + 1, 0}, else: {a, b}
		{a, b, c, d}
	end

	defp ip_to_inet(ip) when is_tuple(ip),  do: %Postgrex.INET{address: ip}
	defp ip_to_inet(ip) when is_binary(ip), do: %Postgrex.INET{address: ip_to_tuple(ip)}

	@spec ip_to_tuple(String.t) :: ip_tuple
	defp ip_to_tuple(ip) do
		ip
		|> String.split(".")
		|> Enum.map(&String.to_integer/1)
		|> List.to_tuple
	end

	def inet_to_ip(%Postgrex.INET{address: {a, b, c, d}}) do
		"#{a}.#{b}.#{c}.#{d}"
	end

	def inet_to_tuple(%Postgrex.INET{address: {a, b, c, d}}) do
		{a, b, c, d}
	end
end
