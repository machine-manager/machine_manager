defmodule MachineManager.UpgradeError do
	defexception [:message]
end

defmodule MachineManager.BootstrapError do
	defexception [:message]
end

defmodule MachineManager.ConfigureError do
	defexception [:message]
end

defmodule MachineManager.ProbeError do
	defexception [:message]
end

defmodule MachineManager.Core do
	alias MachineManager.{
		ScriptWriter, Parallel, Repo, UpgradeError, BootstrapError,
		ConfigureError, ProbeError, WireGuard, ErlExecUtil}
	alias Gears.{StringUtil, FileUtil}
	import Ecto.Query

	def list(queryable) do
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
					pending_upgrades: fragment("array_agg(json_build_object('package', ?::varchar, 'old_version', ?, 'new_version', ?))", u.package, u.old_version, u.new_version)
				})
			|> group_by([u], u.hostname)

		queryable
		|> select([m, t, u], %{
				hostname:          m.hostname,
				public_ip:         m.public_ip,
				wireguard_ip:      m.wireguard_ip,
				wireguard_privkey: m.wireguard_privkey,
				ssh_port:          m.ssh_port,
				tags:              t.tags,
				pending_upgrades:  u.pending_upgrades,
				last_probe_time:   m.last_probe_time,
				boot_time:         m.boot_time,
				datacenter:        m.datacenter,
				country:           m.country,
				cpu_model_name:    m.cpu_model_name,
				cpu_architecture:  m.cpu_architecture,
				ram_mb:            m.ram_mb,
				core_count:        m.core_count,
				thread_count:      m.thread_count,
				kernel:            m.kernel,
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
			sql_row_to_ssh_config_entry(row)
		end
		|> Enum.join("\n")
	end

	def wireguard_config(hostname) do
		row =
			from("machines")
			|> select([:wireguard_privkey, :wireguard_ip])
			|> where([m], m.hostname == ^hostname)
			|> Repo.all
			|> hd
		listen_port = 51820
		peers       = []
		WireGuard.make_wireguard_config(row.wireguard_privkey, inet_to_ip(row.wireguard_ip), listen_port, peers)
	end

	defp sql_row_to_ssh_config_entry(row) do
		"""
		Host #{row.hostname}
		  Hostname #{inet_to_ip(row.public_ip)}
		  Port #{row.ssh_port}
		"""
	end

	def configure_many(queryable, handle_configure_result, handle_waiting, show_progress) do
		rows = list(queryable)
		if show_progress and rows |> length > 1 do
			raise(ConfigureError, "Can't show progress when configuring more than one machine")
		end
		wrapped_configure = fn row ->
			try do
				configure(row, show_progress)
			rescue
				e in ConfigureError -> {:configure_error, e.message}
				e in BootstrapError -> {:bootstrap_error, e.message}
			end
		end
		task_map =
			rows
			|> Enum.map(fn row -> {row.hostname, Task.async(fn -> wrapped_configure.(row) end)} end)
			|> Map.new
		Parallel.block_on_tasks(task_map, handle_configure_result, handle_waiting, 2000)
	end

	# Can raise ConfigureError or BootstrapError
	def configure(row, show_progress \\ false) do
		roles        = ScriptWriter.roles_for_tags(row.tags)
		script_cache = Path.expand("~/.cache/machine_manager/script_cache")
		basename     = case roles do
			[] -> "__no_roles__"
			_  -> roles |> Enum.sort |> Enum.join(",")
		end
		output_file  = Path.join(script_cache, basename)
		File.mkdir_p!(script_cache)
		ScriptWriter.write_script_for_roles(roles, output_file)
		wireguard_config = WireGuard.make_wireguard_config(row.wireguard_privkey, inet_to_ip(row.wireguard_ip), 51820, [])
		case transfer_file(output_file, row, ".cache/machine_manager/script",
		                   before_rsync: "mkdir -p .cache/machine_manager") do
			{"", 0}          -> nil
			{out, exit_code} -> raise_upload_error(row.hostname, out, exit_code, "configuration script")
		end
		case transfer_content(wireguard_config, row, ".cache/machine_manager/wg0.conf") do
			{"", 0}          -> nil
			{out, exit_code} -> raise_upload_error(row.hostname, out, exit_code, "WireGuard configuration")
		end
		arguments = [".cache/machine_manager/script"] ++ row.tags
		for arg <- arguments do
			if arg |> String.contains?(" ") do
				raise(ConfigureError,
					"Argument list #{inspect arguments} contains an argument with a space: #{inspect arg}")
			end
		end
		case show_progress do
			true ->
				{"", exit_code} = run_on_machine(row, arguments |> Enum.join(" "), false)
				case exit_code do
					0 -> :configured
					_ -> raise(ConfigureError,
						"Configuring machine #{inspect row.hostname} failed with exit code #{exit_code}")
				end
			false ->
				{out, exit_code} = run_on_machine(row, arguments |> Enum.join(" "))
				case exit_code do
					0 -> :configured
					_ ->
						case erlang_missing_error?(out) do
							true ->
								# Machine seems to be missing erlang, so bootstrap it, then try running the script again.
								bootstrap(row)
								{out, exit_code} = run_on_machine(row, arguments |> Enum.join(" "))
								case exit_code do
									0 -> :configured
									_ -> raise_configure_error(row.hostname, out, exit_code)
								end
							false -> raise_configure_error(row.hostname, out, exit_code)
						end
				end
		end
	end

	defp raise_upload_error(hostname, out, exit_code, upload_description) do
		raise(ConfigureError,
			"""
			Uploading #{upload_description} to machine #{inspect hostname} \
			failed with exit code #{exit_code}; output:

			#{out}
			""")
	end

	defp raise_configure_error(hostname, out, exit_code) do
		raise(ConfigureError,
			"""
			Configuring machine #{inspect hostname} failed with exit code #{exit_code}; output:

			#{out}
			""")
	end

	defp erlang_missing_error?(out) do
		out =~ ~r"/usr/bin/env:.*escript.*: No such file or directory"
	end

	defmacro content(filename) do
		File.read!(filename)
	end

	def bootstrap_many(queryable, handle_bootstrap_result, handle_waiting) do
		rows = list(queryable)
		wrapped_bootstrap = fn row ->
			try do
				bootstrap(row)
			rescue
				e in BootstrapError -> {:bootstrap_error, e.message}
			end
		end
		task_map =
			rows
			|> Enum.map(fn row -> {row.hostname, Task.async(fn -> wrapped_bootstrap.(row) end)} end)
			|> Map.new
		Parallel.block_on_tasks(task_map, handle_bootstrap_result, handle_waiting, 2000)
	end

	@doc """
	Prepare a system so that it can be configured with erlang escripts.  To do this,
	install erlang + curl + ar, but get erlang from our custom-packages repository,
	so first install custom-packages-client and the spiped_key, along with the
	custom-packages apt key and a suitable apt/sources.list.
	"""
	def bootstrap(row) do
		with \
			{_, 0} <-
				run_on_machine(row,
					"""
					apt-get update -q &&
					env DEBIAN_FRONTEND=noninteractive apt-get --quiet --assume-yes install rsync &&
					mkdir -p /etc/custom-packages-client ~/.cache/machine_manager/bootstrap
					"""),
			{"", 0} <-
				transfer_content(custom_packages_spiped_key(), row,
					"/etc/custom-packages-client/spiped_key"),
			{"", 0} <-
				transfer_file(custom_packages_client_deb_filename(), row,
					".cache/machine_manager/bootstrap/custom-packages-client.deb"),
			{"", 0} <-
				transfer_content(bootstrap_setup(), row,
					".cache/machine_manager/bootstrap/setup"),
			{"", 0} <-
				transfer_content(custom_packages_apt_key(), row,
					".cache/machine_manager/bootstrap/custom-packages-apt-key"),
			{_, 0} <-
				run_on_machine(row,
					"""
					chattr -i /etc/apt/trusted.gpg &&
					apt-key add ~/.cache/machine_manager/bootstrap/custom-packages-apt-key &&
					chmod +x ~/.cache/machine_manager/bootstrap/setup &&
					CUSTOM_PACKAGES_PASSWORD=#{custom_packages_password()} ~/.cache/machine_manager/bootstrap/setup
					""")
		do
			:bootstrapped
		else
			{out, exit_code} ->
				raise(BootstrapError,
					"""
					Bootstrapping machine #{inspect row.hostname} failed with exit code #{exit_code}; output:

					#{out}
					""")
		end
	end

	defp custom_packages_apt_key() do
		content("../role_custom_packages/files/apt_keys/2AAA29C8 Custom Packages.txt")
	end

	defp custom_packages_spiped_key() do
		content("../role_custom_packages_server/files/etc/custom-packages-server/spiped_key")
	end

	defp custom_packages_password() do
		content("../role_custom_packages_server/files/etc/custom-packages-server/unencrypted_password")
	end

	defp bootstrap_setup() do
		content("bootstrap/setup")
	end

	defp custom_packages_client_deb_filename() do
		packages_directory = "/var/custom-packages"
		{:ok, list} = File.ls(packages_directory)
		deb = list
			|> Enum.filter(fn filename -> filename =~ ~r/^custom-packages-client_.*_all\.deb$/ end)
			|> Enum.sort
			|> List.last
		Path.join(packages_directory, deb)
	end

	# Transfer content `content` using rsync to machine described by `row` to `dest`
	#
	# Returns {rsync_out, rsync_exit_code}
	defp transfer_content(content, row, dest, opts \\ []) do
		temp = FileUtil.temp_path("machine_manager_transfer_content")
		File.write!(temp, content)
		try do
			transfer_file(temp, row, dest, opts)
		after
			FileUtil.rm_f!(temp)
		end
	end

	defp transfer_file(source_file, row, dest, opts \\ []) do
		transfer_files([source_file], row, dest, opts)
	end

	# Transfer files `source_files` using rsync to machine described by `row` to `dest`
	#
	# If opts[:before_rsync] is non-nil, the given command is executed on the
	# remote before the rsync transfer.  This can be used to create a directory
	# needed for the transfer to succeed.
	#
	# Returns {rsync_out, rsync_exit_code}
	defp transfer_files(source_files, row, dest, opts) do
		before_rsync = opts[:before_rsync]
		args = case before_rsync do
			nil -> []
			_   -> ["--rsync-path", "#{before_rsync} && rsync"]
		end ++
		["-e", "ssh -p #{row.ssh_port}", "--protect-args", "--executability"] ++
		source_files ++ ["root@#{inet_to_ip(row.public_ip)}:#{dest}"]
		System.cmd("rsync", args)
	end

	def probe_many(queryable, handle_probe_result, handle_waiting) do
		rows = list(queryable)
		wrapped_probe = fn row ->
			try do
				{:probed, probe(row)}
			rescue
				e in ProbeError -> {:probe_error, e.message}
			end
		end
		task_map =
			rows
			|> Enum.map(fn row -> {row.hostname, Task.async(fn -> wrapped_probe.(row) end)} end)
			|> Map.new
		Parallel.block_on_tasks(task_map, handle_probe_result, handle_waiting, 2000)
	end

	def exec_many(queryable, command, handle_exec_result, handle_waiting) do
		rows = list(queryable)
		task_map =
			rows
			|> Enum.map(fn row -> {row.hostname, Task.async(fn -> run_on_machine(row, command) end)} end)
			|> Map.new
		Parallel.block_on_tasks(task_map, handle_exec_result, handle_waiting, 2000)
	end

	defp write_probe_data_to_db(hostname, data) do
		{:ok, _} = Repo.transaction(fn ->
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
				data.pending_upgrades |> Enum.map(fn %{name: name, old_version: old_version, new_version: new_version} ->
					[hostname: hostname, package: name, old_version: old_version, new_version: new_version]
				end),
				on_conflict: :nothing
			)
		end)
	end

	def upgrade_many(queryable, handle_upgrade_result, handle_waiting) do
		rows = list(queryable)
		wrapped_upgrade = fn row ->
			try do
				upgrade(row)
			rescue
				e in UpgradeError   -> {:upgrade_error,   e.message}
				e in ConfigureError -> {:configure_error, e.message}
				e in BootstrapError -> {:bootstrap_error, e.message}
				e in ProbeError     -> {:probe_error,     e.message}
			end
		end
		task_map =
			rows
			|> Enum.map(fn row -> {row.hostname, Task.async(fn -> wrapped_upgrade.(row) end)} end)
			|> Map.new
		Parallel.block_on_tasks(task_map, handle_upgrade_result, handle_waiting, 2000)
	end

	# Can raise UpgradeError, ConfigureError, or BootstrapError
	def upgrade(row) do
		case row.pending_upgrades do
			[]       -> :no_pending_upgrades
			upgrades ->
				upgrade_args =
					upgrades
					|> Enum.map(fn upgrade -> "#{upgrade["package"]}=#{upgrade["new_version"]}" end)
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
						#{upgrade_args |> Enum.map(&inspect/1) |> Enum.join(" ")} &&
				apt-get autoremove --quiet --assume-yes
				"""
				{output, exit_code} = run_on_machine(row, command)
				if exit_code != 0 do
					raise(UpgradeError,
						"""
						Upgrade of #{row.hostname} failed with exit code #{exit_code}; output:

						#{output}
						""")
				end
				# Because packages upgrades can do things we don't like (e.g. install
				# files in /etc/cron.d), configure immediately after upgrading.
				configure(row)
				# Probe the machine so that we don't have obsolete 'pending upgrade' list
				probe(row)
				:upgraded
		end
	end

	def reboot_many(queryable, handle_exec_result, handle_waiting) do
		command = "nohup sh -c 'sleep 2; systemctl reboot' > /dev/null 2>&1 < /dev/null &"
		exec_many(queryable, command, handle_exec_result, handle_waiting)
	end

	def shutdown_many(queryable, handle_exec_result, handle_waiting) do
		command = "nohup sh -c 'sleep 2; systemctl poweroff' > /dev/null 2>&1 < /dev/null &"
		exec_many(queryable, command, handle_exec_result, handle_waiting)
	end

	@doc """
	Probe a machine and write the probe data to the database.
	"""
	def probe(row) do
		data = get_probe_data(row)
		# TODO: don't assume that it's the same machine; make sure some unique ID is the same
		write_probe_data_to_db(row.hostname, data)
		nil
	end

	@doc """
	Get probe data from a machine.
	"""
	def get_probe_data(row) do
		# machine_probe expects that we already ran an `apt-get update` when
		# it determines which packages can be upgraded.
		#
		# wait-for-dpkg-lock is included in the machine_probe package, but if
		# it's not installed, we continue anyway.
		command = """
		wait-for-dpkg-lock || true;
		apt-get update > /dev/null 2>&1;
		machine_probe
		"""
		{output, exit_code} = run_on_machine(row, command)
		case exit_code do
			0 ->
				json = output |> get_json_from_probe_output
				case Poison.decode(json, keys: :atoms!) do
					{:ok, data}    -> data
					{:error, _err} ->
						raise(ProbeError,
							"""
							Probing machine #{inspect row.hostname} failed because JSON was corrupted:

							#{json}
							""")
				end
			_ -> raise(ProbeError,
				"""
				Probing machine #{inspect row.hostname} failed with exit code #{exit_code}; output:

				#{output}
				""")
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
		[
			:ram_mb, :cpu_model_name, :cpu_architecture, :core_count, :thread_count,
			:datacenter, :country, :kernel, :boot_time_ms, :pending_upgrades,
			# Keys in :pending_upgrades
			:name, :old_version, :new_version, :origin, :architecture
		]
	end

	@spec run_on_machine(%{public_ip: Postgrex.INET.t, ssh_port: integer}, String.t, boolean) :: {String.t, integer}
	defp run_on_machine(row, command, capture \\ true) do
		ssh("root", inet_to_ip(row.public_ip), row.ssh_port, command, capture)
	end

	@doc """
	Runs `command` on machine at `ip` and `ssh_port` with user `user`, returns
	`{output, exit_code}`.  If `capture` is `true`, `output` includes both
	stdout and stderr; if `false`, both stdout and stderr are echoed to the
	terminal and `output` is `""`.
	"""
	@spec ssh(String.t, String.t, integer, String.t, boolean) :: {String.t, integer}
	def ssh(user, ip, ssh_port, command, capture) do
		{stdout, stderr} = case capture do
			true  -> {true,    :stdout}
			false -> {&echo/3, &echo/3}
		end
		# We use erlexec instead of System.cmd or Porcelain because Erlang's
		# open_port({spawn_executable, ...}, ...) breaks with ssh ControlMaster:
		# it waits for the daemonized ssh [mux] process to exit before returning.
		# erlexec doesn't have this problem.  The cause of the problem is probably
		# https://bugzilla.mindrot.org/show_bug.cgi?id=1988 (xenial comes with
		# OpenSSH 7.2p2, released before the fix.)
		args = ["-q", "-p", "#{ssh_port}", "#{user}@#{ip}", command]
		Exexec.run(["/usr/bin/ssh" | args], stdout: stdout, stderr: stderr, sync: true, env: env_for_ssh())
		|> ErlExecUtil.ret_to_tuple
	end

	def echo(_stream, _os_pid, data) do
		IO.write(data)
	end

	defp env_for_ssh() do
		# Make sure DISPLAY and SSH_ASKPASS are unset so that ssh-askpass
		# or similar doesn't pop up.
		%{"DISPLAY" => "", "SSH_ASKPASS" => ""}
	end

	@doc """
	Adds a machine from the database.
	"""
	@spec add(String.t, String.t, integer, String.t, [String.t]) :: nil
	def add(hostname, public_ip, ssh_port, datacenter, tags) do
		wireguard_privkey = WireGuard.make_wireguard_privkey()
		wireguard_pubkey  = WireGuard.get_wireguard_pubkey(wireguard_privkey)
		{:ok, _} = Repo.transaction(fn ->
			Repo.insert_all("machines", [[
				hostname:          hostname,
				public_ip:         ip_to_inet(public_ip),
				wireguard_ip:      ip_to_inet(get_unused_wireguard_ip()),
				wireguard_privkey: wireguard_privkey,
				wireguard_pubkey:  wireguard_pubkey,
				datacenter:        datacenter,
				ssh_port:          ssh_port,
			]])
			tag(hostname, tags)
		end)
	end

	def get_unused_wireguard_ip() do
		existing_ips = from("machines")
			|> select([m], m.wireguard_ip)
			|> Repo.all
			|> Enum.map(&inet_to_tuple/1)
			|> MapSet.new
		wireguard_start = {10, 10, 0, 0}
		wireguard_end   = {10, 10, 255, 255}
		ip_candidates   = Stream.iterate(wireguard_start, fn ip -> increment_ip_tuple(ip, wireguard_end) end)
		Enum.find(ip_candidates, fn ip -> not MapSet.member?(existing_ips, ip) end)
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

	@doc """
	Remove machines from the database.
	"""
	@spec rm_many(Ecto.Queryable.t) :: nil
	def rm_many(queryable) do
		{:ok, _} = Repo.transaction(fn ->
			hostnames =
				queryable
				|> select([m], m.hostname)
				|> Repo.all
			from("machine_tags")             |> where([t], t.hostname in ^hostnames) |> Repo.delete_all
			from("machine_pending_upgrades") |> where([u], u.hostname in ^hostnames) |> Repo.delete_all
			from("machines")                 |> where([m], m.hostname in ^hostnames) |> Repo.delete_all
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
	Add tags in enumerable `new_tags` to machines matching `queryable`.
	"""
	@spec tag_many(Ecto.Queryable.t, [String.t]) :: nil
	def tag_many(queryable, new_tags) do
		{:ok, _} = Repo.transaction(fn ->
			hostnames =
				queryable
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
	Remove tags in enumerable `remove_tags` from machines matching `queryable`.
	"""
	@spec untag_many(Ecto.Queryable.t, [String.t]) :: nil
	def untag_many(queryable, remove_tags) do
		{:ok, _} = Repo.transaction(fn ->
			hostnames =
				queryable
				|> select([m], m.hostname)
				|> Repo.all
			from("machine_tags")
			|> where([t], t.hostname in ^hostnames)
			|> where([t], t.tag      in ^remove_tags)
			|> Repo.delete_all
			nil
		end)
	end

	@spec set_public_ip(String.t, String.t) :: nil
	def set_public_ip(hostname, public_ip) do
		from("machines")
		|> where([m], m.hostname == ^hostname)
		|> Repo.update_all(set: [public_ip: ip_to_inet(public_ip)])
		nil
	end

	@spec set_ssh_port_many(Ecto.Queryable.t, integer) :: nil
	def set_ssh_port_many(queryable, ssh_port) do
		queryable
		|> Repo.update_all(set: [ssh_port: ssh_port])
		nil
	end

	@spec rekey_wireguard_many(Ecto.Queryable.t) :: nil
	def rekey_wireguard_many(queryable) do
		{:ok, _} = Repo.transaction(fn ->
			hostnames =
				queryable
				|> select([m], m.hostname)
				|> Repo.all
			for hostname <- hostnames do
				rekey_wireguard(hostname)
			end
		end)
		nil
	end

	@spec rekey_wireguard(String.t) :: nil
	def rekey_wireguard(hostname) do
		privkey = WireGuard.make_wireguard_privkey()
		pubkey  = WireGuard.get_wireguard_pubkey(privkey)
		machine(hostname)
		|> Repo.update_all(set: [wireguard_privkey: privkey, wireguard_pubkey: pubkey])
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

	def machine(hostname) do
		from("machines")
		|> where([hostname: ^hostname])
	end

	def machines_matching_regexp(hostname_regexp) do
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
