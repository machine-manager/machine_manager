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
		ConfigureError, ProbeError, WireGuard, ErlExecUtil, Graph}
	alias Gears.{StringUtil, FileUtil}
	import Ecto.Query

	def list(queryable) do
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
				wireguard_pubkey:  m.wireguard_pubkey,
				wireguard_privkey: m.wireguard_privkey,
				ssh_port:          m.ssh_port,
				tags:              t.tags,
				pending_upgrades:  u.pending_upgrades,
				last_probe_time:   type(m.last_probe_time, :utc_datetime),
				boot_time:         type(m.boot_time,       :utc_datetime),
				datacenter:        m.datacenter,
				cpu_model_name:    m.cpu_model_name,
				cpu_architecture:  m.cpu_architecture,
				ram_mb:            m.ram_mb,
				core_count:        m.core_count,
				thread_count:      m.thread_count,
				time_offset:       m.time_offset,
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

	defp sql_row_to_ssh_config_entry(row) do
		"""
		Host #{row.hostname}
		  Hostname #{to_ip_string(row.public_ip)}
		  Port #{row.ssh_port}
		"""
	end

	@spec wireguard_config(String.t) :: String.t
	def wireguard_config(hostname) do
		all_machines     = from("machines") |> list
		all_machines_map = all_machines |> Enum.map(fn row -> {row.hostname, row} end) |> Map.new
		row              = all_machines_map[hostname]
		listen_port      = 51820
		graphs           = connectivity_graphs(all_machines)
		wireguard_peers  = get_wireguard_peers(row, graphs, all_machines_map)
		WireGuard.make_wireguard_config(row.wireguard_privkey, to_ip_string(row.wireguard_ip), listen_port, wireguard_peers)
	end

	@spec hosts_json_file(String.t) :: String.t
	def hosts_json_file(hostname) do
		all_machines     = from("machines") |> list
		all_machines_map = all_machines |> Enum.map(fn row -> {row.hostname, row} end) |> Map.new
		row              = all_machines_map[hostname]
		graphs           = connectivity_graphs(all_machines)
		subdomains       = subdomains(all_machines)
		make_hosts_json_file(row, graphs, subdomains, all_machines_map)
	end

	def configure_many(queryable, handle_configure_result, handle_waiting, show_progress, allow_warnings) do
		rows = list(queryable)
		if show_progress and length(rows) > 1 do
			raise(ConfigureError, "Can't show progress when configuring more than one machine")
		end
		# Even through we're building a connectivity graph that includes all
		# machines, we don't actually need to do compile scripts for *all*
		# machines because make_connectivity_graph just runs require_file on
		# connections.exs files.
		write_scripts_for_machines(rows, allow_warnings)
		all_machines      = from("machines") |> list
		all_machines_map  = all_machines |> Enum.map(fn row -> {row.hostname, row} end) |> Map.new
		graphs            = connectivity_graphs(all_machines)
		wrapped_configure = fn row ->
			try do
				configure(row, graphs, all_machines_map, show_progress)
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

	@script_cache Path.expand("~/.cache/machine_manager/script_cache")

	# We use this to avoid compiling a script N times for N machines with the same roles.
	defp write_scripts_for_machines(rows, allow_warnings \\ false) do
		unique_role_combinations =
			rows
			|> Enum.map(fn row -> ScriptWriter.roles_for_tags(row.tags) end)
			|> MapSet.new
		File.mkdir_p!(@script_cache)
		pmap(unique_role_combinations, fn roles ->
			script_file = script_filename_for_roles(roles)
			ScriptWriter.write_script_for_roles(roles, script_file, allow_warnings: allow_warnings)
		end, 2 * 60 * 1000)
	end

	def pmap(collection, func, timeout) do
		collection
		|> Enum.map(&(Task.async(fn -> func.(&1) end)))
		|> Enum.map(fn task -> Task.await(task, timeout) end)
	end

	@doc """
	Output a machine connectivity graph as a .dot file to stdout, for use with Graphviz
	"""
	@spec connectivity(String.t) :: nil
	def connectivity(type_s) do
		all_machines = from("machines") |> list
		graphs       = connectivity_graphs(all_machines)
		type         = type_s |> String.to_atom
		edge_color   = color_for_connectivity_type(type)
		edges        = graphs[type]
			|> Enum.flat_map(fn {a, bs} ->
					Enum.map(bs, fn b -> "#{inspect a} -- #{inspect b} [color=#{inspect edge_color}];" end)
				end)
		# `strict` dedupes the edges for us
		dot = """
		strict graph connectivity {
			graph [fontname="sans-serif"];
			node  [fontname="sans-serif", fontsize="10pt"];
			edge  [fontname="sans-serif"];

		#{edges |> Enum.join("\n") |> indent}
		}
		"""
		:ok = IO.write(dot)
	end

	defp color_for_connectivity_type(:wireguard), do: "red"
	defp color_for_connectivity_type(:public),    do: "black"

	defp indent(s) do
		s
		|> String.split("\n")
		|> Enum.map(fn line -> "\t#{line}" end)
		|> Enum.join("\n")
	end

	def connectivity_graphs(all_machines) do
		connections = for row <- all_machines do
			hostname    = row.hostname
			connections = partial_connections_for_machine(row)
			{hostname, connections}
		end
		%{
			wireguard: connectivity_graph(connections, :wireguard),
			public:    connectivity_graph(connections, :public),
		}
	end

	defp connectivity_graph(connections, key) do
		connections
		|> Enum.map(fn {hostname, connections} -> {hostname, connections[key]} end)
		|> Enum.reject(&is_nil/1)
		|> Map.new
		|> Graph.bidirectionalize
	end

	# Returns %{
	#   wireguard: a partial list of hostnames that machine `row` should be connected to with WireGuard
	#   public:    a partial list of hostnames that machine `row` should know about in /etc/hosts
	# }
	# Partial because the lists don't include machines with roles connected to *this* machine.
	defp partial_connections_for_machine(row) do
		tags     = row.tags
		hostname = row.hostname
		roles    = ScriptWriter.roles_for_tags(tags)
		for role <- roles do
			load_connections_module_for_role(role)
			mod = connections_module_for_role(role)
			if function_exported?(mod, :connections, 2) do
				connections_descriptor = apply(mod, :connections, [tags, from("machines")])
				wireguard_hostnames = case connections_descriptor[:wireguard] do
					nil       -> []
					queryable -> queryable |> select([m], m.hostname) |> Repo.all
				end |> MapSet.new |> MapSet.delete(hostname)
				# We use MapSet.delete(hostname) because a machine should not be connected to itself.
				public_hostnames = case connections_descriptor[:public] do
					nil       -> []
					queryable -> queryable |> select([m], m.hostname) |> Repo.all
				end |> MapSet.new |> MapSet.delete(hostname) |> MapSet.union(wireguard_hostnames)
				# A wireguard connection also implies a public-internet connection.
				%{wireguard: wireguard_hostnames, public: public_hostnames}
			end
		end
		|> Enum.reject(&is_nil/1)
		|> Enum.reduce(%{wireguard: MapSet.new, public: MapSet.new}, fn(map, acc) ->
			%{
				wireguard: MapSet.union(acc.wireguard, map[:wireguard] || MapSet.new),
				public:    MapSet.union(acc.public,    map[:public]    || MapSet.new),
			}
		end)
	end

	def subdomains(all_machines) do
		tuples = for row <- all_machines do
			hostname   = row.hostname
			{hostname, subdomains_for_machine(row)}
		end
		%{
			wireguard: tuples |> Enum.map(fn {hostname, m} -> {hostname, m.wireguard} end) |> Map.new,
			public:    tuples |> Enum.map(fn {hostname, m} -> {hostname, m.public}    end) |> Map.new,
		}
	end

	defp subdomains_for_machine(row) do
		tags  = row.tags
		roles = ScriptWriter.roles_for_tags(tags)
		for role <- roles do
			load_connections_module_for_role(role)
			mod = connections_module_for_role(role)
			if function_exported?(mod, :subdomains, 1) do
				subdomains_descriptor = apply(mod, :subdomains, [tags])
				%{
					wireguard: (subdomains_descriptor[:wireguard] || []) |> MapSet.new,
					public:    (subdomains_descriptor[:public]    || []) |> MapSet.new,
				}
			end
		end
		|> Enum.reject(&is_nil/1)
		|> Enum.reduce(%{wireguard: MapSet.new, public: MapSet.new}, fn(map, acc) ->
			%{
				wireguard: MapSet.union(acc.wireguard, map[:wireguard]),
				public:    MapSet.union(acc.public,    map[:public]),
			}
		end)
	end

	# For a given role, return the module that contains the `connections()` function.
	@spec connections_module_for_role(String.t) :: module
	defp connections_module_for_role(role) do
		role
		|> String.split("_")
		|> Enum.map(&String.capitalize/1)
		|> Enum.join
		|> (fn s -> "Elixir.Role#{s}.Connections" end).()
		|> String.to_atom
	end

	@spec load_connections_module_for_role(String.t) :: nil
	defp load_connections_module_for_role(role) do
		# Assume that all role projects are stored as siblings to machine_manager/
		# First |> dirname is to walk about of lib/
		role_projects_dir = __DIR__ |> Path.dirname |> Path.dirname
		connections_exs   = Path.join(role_projects_dir, "role_#{role}/lib/connections.exs")
		if File.exists?(connections_exs) do
			# TODO: don't assume the file in the working directory is known-good
			Code.require_file(connections_exs)
		end
		nil
	end

	# This function assumes an up-to-date configuration script is already present
	# in @script_cache (call write_scripts_for_machines first).
	#
	# Can raise ConfigureError or BootstrapError
	def configure(row, graphs, all_machines_map, show_progress \\ false) do
		roles            = ScriptWriter.roles_for_tags(row.tags)
		script_file      = script_filename_for_roles(roles)
		wireguard_peers  = get_wireguard_peers(row, graphs, all_machines_map)
		wireguard_config = WireGuard.make_wireguard_config(row.wireguard_privkey, to_ip_string(row.wireguard_ip), 51820, wireguard_peers)
		subdomains       = subdomains(all_machines_map |> Map.values)
		hosts_file       = make_hosts_json_file(row, graphs, subdomains, all_machines_map)
		case transfer_file(script_file, row, ".cache/machine_manager/script",
		                   before_rsync: "mkdir -p .cache/machine_manager") do
			{"", 0}          -> nil
			{out, exit_code} -> raise_upload_error(row.hostname, out, exit_code, "configuration script")
		end
		case transfer_content(wireguard_config, row, ".cache/machine_manager/wg0.conf") do
			{"", 0}          -> nil
			{out, exit_code} -> raise_upload_error(row.hostname, out, exit_code, "WireGuard configuration")
		end
		case transfer_content(hosts_file, row, ".cache/machine_manager/hosts.json") do
			{"", 0}          -> nil
			{out, exit_code} -> raise_upload_error(row.hostname, out, exit_code, "hosts.json")
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
				{"", exit_code} = run_on_machine(row, configure_command(arguments), false)
				case exit_code do
					0 -> :configured
					_ -> raise(ConfigureError,
						"Configuring machine #{inspect row.hostname} failed with exit code #{exit_code}")
				end
			false ->
				{out, exit_code} = run_on_machine(row, configure_command(arguments))
				case exit_code do
					0 -> :configured
					_ ->
						case erlang_missing_error?(out) do
							true ->
								# Machine seems to be missing erlang, so bootstrap it, then try running the script again.
								bootstrap(row)
								{out, exit_code} = run_on_machine(row, configure_command(arguments))
								case exit_code do
									0 -> :configured
									_ -> raise_configure_error(row.hostname, out, exit_code)
								end
							false -> raise_configure_error(row.hostname, out, exit_code)
						end
				end
		end
	end

	defp configure_command(arguments) do
		# Upgrade Erlang first because the machine may have an older OTP release
		# that cannot execute an escript compiled for a newer OTP release.
		"""
		apt-get install -y --no-install-recommends --only-upgrade \
			-o Dpkg::Options::=--force-confdef \
			-o Dpkg::Options::=--force-confold \
			erlang-base-hipe erlang-crypto &&
		#{arguments |> Enum.join(" ")}
		"""
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

	defp get_wireguard_peers(self_row, graphs, all_machines_map) do
		(graphs.wireguard[self_row.hostname] || [])
		|> Enum.map(fn hostname ->
				peer_row = all_machines_map[hostname]
				endpoint = case ip_connectable?(self_row.public_ip, peer_row.public_ip) do
					true  -> "#{to_ip_string(peer_row.public_ip)}:51820"
					false -> nil
				end
				%{
					public_key:  peer_row.wireguard_pubkey,
					endpoint:    endpoint,
					allowed_ips: [to_ip_string(peer_row.wireguard_ip)],
					comment:     peer_row.hostname,
				}
			end)
	end

	def make_hosts_json_file(self_row, graphs, subdomains, all_machines_map) do
		wireguard_hosts =
			Stream.concat([self_row.hostname], graphs.wireguard[self_row.hostname] || [])
			|> Enum.flat_map(fn hostname ->
					wireguard_ip = all_machines_map[hostname].wireguard_ip
					for hostname <- hostnames("#{hostname}.wg", subdomains.wireguard[hostname]) do
						[to_ip_string(wireguard_ip), hostname]
					end
				end)
		public_hosts =
			Stream.concat([self_row.hostname], graphs.public[self_row.hostname] || [])
			|> Enum.flat_map(fn hostname ->
					peer_ip = all_machines_map[hostname].public_ip
					case ip_connectable?(self_row.public_ip, peer_ip) do
						true  ->
							for hostname <- hostnames("#{hostname}.pi", subdomains.public[hostname]) do
								[to_ip_string(peer_ip), hostname]
							end
						false -> []
					end
				end)
		Poison.encode!(wireguard_hosts ++ [[]] ++ public_hosts)
	end

	defp hostnames(base, subdomains) do
		[base | Enum.map(subdomains || [], fn sub -> "#{sub}.#{base}" end)]
	end

	defp script_filename_for_roles(roles) do
		basename = case roles do
			[] -> "__no_roles__"
			_  -> roles |> Enum.sort |> Enum.join(",")
		end
		Path.join(@script_cache, basename)
	end

	defp erlang_missing_error?(out) do
		out =~ ~r"/usr/bin/env:.*escript.*: No such file or directory"
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
		release = Converge.Util.tag_value!(row.tags, "release")
		unless release =~ ~r/\A[a-z]{2,20}\z/ do
			raise("Unexpected value for release tag: #{inspect release}")
		end
		with \
			{"", 0} <-
				transfer_content(custom_packages_spiped_key(), row,
					"/etc/custom-packages-client/spiped_key",
					before_rsync: "mkdir -p /etc/custom-packages-client ~/.cache/machine_manager/bootstrap"),
			{"", 0} <-
				transfer_file(custom_packages_client_deb_filename(release), row,
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
					(chattr -i /etc/apt/trusted.gpg || true) &&
					apt-key add ~/.cache/machine_manager/bootstrap/custom-packages-apt-key &&
					chmod +x ~/.cache/machine_manager/bootstrap/setup &&
					RELEASE=#{release} CUSTOM_PACKAGES_PASSWORD=#{custom_packages_password()} ~/.cache/machine_manager/bootstrap/setup
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

	defmacro content(filename) do
		File.read!(filename)
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

	defp custom_packages_client_deb_filename(release) do
		packages_directory = "/var/custom-packages/#{release}"
		{:ok, list} = File.ls(packages_directory)
		deb = list
			|> Enum.filter(fn filename -> filename =~ ~r/\Acustom-packages-client_.*_all\.deb\z/ end)
			|> Enum.sort
			|> List.last
		unless deb do
			raise("Could not find a custom-packages-client_*_all.deb file in #{packages_directory}")
		end
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
	# If rsync appears to be missing on the remote, this will install rsync
	# and try again.
	#
	# Returns {rsync_stdout_and_stderr, rsync_exit_code}
	defp transfer_files(source_files, row, dest, opts) do
		before_rsync = opts[:before_rsync]
		args =
			case before_rsync do
				nil -> []
				_   -> ["--rsync-path", "#{before_rsync} && rsync"]
			end ++
			["-e", "ssh -p #{row.ssh_port}", "--protect-args", "--executability"] ++
			source_files ++
			["root@#{to_ip_string(row.public_ip)}:#{dest}"]
		case System.cmd("rsync", args, stderr_to_stdout: true) do
			{out, 0}         -> {out, 0}
			{out, exit_code} ->
				cond do
					String.contains?(out, "rsync: command not found") ->
						case install_rsync_on_machine(row) do
							{_, 0} -> System.cmd("rsync", args, stderr_to_stdout: true)
							{_, _} -> {out, exit_code}
						end
					true -> {out, exit_code}
				end
		end
	end

	defp install_rsync_on_machine(row) do
		run_on_machine(row,
			"""
			apt-get update -q &&
			env DEBIAN_FRONTEND=noninteractive apt-get --quiet --assume-yes install rsync
			""")
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
				kernel:           data.kernel,
				boot_time:        data.boot_time_ms |> DateTime.from_unix!(:millisecond),
				time_offset:      (if data.time_offset, do: Decimal.new(data.time_offset)),
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
		rows             = list(queryable)
		# upgrade calls configure, which expects updated scripts in @script_cache.
		# Note that we don't need to compile scripts for machines with no pending
		# upgrades, because they will not be upgraded and therefore not configured.
		write_scripts_for_machines(rows |> Enum.reject(fn row -> row.pending_upgrades == [] end))
		all_machines     = from("machines") |> list
		all_machines_map = all_machines |> Enum.map(fn row -> {row.hostname, row} end) |> Map.new
		graphs           = connectivity_graphs(all_machines)
		wrapped_upgrade = fn row ->
			try do
				upgrade(row, graphs, all_machines_map)
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
	def upgrade(row, graphs, all_machines_map) do
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
				configure(row, graphs, all_machines_map)
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
			:datacenter, :kernel, :boot_time_ms, :pending_upgrades, :time_offset,
			# Keys in :pending_upgrades
			:name, :old_version, :new_version, :origins, :architecture
		]
	end

	@spec run_on_machine(%{public_ip: Postgrex.INET.t, ssh_port: integer}, String.t, boolean) :: {String.t, integer}
	defp run_on_machine(row, command, capture \\ true) do
		ssh("root", to_ip_string(row.public_ip), row.ssh_port, command, capture)
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
		# Use erlexec instead of System.cmd or Porcelain because Erlang's
		# open_port({spawn_executable, ...}, ...) breaks with ssh ControlMaster:
		# it waits for the daemonized ssh [mux] process to exit before returning.
		# erlexec doesn't have this problem.  The probable cause of this problem
		# is https://bugzilla.mindrot.org/show_bug.cgi?id=1988 (xenial comes with
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
				public_ip:         to_ip_postgrex(public_ip),
				wireguard_ip:      to_ip_postgrex(get_unused_wireguard_ip()),
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
			|> Enum.map(&to_ip_tuple/1)
			|> MapSet.new
		wireguard_start = {10, 10, 0, 0}
		wireguard_end   = {10, 10, 255, 255}
		ip_candidates   = Stream.iterate(wireguard_start, fn ip -> increment_ip_tuple(ip, wireguard_end) end)
		Enum.find(ip_candidates, fn ip -> not MapSet.member?(existing_ips, ip) end)
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
		|> Repo.update_all(set: [public_ip: to_ip_postgrex(public_ip)])
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

	@typep ip_tuple :: {integer, integer, integer, integer}

	@spec increment_ip_tuple(ip_tuple, ip_tuple) :: ip_tuple
	def increment_ip_tuple(ip_tuple = {a, b, c, d}, maximum \\ {255, 255, 255, 255}) when ip_tuple != maximum do
		d = d + 1
		{c, d} = if d == 256, do: {c + 1, 0}, else: {c, d}
		{b, c} = if c == 256, do: {b + 1, 0}, else: {b, c}
		{a, b} = if b == 256, do: {a + 1, 0}, else: {a, b}
		{a, b, c, d}
	end

	defp to_ip_postgrex(ip) when is_tuple(ip),  do: %Postgrex.INET{address: ip,              netmask: 32}
	defp to_ip_postgrex(ip) when is_binary(ip), do: %Postgrex.INET{address: to_ip_tuple(ip), netmask: 32}

	@spec to_ip_tuple(String.t) :: ip_tuple
	def to_ip_tuple(s) when is_binary(s) do
		s
		|> String.split(".")
		|> Enum.map(&String.to_integer/1)
		|> List.to_tuple
	end
	def to_ip_tuple(%Postgrex.INET{address: address}),       do: address

	def to_ip_string(s) when is_binary(s),                   do: s
	def to_ip_string(%Postgrex.INET{address: {a, b, c, d}}), do: "#{a}.#{b}.#{c}.#{d}"

	defp ip_connectable?(source, dest) do
		# Some machines may have a "public" IP that is actually on a LAN;
		# these addresses should not end up on machines that aren't on the LAN.
		case {ip_private?(source), ip_private?(dest)} do
			{false, true} -> false
			_             -> true
		end
	end

	def ip_private?(s) when is_binary(s),              do: ip_private?(to_ip_tuple(s))
	def ip_private?(%Postgrex.INET{address: address}), do: ip_private?(address)

	@spec ip_private?(ip_tuple) :: boolean
	def ip_private?({a, b, _c, _d}) do
		case {a, b} do
			{192, 168}                       -> true
			{10, _}                          -> true
			{172, n} when n >= 16 and n < 32 -> true
			{127, _}                         -> true
			_                                -> false
		end
	end
end
