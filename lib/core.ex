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
	alias MachineManager.{
		ScriptWriter, Parallel, Repo, UpgradeError, ConfigureError, ProbeError,
		WireGuard, Graph, PortableErlang}
	alias Gears.{StringUtil, FileUtil}
	import Ecto.Query
	import Converge.Util, only: [architecture_for_tags: 1]

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
					pending_upgrades: fragment(
						"""
						array_agg(
							json_build_object(
								'package',     ?::varchar,
								'old_version', ?,
								'new_version', ?
							)
						)
						""", u.package, u.old_version, u.new_version)
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
				tags:              coalesce(t.tags,             fragment("'{}'::varchar[]")),
				pending_upgrades:  coalesce(u.pending_upgrades, fragment("'{}'::json[]")),
				last_probe_time:   type(m.last_probe_time, :utc_datetime),
				boot_time:         type(m.boot_time,       :utc_datetime),
				cpu_model_name:    m.cpu_model_name,
				cpu_architecture:  m.cpu_architecture,
				ram_mb:            m.ram_mb,
				core_count:        m.core_count,
				thread_count:      m.thread_count,
				time_offset:       m.time_offset,
				kernel:            m.kernel,
			})
		|> join(:left, [m], t in subquery(tags_aggregate),             on: t.hostname == m.hostname)
		|> join(:left, [m], u in subquery(pending_upgrades_aggregate), on: u.hostname == m.hostname)
		|> order_by(asc: :hostname)
		|> Repo.all
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
		graphs           = connectivity_graphs(all_machines)
		wireguard_config_for_machine(row, graphs, all_machines_map)
	end

	defp wireguard_config_for_machine(row, graphs, all_machines_map) do
		listen_port      = 904
		wireguard_peers  = get_wireguard_peers(row, graphs, all_machines_map)
		addresses        =
			case Converge.Util.tag_values(row.tags, "wireguard_address") do
				[]        -> [to_ip_string(row.wireguard_ip)]
				addresses -> addresses
			end
		WireGuard.make_wireguard_config(row.wireguard_privkey, addresses, listen_port, wireguard_peers)
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
		architectures     = get_machine_architectures(rows)
		portable_erlangs  = temp_portable_erlangs(architectures)
		# Even through we're building a connectivity graph that includes all
		# machines, we don't actually need to do compile scripts for *all*
		# machines because make_connectivity_graph just runs require_file on
		# connections.exs files.
		write_scripts_for_machines(rows, allow_warnings)
		all_machines      = from("machines") |> list
		all_machines_map  = all_machines |> Enum.map(fn row -> {row.hostname, row} end) |> Map.new
		graphs            = connectivity_graphs(all_machines)
		wrapped_configure = fn row ->
			portable_erlang = portable_erlangs[architecture_for_tags(row.tags)]
			try do
				configure(row, graphs, all_machines_map, portable_erlang, show_progress)
			rescue
				e in ConfigureError -> {:configure_error, e.message}
			end
		end
		task_map =
			rows
			|> Enum.map(fn row -> {row.hostname, Task.async(fn -> wrapped_configure.(row) end)} end)
			|> Map.new
		Parallel.block_on_tasks(task_map, handle_configure_result, handle_waiting, 2000)
	end

	@script_cache Path.expand("~/.cache/machine_manager/script_cache")

	defp get_machine_architectures(rows) do
		rows
		|> Enum.map(fn row -> architecture_for_tags(row.tags) end)
		|> MapSet.new
	end

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

	@doc """
	Probe a machine and write the probe data to the database.
	"""
	def probe(row, portable_erlang) do
		data = get_probe_data(row, portable_erlang)
		# TODO: don't assume that it's the same machine; make sure some unique ID is the same
		write_probe_data_to_db(row.hostname, data)
		nil
	end

	@machine_probe_content File.read!(Path.join(__DIR__, "../../machine_probe/machine_probe"))

	@doc """
	Get probe data from a machine.
	"""
	def get_probe_data(row, portable_erlang) do
		# portable_erlang can be nil in this function, in case the caller is
		# certain the machine already has it.
		if portable_erlang != nil do
			transfer_portable_erlang(portable_erlang, row)
			case transfer_portable_erlang(portable_erlang, row) do
				:ok                      -> nil
				{:error, out, exit_code} -> raise_upload_error(ProbeError, row.hostname, out, exit_code, "erlang")
			end
		end
		case transfer_content(@machine_probe_content, row, ".cache/machine_manager/machine_probe",
			                   before_rsync: "mkdir -p .cache/machine_manager", executable: true) do
			{"", 0}          -> nil
			{out, exit_code} -> raise_upload_error(ProbeError, row.hostname, out, exit_code, "machine_probe")
		end
		{output, exit_code} = run_on_machine(row, ".cache/machine_manager/erlang/bin/escript .cache/machine_manager/machine_probe")
		case exit_code do
			0 ->
				json = get_json_from_probe_output(output)
				case Jason.decode(json, keys: :atoms!) do
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
		# Make sure these atoms are in the atom table for our Jason.decode!
		[
			:ram_mb, :cpu_model_name, :cpu_architecture, :core_count, :thread_count,
			:kernel, :boot_time_ms, :pending_upgrades, :time_offset,
			# Keys in :pending_upgrades
			:name, :old_version, :new_version, :origins, :architecture,
		]
	end

	# This function assumes an up-to-date configuration script is already present
	# in @script_cache (call write_scripts_for_machines first).
	#
	# Can raise ConfigureError
	def configure(row, graphs, all_machines_map, portable_erlang, show_progress \\ false) do
		roles            = ScriptWriter.roles_for_tags(row.tags)
		script_file      = script_filename_for_roles(roles)
		wireguard_config = wireguard_config_for_machine(row, graphs, all_machines_map)
		subdomains       = subdomains(all_machines_map |> Map.values)
		hosts_file       = make_hosts_json_file(row, graphs, subdomains, all_machines_map)
		case transfer_portable_erlang(portable_erlang, row) do
			:ok                      -> nil
			{:error, out, exit_code} -> raise_upload_error(ConfigureError, row.hostname, out, exit_code, "erlang")
		end
		# script_file is already compressed, so don't use compress: true
		case transfer_path(script_file, row, ".cache/machine_manager/script",
		                   before_rsync: "mkdir -p .cache/machine_manager") do
			{"", 0}          -> nil
			{out, exit_code} -> raise_upload_error(ConfigureError, row.hostname, out, exit_code, "configuration script")
		end
		case transfer_content(wireguard_config, row, ".cache/machine_manager/wg0.conf", compress: true) do
			{"", 0}          -> nil
			{out, exit_code} -> raise_upload_error(ConfigureError, row.hostname, out, exit_code, "WireGuard configuration")
		end
		case transfer_content(hosts_file, row, ".cache/machine_manager/hosts.json", compress: true) do
			{"", 0}          -> nil
			{out, exit_code} -> raise_upload_error(ConfigureError, row.hostname, out, exit_code, "hosts.json")
		end
		arguments = [".cache/machine_manager/erlang/bin/escript", ".cache/machine_manager/script"] ++ row.tags
		for arg <- arguments do
			if String.contains?(arg, " ") do
				raise(ConfigureError,
					"Argument list #{inspect arguments} contains an argument with a space: #{inspect arg}")
			end
		end
		case show_progress do
			true ->
				{"", exit_code} = run_on_machine(row, Enum.join(arguments, " "), false)
				case exit_code do
					0 -> :configured
					_ -> raise(ConfigureError,
						"Configuring machine #{inspect row.hostname} failed with exit code #{exit_code}")
				end
			false ->
				{out, exit_code} = run_on_machine(row, Enum.join(arguments, " "))
				case exit_code do
					0 -> :configured
					_ -> raise_configure_error(row.hostname, out, exit_code)
				end
		end
	end

	defp transfer_portable_erlang(portable_erlang, row) do
		case transfer_path("#{portable_erlang}/", row, ".cache/machine_manager/erlang",
		                   before_rsync: "mkdir -p .cache/machine_manager/erlang", compress: true) do
			{"", 0}          -> :ok
			{out, exit_code} -> {:error, out, exit_code}
		end
	end

	defp raise_upload_error(error, hostname, out, exit_code, upload_description) do
		raise(error,
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
		wireguard_snat_host = Converge.Util.tag_value(self_row.tags, "wireguard_snat_host")
		(graphs.wireguard[self_row.hostname] || [])
		|> Enum.map(fn hostname ->
				peer_row = all_machines_map[hostname]
				endpoint = case ip_connectable?(self_row.public_ip, peer_row.public_ip) do
					true  -> "#{to_ip_string(peer_row.public_ip)}:904"
					false -> nil
				end
				allowed_ips = case hostname do
					^wireguard_snat_host -> ["0.0.0.0/0"]
					_                    -> [to_ip_string(peer_row.wireguard_ip)]
				end
				%{
					public_key:  peer_row.wireguard_pubkey,
					endpoint:    endpoint,
					allowed_ips: allowed_ips,
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
		Jason.encode!(wireguard_hosts ++ [[]] ++ public_hosts)
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

	# Transfer content `content` using rsync to machine described by `row` to `dest`
	#
	# Returns {rsync_out, rsync_exit_code}
	defp transfer_content(content, row, dest, opts) do
		temp = FileUtil.temp_path("machine_manager_transfer_content")
		File.touch!(temp)
		if opts[:executable] do
			:ok = File.chmod!(temp, 0o700)
		else
			:ok = File.chmod!(temp, 0o600)
		end
		File.write!(temp, content)
		try do
			transfer_path(temp, row, dest, opts)
		after
			FileUtil.rm_f!(temp)
		end
	end

	defp transfer_path(source_path, row, dest, opts) do
		transfer_paths([source_path], row, dest, opts)
	end

	# Transfer files/directories `source_paths` using rsync to machine described
	# by `row` to `dest`.
	#
	# If opts[:before_rsync] is non-nil, the given command is executed on the
	# remote before the rsync transfer.  This can be used to create a directory
	# needed for the transfer to succeed.
	#
	# If opts[:compress] is true, use rsync -z (--compress).
	#
	# If rsync appears to be missing on the remote, this will install rsync
	# and try again.
	#
	# Returns {rsync_stdout_and_stderr, rsync_exit_code}
	defp transfer_paths(source_paths, row, dest, opts) do
		before_rsync = opts[:before_rsync]
		rsync_args =
			(if before_rsync != nil, do: ["--rsync-path", "#{before_rsync} && rsync"], else: []) ++
			(if opts[:compress],     do: ["--compress"], else: []) ++
			["-e", "ssh -p #{row.ssh_port}", "--protect-args", "--recursive", "--delete", "--executability", "--links"] ++
			source_paths ++
			["root@#{to_ip_string(row.public_ip)}:#{dest}"]
		case System.cmd("rsync", rsync_args, env: env_for_ssh(), stderr_to_stdout: true) do
			{out, 0}         -> {out, 0}
			{out, exit_code} ->
				cond do
					String.contains?(out, "command not found") ->
						case install_rsync_on_machine(row) do
							{_, 0}           -> System.cmd("rsync", rsync_args, stderr_to_stdout: true)
							{out, exit_code} -> {out, exit_code}
						end
					true -> {out, exit_code}
				end
		end
	end

	defp install_rsync_on_machine(row) do
		run_on_machine(row,
			"""
			(apt-get update -q || apt-get update -q || echo "apt-get update failed twice but continuing anyway") &&
			env DEBIAN_FRONTEND=noninteractive apt-get --quiet --assume-yes --no-install-recommends install rsync
			""")
	end

	def probe_many(queryable, handle_probe_result, handle_waiting) do
		rows             = list(queryable)
		architectures    = get_machine_architectures(rows)
		portable_erlangs = temp_portable_erlangs(architectures)
		wrapped_probe    = fn row ->
			portable_erlang = portable_erlangs[architecture_for_tags(row.tags)]
			try do
				{:probed, probe(row, portable_erlang)}
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
		architectures    = get_machine_architectures(rows)
		portable_erlangs = temp_portable_erlangs(architectures)
		# upgrade calls configure, which expects updated scripts in @script_cache.
		# Note that we don't need to compile scripts for machines with no pending
		# upgrades, because they will not be upgraded and therefore not configured.
		write_scripts_for_machines(rows |> Enum.reject(fn row -> row.pending_upgrades == [] end))
		all_machines     = from("machines") |> list
		all_machines_map = all_machines |> Enum.map(fn row -> {row.hostname, row} end) |> Map.new
		graphs           = connectivity_graphs(all_machines)
		wrapped_upgrade = fn row ->
			portable_erlang = portable_erlangs[architecture_for_tags(row.tags)]
			try do
				upgrade(row, graphs, all_machines_map, portable_erlang)
			rescue
				e in UpgradeError   -> {:upgrade_error,   e.message}
				e in ConfigureError -> {:configure_error, e.message}
				e in ProbeError     -> {:probe_error,     e.message}
			end
		end
		task_map =
			rows
			|> Enum.map(fn row -> {row.hostname, Task.async(fn -> wrapped_upgrade.(row) end)} end)
			|> Map.new
		Parallel.block_on_tasks(task_map, handle_upgrade_result, handle_waiting, 2000)
	end

	# Can raise UpgradeError or ConfigureError
	def upgrade(row, graphs, all_machines_map, portable_erlang) do
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
				configure(row, graphs, all_machines_map, portable_erlang)
				# Probe the machine so that we don't have obsolete 'pending upgrade' list
				probe(row, nil)
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

	@spec run_on_machine(%{public_ip: Postgrex.INET.t, ssh_port: integer}, String.t, boolean) :: {String.t, integer}
	defp run_on_machine(row, command, capture \\ true) do
		ssh("root", to_ip_string(row.public_ip), row.ssh_port, command, capture)
	end

	defp temp_portable_erlangs(architectures) do
		for arch <- architectures do
			portable_erlang = FileUtil.temp_dir("machine_manager_portable_erlang")
			PortableErlang.make_portable_erlang(portable_erlang, arch)
			{arch, portable_erlang}
		end
		|> Map.new
	end

	@doc """
	Runs `command` on machine at `ip` and `ssh_port` with user `user`, returns
	`{output, exit_code}`.  If `capture` is `true`, `output` includes both
	stdout and stderr; if `false`, both stdout and stderr are echoed to the
	terminal and `output` is `""`.

	Note that if user has OpenSSH < 7.3 and ssh is configured to use
	ControlMaster, this function will hang and not return after ssh is done.
	See https://bugzilla.mindrot.org/show_bug.cgi?id=1988
	"""
	@spec ssh(String.t, String.t, integer, String.t, boolean) :: {String.t, integer}
	def ssh(user, ip, ssh_port, command, capture) do
		case capture do
			true ->
				System.cmd("ssh", ["-q", "-p", "#{ssh_port}", "#{user}@#{ip}", command],
					stderr_to_stdout: true,
					env: env_for_ssh()
				)
			false ->
				%Porcelain.Result{status: exit_code} = \
					Porcelain.exec("ssh", ["-q", "-p", "#{ssh_port}", "#{user}@#{ip}", command],
						out: {:file, Process.group_leader},
						# "when using `Porcelain.Driver.Basic`, the only supported values
						# are `nil` (stderr will be printed to the terminal) and `:out`."
						err: nil,
						env: env_for_ssh()
					)
				{"", exit_code}
		end
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
	@spec add(String.t, String.t, integer, [String.t]) :: nil
	def add(hostname, public_ip, ssh_port, tags) do
		wireguard_privkey = WireGuard.make_wireguard_privkey()
		wireguard_pubkey  = WireGuard.get_wireguard_pubkey(wireguard_privkey)
		{:ok, _} = Repo.transaction(fn ->
			Repo.insert_all("machines", [[
				hostname:          hostname,
				public_ip:         to_ip_postgrex(public_ip),
				wireguard_ip:      to_ip_postgrex(get_unused_wireguard_ip()),
				wireguard_privkey: wireguard_privkey,
				wireguard_pubkey:  wireguard_pubkey,
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
