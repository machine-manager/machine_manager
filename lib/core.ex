defmodule MachineManager.UpgradeError do
	defexception [:message]
end

defmodule MachineManager.ConfigureError do
	defexception [:message]
end

defmodule MachineManager.ProbeError do
	defexception [:message]
end

defmodule MachineManager.WaitError do
	defexception [:message]
end

defmodule MachineManager.Core do
	alias MachineManager.{
		ScriptWriter, Parallel, Repo, UpgradeError, ConfigureError, ProbeError,
		WaitError, WireGuard, Graph, PortableErlang}
	alias Gears.{StringUtil, FileUtil}
	import Ecto.Query
	import Converge.Util, only: [architecture_for_tags: 1]
	use Memoize

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

		addresses_aggregate =
			from("machine_addresses")
			|> select([a], %{
					hostname:  a.hostname,
					addresses: fragment(
						"""
						array_agg(
							json_build_object(
								'network', ?,
								'address', ?
							)
						)
						""", a.network, a.address)
				})
			|> group_by([a], a.hostname)

		queryable
		|> select([m, t, u, a], %{
				hostname:          m.hostname,
				type:              m.type,
				wireguard_ip:      m.wireguard_ip,
				wireguard_port:    m.wireguard_port,
				wireguard_pubkey:  m.wireguard_pubkey,
				wireguard_privkey: m.wireguard_privkey,
				wireguard_expose:  m.wireguard_expose,
				ssh_port:          m.ssh_port,
				ssh_user:          m.ssh_user,
				ssh_expose:        m.ssh_expose,
				country:           m.country,
				release:           m.release,
				boot:              m.boot,
				tags:              coalesce(t.tags,             fragment("'{}'::varchar[]")),
				pending_upgrades:  coalesce(u.pending_upgrades, fragment("'{}'::json[]")),
				addresses:         coalesce(a.addresses,        fragment("'{}'::json[]")),
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
		|> join(:left, [m], a in subquery(addresses_aggregate),        on: a.hostname == m.hostname)
		|> order_by(asc: :hostname)
		|> Repo.all
		|> fix_machine_rows
	end

	defp fix_machine_rows(rows) do
		for row <- rows do
			%{row | addresses: Enum.map(row.addresses, &fix_address/1)}
		end
	end

	defp fix_address(%{"network" => network, "address" => address}) do
		%{network: network, address: to_ip_postgrex(address)}
	end

	def net_list() do
		from("networks")
		|> select([n], %{name: n.name, parent: n.parent})
		|> Repo.all
	end

	def net_add(name, parent) do
		Repo.insert_all("networks", [[
			name:   name,
			parent: parent,
		]])
	end

	def net_rm(name) do
		from("networks")
		|> where([n], n.name == ^name)
		|> Repo.delete_all
	end

	def forward_list(hostname_regexp) do
		machines =
			from("machines")
			|> select([:hostname, :wireguard_port, :ssh_port])

		forwards =
			from("machine_forwards")
			|> select([:hostname, :type, :final_destination, :port])

		from("machine_forwards")
		|> hostname_matching_regexp(hostname_regexp)
		|> select([f, m, i], %{
				hostname:                         f.hostname,
				source_port:                      f.port,
				type:                             f.type,
				next_destination:                 f.next_destination,
				final_destination:                f.final_destination,
				final_destination_wireguard_port: m.wireguard_port,
				final_destination_ssh_port:       m.ssh_port,
				next_destination_port:            i.port,
			})
		|> join(:left, [f], m in subquery(machines), on: f.final_destination == m.hostname)
		|> join(:left, [f], i in subquery(forwards), on: f.next_destination  == i.hostname and f.type == i.type and f.final_destination == i.final_destination)
		|> Repo.all
		|> fix_forward_rows
	end

	defp fix_forward_rows(rows) do
		for row <- rows do
			%{
				hostname:          row.hostname,
				source_port:       row.source_port,
				destination_port:  destination_port_for_forward(row),
				type:              row.type,
				protocol:          protocol_for_forward(row),
				next_destination:  row.next_destination,
				final_destination: row.final_destination,
			}
		end
	end

	defp destination_port_for_forward(row) do
		if row.next_destination == row.final_destination do
			case row.type do
				"wireguard" -> row.final_destination_wireguard_port
				"ssh"       -> row.final_destination_ssh_port
			end
		else
			row.next_destination_port
		end
	end

	defp protocol_for_forward(row) do
		case row.type do
			"wireguard" -> "udp"
			"ssh"       -> "tcp"
		end
	end

	def ssh_config() do
		rows    = from("machines") |> list
		parents = network_parents()
		for row <- rows do
			address = mm_reachable_address(row, parents)
			case address do
				nil -> nil
				_   -> ssh_config_entry(row.hostname, address, row.ssh_port)
			end
		end
		|> Enum.reject(&is_nil/1)
		|> Enum.join("\n")
	end

	defp ssh_config_entry(hostname, address, ssh_port) do
		"""
		Host #{hostname}
		  HostName #{to_ip_string(address)}
		  Port #{ssh_port}
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
		listen_port      = row.wireguard_port
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

	def configure_many(queryable, retry_on_port, handle_configure_result, handle_waiting, show_progress, allow_warnings) do
		rows = list(queryable)
		if show_progress and length(rows) > 1 do
			raise(ConfigureError, "Can't show progress when configuring more than one machine")
		end
		act_many(:configure, rows, retry_on_port, handle_configure_result, handle_waiting, show_progress: show_progress, allow_warnings: allow_warnings)
	end

	def upgrade_many(queryable, retry_on_port, handle_upgrade_result, handle_waiting) do
		rows = list(queryable)
		act_many(:upgrade, rows, retry_on_port, handle_upgrade_result, handle_waiting)
	end

	def setup_many(queryable, retry_on_port, handle_setup_result, handle_waiting) do
		rows = list(queryable)
		act_many(:setup, rows, retry_on_port, handle_setup_result, handle_waiting)
	end

	def probe_many(queryable, retry_on_port, handle_probe_result, handle_waiting) do
		queryable =
			queryable
			|> where([m], m.type == "debian")
		rows = list(queryable)
		act_many(:probe, rows, retry_on_port, handle_probe_result, handle_waiting)
	end

	@machine_probe_content File.read!(Path.join(__DIR__, "../../machine_probe/machine_probe"))

	defp act_many(command, rows, retry_on_port, handle_result, handle_waiting, opts \\ []) do
		architectures    = get_machine_architectures(rows)
		portable_erlangs = temp_portable_erlangs(architectures)
		case command do
			# Even through we're building a connectivity graph that includes all
			# machines, we don't actually need to do compile scripts for *all*
			# machines because make_connectivity_graph just runs require_file on
			# connections.exs files.
			c when c in [:configure, :setup] ->
				write_scripts_for_machines(rows, opts[:allow_warnings])

			# upgrade calls configure, which expects updated scripts in @script_cache.
			# But we don't need to compile scripts for machines with no pending
			# upgrades, because they will not be upgraded and therefore not configured.
			:upgrade ->
				write_scripts_for_machines(Enum.reject(rows, fn row -> row.pending_upgrades == [] end))

			:probe ->
				nil
		end
		all_machines     = from("machines") |> list
		all_machines_map = all_machines |> Enum.map(fn row -> {row.hostname, row} end) |> Map.new
		graphs           = connectivity_graphs(all_machines)
		wrapped = fn row ->
			portable_erlang = portable_erlangs[architecture_for_tags(row.tags)]
			temp_dir        = FileUtil.temp_dir("machine_manager_act_many")
			machine_probe   = if command in [:setup, :upgrade, :probe] do
				write_temp_file(temp_dir, "machine_probe", @machine_probe_content, executable: true)
			end
			try do
				case command do
					:configure -> configure(row, graphs, all_machines_map, portable_erlang, retry_on_port, opts[:show_progress])
					:setup     -> setup(row, graphs, all_machines_map, portable_erlang, retry_on_port, machine_probe)
					:upgrade   -> upgrade(row, graphs, all_machines_map, portable_erlang, retry_on_port, machine_probe)
					:probe     -> probe(row, portable_erlang, machine_probe, retry_on_port)
				end
			rescue
				e in UpgradeError   -> {:upgrade_error,   e.message}
				e in ConfigureError -> {:configure_error, e.message}
				e in ProbeError     -> {:probe_error,     e.message}
				e in WaitError      -> {:wait_error,      e.message}
			after
				File.rm_rf(temp_dir)
			end
		end
		task_map =
			rows
			|> Enum.map(fn row -> {row.hostname, Task.async(fn -> wrapped.(row) end)} end)
			|> Map.new
		Parallel.block_on_tasks(task_map, handle_result, handle_waiting, 2000)
	end

	@script_cache Path.expand("~/.cache/machine_manager/script_cache")

	defp get_machine_architectures(rows) do
		rows
		|> Enum.map(fn row -> architecture_for_tags(row.tags) end)
		|> MapSet.new
	end

	defp temp_portable_erlangs(architectures) do
		for arch <- architectures do
			temp_dir        = FileUtil.temp_dir("machine_manager_portable_erlang")
			portable_erlang = Path.join(temp_dir, "erlang")
			File.mkdir!(portable_erlang)
			PortableErlang.make_portable_erlang(portable_erlang, arch)
			{arch, portable_erlang}
		end
		|> Map.new
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
					queryable -> queryable |> select([m], m.hostname) |> where([m], not is_nil(m.wireguard_ip)) |> Repo.all
				end |> MapSet.new |> MapSet.delete(hostname)
				# MapSet.delete(hostname) because a machine should not be connected to itself.
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
	def probe(row, portable_erlang, machine_probe, retry_on_port) do
		data = get_probe_data(row, portable_erlang, machine_probe, retry_on_port)
		# TODO: don't assume that it's the same machine; make sure some unique ID is the same
		write_probe_data_to_db(row.hostname, data)
		:probed
	end

	@doc """
	Get probe data from a machine.
	"""
	def get_probe_data(row, portable_erlang, machine_probe, retry_on_port) do
		# portable_erlang can be nil in this function, in case the caller is
		# certain the machine already has it.
		files = case portable_erlang do
			nil -> [machine_probe]
			_   -> [portable_erlang, machine_probe]
		end
		case transfer_paths(files, row, ".cache/machine_manager/",
			                 before_rsync: "mkdir -p .cache/machine_manager", compress: true) do
			{"", 0}          -> nil
			{out, exit_code} -> raise_upload_error(ProbeError, row.hostname, out, exit_code, inspect(files))
		end
		{output, exit_code} = run_on_machine(row, ".cache/machine_manager/erlang/bin/escript .cache/machine_manager/machine_probe", shell: true, retry_on_port: retry_on_port)
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
	# Can raise ConfigureError, ProbeError, UpgradeError, or WaitError
	def setup(row, graphs, all_machines_map, portable_erlang, retry_on_port, machine_probe) do
		:configured = configure(row, graphs, all_machines_map, portable_erlang, retry_on_port)
		:probed     = probe(row, nil, machine_probe, retry_on_port)
		# Get updated row with package upgrades
		[row]       = list(machine(row.hostname))
		:upgraded   = upgrade(row, graphs, all_machines_map, portable_erlang, retry_on_port, machine_probe)
		reboot(row)
		wait(row)
		:probed     = probe(row, nil, machine_probe, retry_on_port)
		:setup
	end

	# This function assumes an up-to-date configuration script is already present
	# in @script_cache (call write_scripts_for_machines first).
	#
	# Can raise ConfigureError
	def configure(row, graphs, all_machines_map, portable_erlang, retry_on_port, show_progress \\ false) do
		roles            = ScriptWriter.roles_for_tags(row.tags)
		script_file      = script_filename_for_roles(roles)
		wireguard_config = wireguard_config_for_machine(row, graphs, all_machines_map)
		subdomains       = subdomains(all_machines_map |> Map.values)
		hosts_file       = make_hosts_json_file(row, graphs, subdomains, all_machines_map)
		temp_dir         = FileUtil.temp_dir("machine_manager_configure")
		try do
			script     = Path.join(temp_dir, "script")
			File.ln!(script_file, script)
			wg0_conf   = write_temp_file(temp_dir, "wg0.conf",   wireguard_config)
			hosts_json = write_temp_file(temp_dir, "hosts.json", hosts_file)
			files      = [portable_erlang, script, wg0_conf, hosts_json]
			case transfer_paths(files, row, ".cache/machine_manager/",
				                 before_rsync: "mkdir -p .cache/machine_manager", compress: true, retry_on_port: retry_on_port) do
				{"", 0}          -> nil
				{out, exit_code} -> raise_upload_error(ConfigureError, row.hostname, out, exit_code, inspect(files))
			end
		after
			File.rm_rf!(temp_dir)
		end

		arguments = [".cache/machine_manager/erlang/bin/escript", ".cache/machine_manager/script"] ++ all_tags(row)
		case show_progress do
			true ->
				{"", exit_code} = run_on_machine(row, arguments, retry_on_port: retry_on_port, capture: false)
				case exit_code do
					0 -> :configured
					_ -> raise(ConfigureError, "Configuring machine #{inspect row.hostname} failed with exit code #{exit_code}")
				end
			false ->
				{out, exit_code} = run_on_machine(row, arguments, retry_on_port: retry_on_port)
				case exit_code do
					0 -> :configured
					_ -> raise_configure_error(row.hostname, out, exit_code)
				end
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
				parents  = network_parents()
				endpoint = case reachable_addresses(parents, self_row, peer_row) do
					[address | _] -> "#{to_ip_string(address)}:#{peer_row.wireguard_port}"
					# We can't connect to them, but maybe they can connect to us
					[] -> nil
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
		parents = network_parents()
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
					peer_row = all_machines_map[hostname]
					case reachable_addresses(parents, self_row, peer_row) do
						[address | _] ->
							for hostname <- hostnames("#{hostname}.pi", subdomains.public[hostname]) do
								[to_ip_string(address), hostname]
							end
						[] -> []
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

	defp write_temp_file(temp_dir, filename, content, opts \\ []) do
		temp     = Path.join(temp_dir, filename)
		mode     = case opts[:executable] do
			true -> 0o700
			_    -> 0o600
		end
		File.touch!(temp)
		:ok = File.chmod!(temp, mode)
		File.write!(temp, content)
		temp
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
	# If opts[:retry_on_port] is not nil, retry on that port if a connection to
	# the configured port fails.
	#
	# If rsync appears to be missing on the remote, this will install rsync
	# and try again.
	#
	# Returns {rsync_stdout_and_stderr, rsync_exit_code}
	defp transfer_paths(source_paths, row, dest, opts) do
		before_rsync  = opts[:before_rsync]
		retry_on_port = opts[:retry_on_port]
		port          = case opts[:port_override] do
			nil                 -> row.ssh_port
			p when is_number(p) -> p
		end
		rsync_args    =
			(if before_rsync != nil, do: ["--rsync-path", "#{before_rsync} && rsync"], else: []) ++
			(if opts[:compress],     do: ["--compress"], else: []) ++
			["--protect-args", "--recursive", "--delete", "--executability", "--links"] ++
			source_paths ++
			["#{row.ssh_user}@#{to_ip_string(mm_reachable_address!(row))}:#{dest}"]
		case System.cmd("rsync", rsync_ssh_args(port) ++ rsync_args, env: env_for_ssh(), stderr_to_stdout: true) do
			{out, 0} ->
				{out, 0}
			{_, 255} when retry_on_port != nil ->
				opts = [retry_on_port: nil, port_override: retry_on_port] ++ opts
				transfer_paths(source_paths, row, dest, opts)
			{out, exit_code} ->
				cond do
					String.contains?(out, "command not found") ->
						case install_rsync_on_machine(row, retry_on_port: port) do
							{_, 0}           -> System.cmd("rsync", rsync_args, stderr_to_stdout: true)
							{out, exit_code} -> {out, exit_code}
						end
					true -> {out, exit_code}
				end
		end
	end

	defp rsync_ssh_args(port) do
		["-e", "ssh -p #{port} -o ConnectTimeout=#{ssh_connect_timeout()}"]
	end

	defp ssh_connect_timeout(), do: 10

	defp install_rsync_on_machine(row, opts) do
		run_on_machine(row,
			"""
			(apt-get update -q || apt-get update -q || echo "apt-get update failed twice but continuing anyway") &&
			env DEBIAN_FRONTEND=noninteractive apt-get --quiet --assume-yes --no-install-recommends install rsync
			""",
			[shell: true] ++ opts)
	end

	def exec_many(queryable, shell, command, handle_exec_result, handle_waiting) do
		rows = list(queryable)
		# When calling run_on_machine, don't allow retry because the command may
		# return exit code 255 (the same as ssh's connection failure exit code)
		# and yet not be safe to run again.
		task_map =
			rows
			|> Enum.map(fn row -> {row.hostname, Task.async(fn -> run_on_machine(row, command, shell: shell) end)} end)
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
			clear_pending_upgrades(hostname)
			Repo.insert_all("machine_pending_upgrades",
				(data.pending_upgrades || []) |> Enum.map(fn %{name: name, old_version: old_version, new_version: new_version} ->
					[hostname: hostname, package: name, old_version: old_version, new_version: new_version]
				end),
				on_conflict: :nothing
			)
		end)
	end

	defp clear_pending_upgrades(hostname) do
		from("machine_pending_upgrades")
		|> where([u], u.hostname == ^hostname)
		|> Repo.delete_all
	end

	# Can raise UpgradeError or ConfigureError
	def upgrade(row, graphs, all_machines_map, portable_erlang, retry_on_port, machine_probe) do
		case row.pending_upgrades do
			[]       -> :no_pending_upgrades
			upgrades ->
				upgrade_args =
					upgrades
					|> Enum.map(fn upgrade -> "#{upgrade["package"]}=#{upgrade["new_version"]}" end)
				# TODO: if disk is very low, first run
				# apt-get clean
				# apt-get autoremove --quiet --assume-yes
				command =
					"""
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
				{output, exit_code} = run_on_machine(row, command, shell: true)
				if exit_code != 0 do
					raise(UpgradeError,
						"""
						Upgrade of #{row.hostname} failed with exit code #{exit_code}; output:

						#{output}
						""")
				end
				# Because packages upgrades can do things we don't like (e.g. install
				# files in /etc/cron.d), configure immediately after upgrading.
				configure(row, graphs, all_machines_map, portable_erlang, retry_on_port)
				# Probe the machine so that we don't have obsolete 'pending upgrade' list
				probe(row, nil, machine_probe, retry_on_port)
				:upgraded
		end
	end

	defp reboot(row) do
		{_, 0} = run_on_machine(row, reboot_command(), shell: true)
	end

	def reboot_many(queryable, handle_exec_result, handle_waiting) do
		exec_many(queryable, true, reboot_command(), handle_exec_result, handle_waiting)
	end

	def shutdown_many(queryable, handle_exec_result, handle_waiting) do
		exec_many(queryable, true, shutdown_command(), handle_exec_result, handle_waiting)
	end

	defp reboot_command(),   do: "nohup sh -c 'sleep #{delay_before_shutdown()}; systemctl reboot'   > /dev/null 2>&1 < /dev/null &"
	defp shutdown_command(), do: "nohup sh -c 'sleep #{delay_before_shutdown()}; systemctl poweroff' > /dev/null 2>&1 < /dev/null &"

	@max_reboot_wait_time 1200

	defp wait(row) do
		# Wait for an existing reboot/shutdown command to start
		Process.sleep(1000 * (delay_before_shutdown() + 1))

		attempts = @max_reboot_wait_time / ssh_connect_timeout()
		case wait_for_machine(row, attempts) do
			{_, 0}       -> nil
			{message, 1} -> raise(WaitError, message)
		end
	end

	def wait_many(queryable, handle_exec_result, handle_waiting) do
		rows = list(queryable)
		task_map =
			rows
			|> Enum.map(fn row -> {
					row.hostname,
					Task.async(fn ->
						wait_for_existing_shutdown_to_start()
						attempts = @max_reboot_wait_time / ssh_connect_timeout()
						wait_for_machine(row, attempts)
					end)
				} end)
			|> Map.new
		Parallel.block_on_tasks(task_map, handle_exec_result, handle_waiting, 2000)
	end

	defp wait_for_existing_shutdown_to_start() do
		Process.sleep(1000 * (delay_before_shutdown() + 1))
	end

	defp delay_before_shutdown(), do: 2

	defp wait_for_machine(row, attempt) do
		case run_on_machine(row, "true", shell: true) do
			{_, 0} -> {"", 0}
			{_, _} ->
				# Maybe try again
				case attempt do
					0 -> {"Gave up waiting", 1}
					_ -> wait_for_machine(row, attempt - 1)
				end
		end
	end

	defp run_on_machine(row, command, options) do
		retry_on_port = options[:retry_on_port]
		shell         = options[:shell] || false
		capture       = case options[:capture] do
			nil   -> true
			true  -> true
			false -> false
		end
		case ssh(row.ssh_user, to_ip_string(mm_reachable_address!(row)), row.ssh_port, shell, command, capture) do
			{"", 255} when retry_on_port != nil ->
				ssh(row.ssh_user, to_ip_string(mm_reachable_address!(row)), retry_on_port, shell, command, capture)
			{out, code} ->
				{out, code}
		end
	end

	@doc """
	Runs `command` on machine at `ip` and `ssh_port` with user `user`, returns
	`{output, exit_code}`.  If `shell` is false, `command` must be a list of
	command and arguments to be run without shell interpretation; if true,
	`command` must be a string containing a command to be run with
	shell interpretation.  If `capture` is `true`, `output` includes both
	stdout and stderr; if `false`, both stdout and stderr are echoed to the
	terminal and `output` is `""`.

	Note that if user has OpenSSH < 7.3 and ssh is configured to use
	ControlMaster, this function will hang and not return after ssh is done.
	See https://bugzilla.mindrot.org/show_bug.cgi?id=1988
	"""
	@spec ssh(String.t, String.t, integer, boolean, String.t | [String.t], boolean) :: {String.t, integer}
	def ssh(user, ip, ssh_port, shell, command, capture) do
		base_ssh_args = ["-o", "ConnectTimeout=#{ssh_connect_timeout()}", "-q", "-p", "#{ssh_port}", "#{user}@#{ip}"]
		{stdin, executable, args} = case shell do
			false when is_list(command) ->
				# ssh has no means to avoid the remote shell, but we can try to "escape" its
				# effects by passing the command over stdin and running it with xargs -0 env --
				# https://unix.stackexchange.com/a/205569/109817
				stdin    = Enum.join(command, "\x00")
				ssh_args = base_ssh_args ++ ["xargs -0 env --"]
				# Use head -c to close stdin because Erlang is unable to
				sh_args  = ["-c", "head -c #{byte_size(stdin)} | ssh #{ssh_args |> Enum.map(&insecure_quote/1) |> Enum.join(" ")}"]
				{stdin, "sh", sh_args}
			true when is_binary(command) ->
				ssh_args = base_ssh_args ++ [command]
				{"", "ssh", ssh_args}
		end
		case capture do
			true ->
				%Porcelain.Result{status: exit_code, out: out} =
					Porcelain.exec(executable, args, in: stdin, err: :out)
				{out, exit_code}
			false ->
				%Porcelain.Result{status: exit_code} =
					Porcelain.exec(executable, args, in: stdin,
						out: {:file, Process.group_leader},
						# "when using `Porcelain.Driver.Basic`, the only supported values
						# are `nil` (stderr will be printed to the terminal) and `:out`."
						err: nil,
						env: env_for_ssh()
					)
				{"", exit_code}
		end
	end

	defp insecure_quote(s) do
		s
		|> String.replace("\\", "\\\\")
		|> String.replace(" ", "\\ ")
	end

	defp all_tags(row) do
		virtual_tag_pairs = [
			{"hostname",       row.hostname},
			{"wireguard_port", row.wireguard_port},
			{"ssh_port",       row.ssh_port},
			{"country",        row.country},
			{"release",        row.release},
			{"boot",           row.boot},
		]
		virtual_tags = for {key, value} <- virtual_tag_pairs do
			case Converge.Util.tag_values(row.tags, key) do
				[]     -> "#{key}:#{value}"
				values ->
					raise(
						"""
						Unexpected non-virtual tags #{inspect reassemble_tags(key, values)} \
						conflict with virtual tag #{inspect "#{key}:#{value}"}; remove the conflicting tags.
						""")
			end
		end
		row.tags ++ virtual_tags
	end

	defp reassemble_tags(key, values) do
		for value <- values do
			"#{key}:#{value}"
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
	def add(hostname, options) do
		{wireguard_port, wireguard_ip, wireguard_privkey, wireguard_pubkey} = case options.type do
			"debian" ->
				wireguard_ip      = to_ip_postgrex(get_unused_wireguard_ip())
				wireguard_privkey = WireGuard.make_wireguard_privkey()
				wireguard_pubkey  = WireGuard.get_wireguard_pubkey(wireguard_privkey)
				{options.wireguard_port, wireguard_ip, wireguard_privkey, wireguard_pubkey}
			"edgerouter" ->
				{nil, nil, nil, nil}
		end
		{:ok, _} = Repo.transaction(fn ->
			Repo.insert_all("machines", [[
				hostname:          hostname,
				type:              options.type,
				ssh_port:          options.ssh_port,
				ssh_user:          options.ssh_user,
				ssh_expose:        options.ssh_expose,
				wireguard_port:    wireguard_port,
				wireguard_ip:      wireguard_ip,
				wireguard_privkey: wireguard_privkey,
				wireguard_pubkey:  wireguard_pubkey,
				wireguard_expose:  options.wireguard_expose,
				country:           options.country,
				release:           options.release,
				boot:              options.boot,
			]])
			tag(hostname, options.tags)
			for {network, address} <- options.addresses do
				set_ip(hostname, network, address)
			end
		end)
	end

	def get_unused_wireguard_ip() do
		existing_ips =
			from("machines")
			|> select([m], m.wireguard_ip)
			|> where([m], not is_nil(m.wireguard_ip))
			|> Repo.all
			|> Enum.map(&to_ip_tuple/1)
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
			from("machine_addresses")        |> where([a], a.hostname in ^hostnames) |> Repo.delete_all
			from("machine_forwards")         |> where([f], f.hostname in ^hostnames) |> Repo.delete_all
			from("machines")                 |> where([m], m.hostname in ^hostnames) |> Repo.delete_all
		end)
		nil
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
		nil
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
		end)
		nil
	end

	@spec set_ip(String.t, String.t, String.t) :: nil
	def set_ip(hostname, network, address) do
		# Don't ignore conflicts on this insert: we want to see unique constraint
		# violations instead of silently ignoring them
		Repo.insert_all("machine_addresses", [[
			hostname: hostname,
			network:  network,
			address:  to_ip_postgrex(address),
		]])
		update_forwards()
		nil
	end

	@spec unset_ip(String.t, String.t, String.t) :: nil
	def unset_ip(hostname, network, address) do
		address = to_ip_postgrex(address)
		from("machine_addresses")
		|> where([a], a.hostname == ^hostname and a.network == ^network and a.address == ^address)
		|> Repo.delete_all
		update_forwards()
		nil
	end

	@spec set_ssh_port_many(Ecto.Queryable.t, integer) :: nil
	def set_ssh_port_many(queryable, ssh_port) do
		queryable
		|> Repo.update_all(set: [ssh_port: ssh_port])
		nil
	end

	@spec set_ssh_user_many(Ecto.Queryable.t, String.t) :: nil
	def set_ssh_user_many(queryable, ssh_user) do
		queryable
		|> Repo.update_all(set: [ssh_user: ssh_user])
		nil
	end

	@spec set_ssh_expose_many(Ecto.Queryable.t, String.t) :: nil
	def set_ssh_expose_many(queryable, ssh_expose) do
		queryable
		|> Repo.update_all(set: [ssh_expose: ssh_expose])
		update_forwards()
		nil
	end

	@spec set_wireguard_port_many(Ecto.Queryable.t, integer) :: nil
	def set_wireguard_port_many(queryable, wireguard_port) do
		queryable
		|> Repo.update_all(set: [wireguard_port: wireguard_port])
		nil
	end

	@spec set_wireguard_expose_many(Ecto.Queryable.t, String.t) :: nil
	def set_wireguard_expose_many(queryable, wireguard_expose) do
		queryable
		|> Repo.update_all(set: [wireguard_expose: wireguard_expose])
		update_forwards()
		nil
	end

	# We need to keep the port numbers in the machine_forwards table stable,
	# so the strategy here is to get a list of forwards we want (without
	# describing the port yet) and then adjust the machine_forwards table
	# by adding and removing rows, preserving any existing rows.
	defp update_forwards() do
		{:ok, _} = Repo.transaction(fn ->
			tree               = network_tree()
			inverted_tree      = invert_network_tree(tree)
			rows               = from("machines") |> list
			network_to_machine = Enum.flat_map(rows, fn row ->
				for network <- machine_networks(row) do
					{network, row}
				end
			end)
			|> into_map_with_multiple_values

			existing_forwards =
				from("machine_forwards")
				|> select([m], {m.hostname, m.type, m.final_destination, m.next_destination})
				|> Repo.all
				|> MapSet.new

			desired_forwards = Enum.flat_map(rows, fn row ->
				cond do
					row.wireguard_expose != nil -> describe_forward("wireguard", row, row, tree, inverted_tree, network_to_machine)
					row.ssh_expose       != nil -> describe_forward("ssh",       row, row, tree, inverted_tree, network_to_machine)
					true                        -> []
				end
			end)
			|> MapSet.new

			create_forwards = MapSet.difference(desired_forwards, existing_forwards)
			delete_forwards = MapSet.difference(existing_forwards, desired_forwards)

			new_rows = for {hostname, type, final_destination, next_destination} <- create_forwards do
				[
					hostname:          hostname,
					port:              get_unused_host_port(hostname, type),
					type:              type,
					next_destination:  next_destination,
					final_destination: final_destination
				]
			end

			Repo.insert_all("machine_forwards", new_rows)

			for {hostname, type, final_destination, next_destination} <- delete_forwards do
				from("machine_forwards") |> where([t],
					t.hostname          == ^hostname and
					t.type              == ^type and
					t.final_destination == ^final_destination and
					t.next_destination  == ^next_destination
				) |> Repo.delete_all
			end
		end)
	end

	# Return a a list of {hostname, type, final_destination, next_destination}
	# describing forwards that need to exist for `final_dest_row` to be reachable
	# on its exposed network.
	defp describe_forward(type, dest_row, final_dest_row, tree, inverted_tree, network_to_machine) do
		expose_to_network = case type do
			"wireguard" -> final_dest_row.wireguard_expose
			"ssh"       -> final_dest_row.ssh_expose
		end
		to_network    = uppermost_network(tree, machine_networks(dest_row))
		from_network  = inverted_tree[to_network]
		forwarder_row = pick_forwarding_machine(network_to_machine, from_network, to_network)
		this_forward  = {forwarder_row.hostname, type, final_dest_row.hostname, dest_row.hostname}
		more_forwards = if from_network != expose_to_network do
			describe_forward(type, forwarder_row, final_dest_row, tree, inverted_tree, network_to_machine)
		else
			[]
		end
		[this_forward | more_forwards]
	end

	defp pick_forwarding_machine(network_to_machine, from_network, to_network) do
		case forwarding_machines(network_to_machine, from_network, to_network) do
			# We expect only one forwarding machine
			[row] -> row
			[]    -> raise(
				"""
				Could not find a machine to serve as forwarder on networks \
				#{inspect({from_network, to_network})}
				""")
		end
	end

	defp forwarding_machines(network_to_machine, from_network, to_network) do
		network_to_machine[to_network]
		|> Enum.filter(fn row -> from_network in machine_networks(row) end)
	end

	defp machine_networks(row) do
		Enum.map(row.addresses, fn address -> address.network end)
	end

	defp uppermost_network(tree, networks) do
		depths = network_depth(tree)
		Enum.sort_by(networks, fn network -> depths[network] end) |> hd
	end

	@first_port 904 + 1
	@last_port  1023
	@skip_ports [989, 990, 991, 992, 993, 995]

	defp get_unused_host_port(hostname, type) do
		existing_ports =
			from("machine_forwards")
			|> where([m], m.hostname == ^hostname and m.type == ^type)
			|> select([m], m.port)
			|> Repo.all
			|> MapSet.new
		port_candidates = Stream.iterate(@first_port, &increment_host_port/1)
		Enum.find(port_candidates, fn port -> not MapSet.member?(existing_ports, port) end)
	end

	def increment_host_port(port) when port >= @first_port and port < @last_port do
		candidate = port + 1
		if candidate in @skip_ports do
			increment_host_port(candidate)
		else
			candidate
		end
	end
	def increment_host_port(port) do
		raise("Port cannot be incremented further: #{port}")
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
		row =
			machine(hostname)
			|> list()
			|> hd
		all_tags(row)
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

	def to_ip_postgrex(ip) do
		%Postgrex.INET{address: to_ip_tuple(ip), netmask: 32}
	end

	@spec to_ip_tuple(String.t) :: ip_tuple
	def to_ip_tuple(s) when is_binary(s) do
		s
		|> String.split(".")
		|> Enum.map(&String.to_integer/1)
		|> List.to_tuple
		|> validated_ip_tuple
	end
	def to_ip_tuple(%Postgrex.INET{address: address}), do: validated_ip_tuple(address)
	def to_ip_tuple({_, _, _, _} = tuple),             do: validated_ip_tuple(tuple)

	def to_ip_string(s) when is_binary(s),                   do: s
	def to_ip_string(%Postgrex.INET{address: {a, b, c, d}}), do: "#{a}.#{b}.#{c}.#{d}"

	# Validate IP addresses to avoid constructing Postgrex.INET structs with
	# invalid octets and then having postgrex encode those overflowing values
	# (e.g. .333 as .77).
	defp validated_ip_tuple({a, b, c, d} = tuple) when \
		is_integer(a) and \
		is_integer(b) and \
		is_integer(c) and \
		is_integer(d) and \
		a >= 0 and a < 256 and \
		b >= 0 and b < 256 and \
		c >= 0 and c < 256 and \
		d >= 0 and d < 256 do

		tuple
	end
	defp validated_ip_tuple(tuple), do: raise(ArgumentError, "Invalid IP tuple: #{inspect tuple}")

	# Get an IP address we can use to reach machine `row` from machine_manager
	defp mm_reachable_address!(row, parents \\ network_parents()) do
		case mm_reachable_address(row, parents) do
			nil ->
				networks = Enum.map(row.addresses, fn a -> a.network end)
				raise("Cannot reach #{row.hostname} from machine_manager; machine is on networks #{inspect networks}")
			address ->
				address
		end
	end

	defp mm_reachable_address(row, parents) do
		case reachable_addresses(parents, mm_row(), row) do
			[address | _] -> address
			_             -> nil
		end
	end

	defmemop mm_row() do
		[row] = list(machine(mm_hostname()))
		row
	end

	# Return the hostname of the machine running machine_manager
	defp mm_hostname() do
		{:ok, c} = :inet.gethostname()
		to_string(c)
	end

	# Get a list of addresses that machine `source_row` can use to reach machine `dest_row`.
	# If none, returns [].  parents should be the result of network_parents().
	defp reachable_addresses(parents, source_row, dest_row) do
		source_ip_map = network_to_ip_map(source_row.addresses)
		dest_ip_map   = network_to_ip_map(dest_row.addresses)
		net_to_net    = cartesian_product(Map.keys(source_ip_map), Map.keys(dest_ip_map))
		Enum.flat_map(net_to_net, fn {source_network, dest_network} ->
			if network_can_reach_network?(parents, source_network, dest_network) do
				dest_ip_map[dest_network]
			else
				[]
			end
		end)
	end

	defp network_to_ip_map(addresses) do
		Enum.reduce(addresses, %{}, fn(v, acc) ->
			Map.update(acc, v.network, [v.address], fn existing -> [v.address | existing] end)
		end)
	end

	# parents should be the result of network_parents()
	defp network_can_reach_network?(_parents, source_network, dest_network) when source_network == dest_network, do: true
	defp network_can_reach_network?(parents, source_network, dest_network), do: dest_network in (parents[source_network] || [])

	@doc """
	Return a map of network -> network depth

	tree is the result of network_tree()
	"""
	def network_depth(tree) do
		network_traverser(tree, nil, 0)
		|> Map.new
	end

	defp network_traverser(tree, key, depth) do
		Enum.flat_map((tree[key] || []), fn name ->
			[{name, depth} | network_traverser(tree, name, depth + 1)]
		end)
	end

	# Return a map of network -> child networks
	def network_tree() do
		net_list()
		|> Enum.map(fn %{name: name, parent: parent} -> {parent, name} end)
		|> into_map_with_multiple_values
	end

	defp invert_network_tree(tree) do
		Enum.flat_map(tree, fn {parent, children} ->
			for child <- children do
				{child, parent}
			end
		end)
		|> Map.new
	end

	# Return a map of network -> [all of network's parents]
	# TODO replace or delete - this doesn't actually do that
	defp network_parents() do
		Enum.map(net_list(), fn %{name: name, parent: parent} ->
			case parent do
				nil -> nil
				_   -> {name, parent}
			end
		end)
		|> Enum.reject(&is_nil/1)
		|> into_map_with_multiple_values
	end

	defp into_map_with_multiple_values(enumerable) do
		Enum.reduce(enumerable, %{}, fn {k, v}, acc ->
			Map.update(acc, k, [v], fn existing -> [v | existing] end)
		end)
	end

	@spec cartesian_product(Enum.t, Enum.t) :: [{term, term}]
	defp cartesian_product(a, b) do
		for x <- a, y <- b, do: {x, y}
	end
end
