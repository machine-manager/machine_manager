alias Gears.{TableFormatter, StringUtil}

defmodule MachineManager.Counter do
	defstruct pid: nil

	def new() do
		{:ok, pid} = Agent.start_link(fn -> 0 end)
		%MachineManager.Counter{pid: pid}
	end

	def increment(ec) do
		Agent.update(ec.pid, fn count -> count + 1 end)
	end

	def get(ec) do
		Agent.get(ec.pid, fn count -> count end)
	end
end


defmodule MachineManager.CLI do
	alias MachineManager.{Core, CPU, Counter, PortableErlang}

	def main(argv) do
		hostname_regexp_help   = "Regular expression used to match hostnames. Automatically wrapped with ^ and $."
		hostname_help          = "Machine hostname"
		boot_mode_help         = ~s[Boot mode ("outside", "mbr", "uefi", "scaleway_kexec", "vendor"); use "outside" for containers, "vendor" for edgerouter machines]
		ssh_expose_help        = "Outermost network to expose SSH port to, using port forwards"
		wireguard_expose_help  = "Outermost network to expose WireGuard port to, using port forwards"
		if_none_fragment_help  = ~s(; use "" or "-" if none)
		option_backup_ssh_port = [long: "--backup-ssh-port", help: "Retry on this SSH port if the configured SSH ports fails.", default: 22]
		spec = Optimus.new!(
			name:               "mm",
			description:        "machine_manager",
			allow_unknown_args: false,
			parse_double_dash:  true,
			subcommands: [
				net: [
					name:  "net",
					about: "Network management commands",
					subcommands: [
						ls: [
							name:  "ls",
							about: "List networks",
						],
						add: [
							name:  "add",
							about: "Add network",
							args: [
								netname: [required: true, help: "Network name"],
								parent:  [required: true, help: "Parent network" <> if_none_fragment_help],
							],
						],
						rm: [
							name:  "rm",
							about: "Remove network",
							args: [
								netname: [required: true, help: "Network name"],
							],
						],
					],
				],
				forward: [
					name:  "forward",
					about: "Port forward commands",
					subcommands: [
						ls: [
							name:  "ls",
							about: "List forwards",
							flags:   [
								no_header: [long: "--no-header", help: "Don't print the column header"],
							],
							options: [
								color: color_option(),
								columns: [short: "-c", long: "--column", multiple: true, help:
									"""
									Column to include in the output.  Can be specified multiple times.  One of: \
									#{get_forward_column_spec() |> Map.keys |> Enum.join(" ")}.                                           \
									If no columns given, uses the default of: \
									#{default_forward_columns() |> Enum.join(" ")}
									"""
								],
							],
							args:  [
								hostname_regexp: [required: false, help: hostname_regexp_help <> "  If not given, forwards for all machines will be listed."],
							],
						],
					],
				],
				ls: [
					name:    "ls",
					about:   "List machines",
					flags:   [
						no_header: [long: "--no-header", help: "Don't print the column header"],
					],
					options: [
						color:   color_option(),
						columns: [short: "-c", long: "--column", multiple: true, help:
							"""
							Column to include in the output.  Can be specified multiple times.  One of: \
							#{get_machine_column_spec() |> Map.keys |> Enum.join(" ")}.                                           \
							If no columns given, uses the default of: \
							#{default_machine_columns() |> Enum.join(" ")}
							"""
						],
					],
					args: [
						hostname_regexp: [required: false, help: hostname_regexp_help <> "  If not given, all machines will be listed."],
					],
				],
				ssh_config: [
					name:  "ssh_config",
					about: "Output an SSH config with all machines to stdout",
				],
				connectivity: [
					name:  "connectivity",
					about: "Output a machine connectivity graph as a .dot file to stdout, for use with Graphviz",
					args: [
						type: [required: true, help: ~s(Connectivity type: either "wireguard" or "public")],
					]
				],
				wireguard_config: [
					name:  "wireguard_config",
					about: "Output a WireGuard configuration file for a machine to stdout",
					args: [
						hostname: [required: true, help: hostname_help],
					],
				],
				hosts_json_file: [
					name:  "hosts_json_file",
					about: "Output the .wg and .pi hosts for a machine as JSON to stdout",
					args: [
						hostname: [required: true, help: hostname_help],
					],
				],
				portable_erlang: [
					name:  "portable_erlang",
					about: "Write a portable Erlang installation for a machine to the given directory (must not exist)",
					args: [
						hostname:  [required: true, help: hostname_help],
						directory: [required: true, help: "Output directory"],
					],
				],
				script: [
					name:  "script",
					about: "Write a configuration script suitable for a particular machine.  Note that tags must be passed to the script as arguments when it is run on the target machine.",
					args: [
						hostname:    [required: true, help: hostname_help],
						output_file: [required: true, help: "Output file"],
					],
					flags: [
						allow_warnings: [long: "--allow-warnings", help: "Write the script even if there are warnings during the build."],
					]
				],
				configure: [
					name:  "configure",
					about: "Configure machines",
					flags: [
						show_progress:   [long: "--progress",        help: "Show configure progress.  Works only when configuring a single server."],
						allow_warnings:  [long: "--allow-warnings",  help: "Write the script even if there are warnings during the build."],
					],
					options: [
						backup_ssh_port: option_backup_ssh_port,
					],
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
					],
				],
				upgrade: [
					name:  "upgrade",
					about: "Upgrade all packages to the new versions in our 'pending upgrades' list for machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
					],
					options: [
						backup_ssh_port: option_backup_ssh_port,
					],
				],
				reboot: [
					name:  "reboot",
					about: "Shut down and reboot machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
					],
				],
				shutdown: [
					name:  "shutdown",
					about: "Shut down and power-off machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
					],
				],
				wait: [
					name:  "wait",
					about: "Wait for machines to boot and have SSH connectivity",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
					],
				],
				setup: [
					name:  "setup",
					about: "Perform initial setup on machines: configure, probe, upgrade, reboot, wait, probe",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
					],
					options: [
						backup_ssh_port: option_backup_ssh_port,
					],
				],
				probe: [
					name:  "probe",
					about: "Probe machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
					],
					options: [
						backup_ssh_port: option_backup_ssh_port,
					],
				],
				exec: [
					name:  "exec",
					about: "Execute command on machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
						command:         [required: true, help: "Command to execute on each machine (by default, executed without shell interpretation; additional arguments are passed to command)", value_name: "COMMAND..."],
					],
					flags: [
						shell: [short: "-s", long: "--shell", help: "Run command with shell interpretation (must give just one COMMAND)"],
					],
					allow_unknown_args: true,
				],
				add: [
					name:  "add",
					about: "Add a machine",
					args: [
						hostname: [required: true, help: hostname_help],
					],
					options: [
						type:             [short: "-y", long: "--type",             required: false, default: "debian", help: ~s[Type ("debian" or "nixos" or "edgerouter")]],
						release:          [short: "-r", long: "--release",          required: true,                     help: ~s[Debian release (e.g. "sid") or "unmanaged"]],
						addresses:        [short: "-a", long: "--address",          required: false, multiple: true,    help: "Network and IPv4 address specified as NETWORK=ADDRESS", parser: &parse_address/1],
						ssh_user:         [short: "-u", long: "--ssh-user",         required: false, default: "root",   help: "SSH user"],
						ssh_port:         [short: "-s", long: "--ssh-port",         parser: :integer, default: 904,     help: "SSH port"],
						ssh_expose:       [short: "-S", long: "--ssh-expose",       required: false,                    help: ssh_expose_help],
						wireguard_port:   [short: "-w", long: "--wireguard-port",   parser: :integer, default: 904,     help: "WireGuard port"],
						wireguard_expose: [short: "-W", long: "--wireguard-expose", required: false,                    help: wireguard_expose_help],
						country:          [short: "-c", long: "--country",          required: true,                     help: "Country code"],
						boot:             [short: "-b", long: "--boot",             required: true,                     help: boot_mode_help],
						tags:             [short: "-t", long: "--tag",              required: false, multiple: true,    help: "Tag"],
					],
				],
				rm: [
					name:  "rm",
					about: "Remove machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
					],
				],
				tag: [
					name:  "tag",
					about: "Add tags to machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
						tag:             [required: false, help: "Tags to add", value_name: "TAG..."],
					],
					allow_unknown_args: true,
				],
				untag: [
					name:  "untag",
					about: "Remove tags from machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
						tag:             [required: false, help: "Tags to remove", value_name: "TAG..."],
					],
					allow_unknown_args: true,
				],
				get_tags: [
					name:  "get-tags",
					about: "Get tags (including virtual tags) for a machine in alphanumeric order, one tag per line",
					options: [
						color: color_option(),
					],
					args: [
						hostname: [required: true, help: hostname_help],
					],
				],
				set_ip: [
					name:  "set-ip",
					about: "Set an IP address for a machine",
					args: [
						hostname: [required: true, help: hostname_help],
						network:  [required: true, help: "Network name"],
						address:  [required: true, help: "IPv4 address"],
					],
				],
				unset_ip: [
					name:  "unset-ip",
					about: "Remove an IP address for a machine",
					args: [
						hostname: [required: true, help: hostname_help],
						network:  [required: true, help: "Network name"],
						address:  [required: true, help: "IPv4 address"],
					],
				],
				set_ssh_port: [
					name:  "set-ssh-port",
					about: "Set a new SSH port for machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
						ssh_port:        [required: true, parser: :integer],
					],
				],
				set_ssh_expose: [
					name:  "set-ssh-expose",
					about: "Set a new SSH exposure",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
						network:         [required: true, help: ssh_expose_help <> if_none_fragment_help],
					],
				],
				set_ssh_user: [
					name:  "set-ssh-user",
					about: "Set a new SSH user for machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
						ssh_user:        [required: true],
					],
				],
				set_wireguard_port: [
					name:  "set-wireguard-port",
					about: "Set a new WireGuard port for machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
						wireguard_port:  [required: true, parser: :integer],
					],
				],
				set_wireguard_expose: [
					name:  "set-wireguard-expose",
					about: "Set a new WireGuard exposure",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
						network:         [required: true, help: wireguard_expose_help <> if_none_fragment_help],
					],
				],
				rekey_wireguard: [
					name:  "rekey-wireguard",
					about: "Regenerate WireGuard keys for machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
					],
				],
			]
		)

		# Rewrite argv to optimus' expectations
		argv = case argv do
			[]                     -> ["--help"]
			["-h"]                 -> ["--help"]
			["help"]               -> ["--help"]
			["net", "help"]        -> ["help", "net"]
			["net", "help", c]     -> ["help", "net", c]
			["net", "--help"]      -> ["help", "net"]
			["net", "-h"]          -> ["help", "net"]
			["forward", "help"]    -> ["help", "forward"]
			["forward", "help", c] -> ["help", "forward", c]
			["forward", "--help"]  -> ["help", "forward"]
			["forward", "-h"]      -> ["help", "forward"]
			other                  -> other
		end

		{subcommands, %{args: args, options: options, flags: flags, unknown: unknown}} =
			case Optimus.parse!(spec, argv) do
				{subcommands, rest} -> {subcommands, rest}
				%{}                 -> raise("Subcommand required; see: mm help")
			end

		# https://github.com/erlang/otp/pull/480 was rejected, so instead we have the
		# wrapper script `mm` set MACHINE_MANAGER_ANSI_ENABLED=1 if stdout and stderr
		# look like a terminal.
		ansi_enabled = case options do
			%{color: :always} -> true
			%{color: :never}  -> false
			_                 -> System.get_env("MACHINE_MANAGER_ANSI_ENABLED") == "1"
		end
		Application.put_env(:elixir, :ansi_enabled, ansi_enabled)

		# debug, info, warn, or error
		# For debug, must be compiled with MIX_ENV=dev
		level = System.get_env("MACHINE_MANAGER_LOG_LEVEL") || "warn"
		Logger.configure(level: String.to_atom(level))
		Logger.configure_backend(:console,
			colors:   [enabled: ansi_enabled],
			metadata: [:module, :line, :pid],
			format:   "$time $metadata[$level] $levelpad$message\n"
		)

		ctx = Core.new_context()

		case subcommands do
			[:net     | rest] -> net(rest, args, options, flags, unknown)
			[:forward | rest] -> forward(rest, args, options, flags, unknown)
			[subcommand]  -> case subcommand do
				:ls                   -> list(args.hostname_regexp, options.columns, (if flags.no_header, do: false, else: true))
				:script               -> Core.write_script_for_machine(args.hostname, args.output_file, allow_warnings: flags.allow_warnings)
				:configure            -> configure_many(ctx, args.hostname_regexp, options.backup_ssh_port, flags.show_progress, flags.allow_warnings)
				:setup                -> setup_many(ctx, args.hostname_regexp, options.backup_ssh_port)
				:ssh_config           -> ssh_config(ctx)
				:connectivity         -> Core.connectivity(args.type)
				:wireguard_config     -> wireguard_config(args.hostname)
				:hosts_json_file      -> hosts_json_file(args.hostname)
				:portable_erlang      -> portable_erlang(args.hostname, args.directory)
				:probe                -> probe_many(ctx, args.hostname_regexp, options.backup_ssh_port)
				:exec                 -> exec_many(ctx, args.hostname_regexp, flags.shell, all_arguments(args.command, unknown))
				:upgrade              -> upgrade_many(ctx, args.hostname_regexp, options.backup_ssh_port)
				:reboot               -> reboot_many(ctx, args.hostname_regexp)
				:shutdown             -> shutdown_many(ctx, args.hostname_regexp)
				:wait                 -> wait_many(ctx, args.hostname_regexp)
				:add                  -> Core.add(args.hostname, options)
				:rm                   -> Core.rm_many(Core.machines_matching_regexp(args.hostname_regexp))
				:tag                  -> Core.tag_many(Core.machines_matching_regexp(args.hostname_regexp),   all_arguments(args.tag, unknown))
				:untag                -> Core.untag_many(Core.machines_matching_regexp(args.hostname_regexp), all_arguments(args.tag, unknown))
				:get_tags             -> get_tags(args.hostname)
				:set_ip               -> Core.set_ip(args.hostname, args.network, args.address)
				:unset_ip             -> Core.unset_ip(args.hostname, args.network, args.address)
				:set_ssh_port         -> Core.set_ssh_port_many(Core.machines_matching_regexp(args.hostname_regexp), args.ssh_port)
				:set_ssh_user         -> Core.set_ssh_user_many(Core.machines_matching_regexp(args.hostname_regexp), args.ssh_user)
				:set_ssh_expose       -> Core.set_ssh_expose_many(Core.machines_matching_regexp(args.hostname_regexp), empty_to_nil(args.network))
				:set_wireguard_port   -> Core.set_wireguard_port_many(Core.machines_matching_regexp(args.hostname_regexp), args.wireguard_port)
				:set_wireguard_expose -> Core.set_wireguard_expose_many(Core.machines_matching_regexp(args.hostname_regexp), empty_to_nil(args.network))
				:rekey_wireguard      -> Core.rekey_wireguard_many(Core.machines_matching_regexp(args.hostname_regexp))
			end
		end
	end

	defp parse_address(s) do
		case String.split(s, "=") do
			[network, address] -> {:ok, {network, address}}
			_                  -> {:error, "Could not parse a NETWORK=ADDRESS from #{inspect s}"}
		end
	end

	# https://github.com/savonarola/optimus/issues/3
	defp all_arguments(maybe_first, rest) do
		case maybe_first do
			nil -> []
			_   -> [maybe_first | rest]
		end
	end

	defp color_option() do
		[
			long:     "--color",
			help:     ~s(Default "auto"; use "always" to output ANSI color codes even to non-terminals; "never" to never output ANSI color codes even to terminals),
			parser:   fn(s) ->
				case s do
					"auto"   -> {:ok, :auto}
					"always" -> {:ok, :always}
					"never"  -> {:ok, :never}
					nil      -> {:ok, :auto}
					other    -> {:error, "Unexpected value for --color: #{inspect other}"}
				end
			end,
		]
	end

	defp net(subcommands, args, _options, _flags, _unknown) do
		subcommand = case subcommands do
			[subcommand] -> subcommand
			_            -> raise("Subcommand required; see: mm help net")
		end
		case subcommand do
			:ls  -> net_ls()
			:add -> net_add(args.netname, args.parent)
			:rm  -> Core.net_rm(args.netname)
		end
	end

	defp net_ls() do
		print_tree(Core.network_tree(), nil, 0)
	end

	defp net_add(name, parent) do
		Core.net_add(name, empty_to_nil(parent))
	end

	defp print_tree(tree, key, depth) do
		indent = String.duplicate("   ", depth)
		for name <- tree[key] || [] do
			IO.puts("#{indent}#{name}")
			print_tree(tree, name, depth + 1)
		end
	end

	defp forward(subcommands, args, options, flags, _unknown) do
		subcommand = case subcommands do
			[subcommand] -> subcommand
			_            -> raise("Subcommand required; see: mm help forward")
		end
		case subcommand do
			:ls  -> forward_list(args.hostname_regexp, options.columns, (if flags.no_header, do: false, else: true))
		end
	end

	defp forward_list(hostname_regexp, columns, print_header) do
		hostname_regexp = case hostname_regexp do
			nil -> ".*"
			_   -> hostname_regexp
		end
		rows          = Core.forward_list(hostname_regexp)
		columns       = case columns do
			[] -> default_forward_columns()
			_  -> columns
		end
		column_spec   = get_forward_column_spec()
		header_row    = get_column_header_row(column_spec, columns)
		table         = Enum.map(rows, fn row ->
			Enum.map(columns, fn column ->
				{_, func} = column_spec[column]
				func.(row)
			end)
		end)
		table         = case print_header do
			true  -> [header_row | table]
			false -> table
		end
		out = TableFormatter.format(table, padding: 2, width_fn: &width_fn/1)
		:ok = IO.write(out)
	end

	defp default_forward_columns() do
		["hostname", "protocol", "source_port", "next_destination", "destination_port", "final_destination"]
	end

	defp get_forward_column_spec() do
		%{
			"hostname"          => {"HOSTNAME",   fn row -> row.hostname end},
			"protocol"          => {"PROTO",      fn row -> row.protocol |> colorize(if row.protocol == "tcp", do: 6, else: 3) end},
			"source_port"       => {"PORT",       fn row -> "#{row.source_port}" end},
			"next_destination"  => {"DEST",       fn row -> row.next_destination end},
			"destination_port"  => {"PORT",       fn row -> "#{row.destination_port}" end},
			"type"              => {"TYPE",       fn row -> row.type |> colorize end},
			"final_destination" => {"FINAL DEST", fn row -> row.final_destination end},
		}
	end

	defp ssh_config(ctx) do
		:ok = IO.write(Core.ssh_config(ctx))
	end

	defp wireguard_config(hostname) do
		:ok = IO.write(Core.wireguard_config(hostname))
	end

	defp hosts_json_file(hostname) do
		:ok = IO.write(Core.hosts_json_file(hostname))
	end

	defp portable_erlang(hostname, dest) do
		row  = Core.list(Core.machine(hostname)) |> hd
		arch = Converge.Util.architecture_for_tags(row.tags)
		File.mkdir!(dest)
		PortableErlang.make_portable_erlang(dest, arch)
	end

	defp configure_many(ctx, hostname_regexp, retry_on_port, show_progress, allow_warnings) do
		error_counter = Counter.new()
		# If Core.configure is printing converge output to the terminal, we don't
		# want to overlap it with "# Waiting on host" output.
		handle_waiting = case show_progress do
			true  -> fn _ -> nil end
			false -> &handle_waiting/1
		end
		Core.configure_many(
			ctx,
			Core.machines_matching_regexp(hostname_regexp),
			retry_on_port,
			fn hostname, task_result -> handle_message_result(:configured, hostname, task_result, error_counter) end,
			handle_waiting,
			show_progress,
			allow_warnings
		)
		nonzero_exit_if_errors(error_counter)
	end

	defp setup_many(ctx, hostname_regexp, retry_on_port) do
		error_counter = Counter.new()
		Core.setup_many(
			ctx,
			Core.machines_matching_regexp(hostname_regexp),
			retry_on_port,
			fn hostname, task_result -> handle_message_result(:setup, hostname, task_result, error_counter) end,
			&handle_waiting/1
		)
		nonzero_exit_if_errors(error_counter)
	end

	defp upgrade_many(ctx, hostname_regexp, backup_ssh_port) do
		error_counter = Counter.new()
		Core.upgrade_many(
			ctx,
			Core.machines_matching_regexp(hostname_regexp),
			backup_ssh_port,
			fn hostname, task_result -> handle_message_result(:upgraded, hostname, task_result, error_counter) end,
			&handle_waiting/1
		)
		nonzero_exit_if_errors(error_counter)
	end

	defp handle_message_result(expected, hostname, task_result, error_counter) do
		pretty_hostname = hostname |> String.pad_trailing(16) |> bolded
		case task_result do
			{:ok, ^expected} ->
				IO.puts("#{pretty_hostname} #{Atom.to_string(expected)}")
			{:ok, :no_pending_upgrades} ->
				IO.puts("#{pretty_hostname} had no pending upgrades in database; probe again if needed")
			{:ok, {:upgrade_error, message}} ->
				IO.puts("#{pretty_hostname} upgrade failed: #{message}")
				Counter.increment(error_counter)
			{:ok, {:configure_error, message}} ->
				IO.puts("#{pretty_hostname} configure failed: #{message}")
				Counter.increment(error_counter)
			{:ok, {:probe_error, message}} ->
				IO.puts("#{pretty_hostname} probe failed: #{message}")
				Counter.increment(error_counter)
			{:ok, {:wait_error, message}} ->
				IO.puts("#{pretty_hostname} wait failed: #{message}")
				Counter.increment(error_counter)
			{:exit, reason} ->
				IO.puts("#{pretty_hostname} #{Atom.to_string(expected)} task failed: #{reason}")
				Counter.increment(error_counter)
		end
	end

	defp reboot_many(ctx, hostname_regexp) do
		error_counter = Counter.new()
		Core.reboot_many(
			ctx,
			Core.machines_matching_regexp(hostname_regexp),
			fn hostname, task_result -> handle_exec_result(hostname, task_result, error_counter) end,
			&handle_waiting/1
		)
		nonzero_exit_if_errors(error_counter)
	end

	defp shutdown_many(ctx, hostname_regexp) do
		error_counter = Counter.new()
		Core.shutdown_many(
			ctx,
			Core.machines_matching_regexp(hostname_regexp),
			fn hostname, task_result -> handle_exec_result(hostname, task_result, error_counter) end,
			&handle_waiting/1
		)
		nonzero_exit_if_errors(error_counter)
	end

	defp wait_many(ctx, hostname_regexp) do
		error_counter = Counter.new()
		Core.wait_many(
			ctx,
			Core.machines_matching_regexp(hostname_regexp),
			fn hostname, task_result -> handle_exec_result(hostname, task_result, error_counter) end,
			&handle_waiting/1
		)
		nonzero_exit_if_errors(error_counter)
	end

	defp exec_many(ctx, hostname_regexp, shell, command) do
		error_counter = Counter.new()
		command = case shell do
			true ->
				case command do
					[s] -> s
					_   -> raise("If shell interpretation is enabled, provide exactly one command; got #{inspect command}")
				end
			_ -> command
		end
		Core.exec_many(
			ctx,
			Core.machines_matching_regexp(hostname_regexp),
			shell,
			command,
			fn hostname, task_result -> handle_exec_result(hostname, task_result, error_counter) end,
			&handle_waiting/1
		)
		nonzero_exit_if_errors(error_counter)
	end

	defp handle_exec_result(hostname, task_result, error_counter) do
		pretty_hostname = hostname |> String.pad_trailing(16) |> bolded
		green           = {24,  154, 0}
		red             = {187, 10,  0}
		case task_result do
			{:ok, {output, exit_code}} ->
				code_color = if exit_code == 0, do: green, else: red
				code_text  = "code=#{exit_code |> to_string |> String.pad_trailing(3)}" |> with_fgcolor(code_color)
				IO.puts("#{pretty_hostname} #{code_text} #{inspect output}")
				if exit_code != 0 do
					Counter.increment(error_counter)
				end
			{:exit, reason} ->
				code_text  = "code=nil" |> with_fgcolor(red)
				IO.puts("#{pretty_hostname} #{code_text} #{inspect reason}")
				Counter.increment(error_counter)
		end
	end

	defp probe_many(ctx, hostname_regexp, retry_on_port) do
		error_counter = Counter.new()
		Core.probe_many(
			ctx,
			Core.machines_matching_regexp(hostname_regexp),
			retry_on_port,
			fn hostname, task_result -> handle_message_result(:probed, hostname, task_result, error_counter) end,
			&handle_waiting/1
		)
		nonzero_exit_if_errors(error_counter)
	end

	defp handle_waiting(waiting_task_map) do
		IO.puts(
			"# Waiting on: #{waiting_task_map |> Map.keys |> Enum.join(" ")}"
			|> with_fgcolor({150, 150, 150})
		)
	end

	defp nonzero_exit_if_errors(error_counter) do
		if Counter.get(error_counter) > 0 do
			System.halt(1)
		end
	end

	defp empty_to_nil(""),  do: nil
	defp empty_to_nil("-"), do: nil
	defp empty_to_nil(s),   do: s

	defp list(hostname_regexp, columns, print_header) do
		hostname_regexp = case hostname_regexp do
			nil -> ".*"
			_   -> hostname_regexp
		end
		columns = case columns do
			[] -> default_machine_columns()
			_  -> columns
		end
		rows          = Core.list(Core.machines_matching_regexp(hostname_regexp))
		column_spec   = get_machine_column_spec()
		header_row    = get_column_header_row(column_spec, columns)
		tag_frequency = make_tag_frequency(rows)
		table         = Enum.map(rows, fn row -> sql_row_to_table_row(column_spec, columns, row, tag_frequency) end)
		table         = case print_header do
			true  -> [header_row | table]
			false -> table
		end
		out = TableFormatter.format(table, padding: 2, width_fn: &width_fn/1)
		:ok = IO.write(out)
	end

	defp get_column_header_row(column_spec, columns) do
		Enum.map(columns, fn column ->
			case column_spec[column] do
				{header, _display_function} -> bolded(header)
				_ -> raise(RuntimeError, "No such column #{inspect column}")
			end
		end)
	end

	defp default_machine_columns() do
		[
			"hostname", "type", "addresses", "wireguard_ip", "wireguard_port",
			"ssh_port", "wireguard_expose", "ssh_expose",
			"ssh_user", "country", "release", "boot", "tags", "ram_mb",
			"cpu_model_name", "core_count", "thread_count", "last_probe_time",
			"boot_time", "time_offset", "kernel", "pending_upgrades",
		]
	end

	defp get_machine_column_spec() do
		%{
			"hostname"         => {"HOSTNAME",         fn row, _ -> row.hostname end},
			"type"             => {"TYPE",             fn row, _ -> row.type |> colorize end},
			"addresses"        => {"ADDRESSES",        &format_addresses/2},
			"wireguard_ip"     => {"WG IP",            fn row, _ -> if row.wireguard_ip     != nil, do: row.wireguard_ip |> Core.to_ip_string, else: "-" end},
			"wireguard_port"   => {"WG",               fn row, _ -> if row.wireguard_port   != nil, do: row.wireguard_port,   else: "-" end},
			"ssh_port"         => {"SSH",              fn row, _ -> row.ssh_port end},
			"wireguard_expose" => {"WG EX",            fn row, _ -> if row.wireguard_expose != nil, do: row.wireguard_expose, else: "-" end},
			"ssh_expose"       => {"SSH EX",           fn row, _ -> if row.ssh_expose       != nil, do: row.ssh_expose,       else: "-" end},
			"ssh_user"         => {"USER",             fn row, _ -> row.ssh_user end},
			"country"          => {"CC",               fn row, _ -> row.country |> colorize end},
			"release"          => {"RELEASE",          fn row, _ -> row.release |> colorize end},
			"boot"             => {"BOOT",             fn row, _ -> row.boot    |> colorize end},
			"tags"             => {"TAGS",             &format_tags/2},
			"ram_mb"           => {"RAM",              fn row, _ -> row.ram_mb end},
			"cpu_model_name"   => {"CPU",              fn row, _ -> if row.cpu_model_name   != nil, do: row.cpu_model_name |> CPU.short_description end},
			"cpu_architecture" => {"ARCH",             fn row, _ -> row.cpu_architecture end},
			"core_count"       => {"CO",               fn row, _ -> row.core_count end},
			"thread_count"     => {"TH",               fn row, _ -> row.thread_count end},
			"last_probe_time"  => {"PROBE TIME",       fn row, _ -> if row.last_probe_time  != nil, do: row.last_probe_time |> pretty_datetime |> colorize_time end},
			"boot_time"        => {"BOOT TIME",        fn row, _ -> if row.boot_time        != nil, do: row.boot_time       |> pretty_datetime |> colorize_time end},
			"time_offset"      => {"TIME OFFSET",      &format_time_offset/2},
			"kernel"           => {"KERNEL",           &format_kernel/2},
			"pending_upgrades" => {"PENDING UPGRADES", &format_pending_upgrades/2},
		}
	end

	defp format_addresses(row, _tag_frequency) do
		row.addresses
		|> Enum.map(
			fn %{network: network, address: address} ->
				"#{bolded(network)}#{with_fgcolor("=", {150, 150, 150})}#{Core.to_ip_string(maybe_scramble_ip(address))}"
			end)
		|> Enum.join(" ")
	end

	defp format_time_offset(row, _tag_frequency) do
		if row.time_offset != nil do
			case Decimal.to_string(row.time_offset, :normal) do
				"-" <> s -> "-" <> s
				s        -> "+" <> s
			end
		end
	end

	defp format_kernel(row, _tag_frequency) do
		if row.kernel != nil do
			row.kernel
			|> String.split(" ")
			|> Enum.take(3) # take "Linux 4.4.0-NN-generic #NN" but ignore "SMP" and the build date
			|> Enum.join(" ")
			|> String.replace_prefix("Linux ", "🐧  ")
			|> colorize
		end
	end

	defp format_pending_upgrades(row, _tag_frequency) do
		if row.pending_upgrades != nil do
			row.pending_upgrades
			|> Enum.map(fn upgrade -> "#{upgrade["package"]}#{with_fgcolor("=", {150, 150, 150})}#{bolded(upgrade["new_version"])}" end)
			|> Enum.join(" ")
		end
	end

	defp get_tags(hostname) do
		Core.get_tags(hostname)
		|> Enum.sort
		|> Enum.map(fn tag -> colorize_tag(tag) end)
		|> Enum.join("\n")
		|> Kernel.<>("\n")
		|> IO.write
	end

	defp format_tags(row, tag_frequency) do
		row.tags
		|> Enum.sort_by(fn tag -> {-tag_frequency[tag], tag} end)
		|> Enum.map(fn tag -> colorize_tag(tag) end)
		|> Enum.join(" ")
	end

	defp colorize_tag(tag) do
		# Compute our own hash to avoid including the bold ANSI codes
		# in the computation.
		hash = :erlang.crc32(tag)
		tag |> bold_first_part_if_multiple_parts() |> colorize(hash)
	end

	defp width_fn(s) do
		s
		|> StringUtil.strip_ansi
		|> StringUtil.half_width_length
	end

	defp make_tag_frequency(rows) do
		tags =
			rows
			|> Enum.flat_map(fn row -> row.tags end)
		Enum.reduce(tags, %{}, fn(tag, map) ->
			Map.update(map, tag, 1, &(&1 + 1))
		end)
	end

	defp sql_row_to_table_row(column_spec, columns, row, tag_frequency) do
		columns
		|> Enum.map(fn column -> {_, func} = column_spec[column]; func.(row, tag_frequency) end)
		|> Enum.map(fn value ->
			case value do
				value when is_binary(value) -> value
				nil                         -> "?"
				_                           -> inspect(value)
			end
		end)
	end

	defp colorize_time(iso_time) do
		[date, time] = iso_time |> String.split("T", parts: 2)
		"#{date}#{with_fgcolor("T", {150, 150, 150})}#{time}"
	end

	# Colorize the background color of a string in a manner that results in the
	# same background color for identical strings.
	@spec colorize(String.t, integer) :: String.t
	defp colorize(string, hash \\ nil) do
		bg_colors = [
			{196, 218, 255},
			{255, 196, 196},
			{255, 201, 242},
			{219, 201, 255},
			{198, 208, 255},
			{198, 235, 255},
			{198, 255, 246},
			{198, 255, 201},
			{224, 255, 198},
			# [no light yellow because we use a light yellow terminal background]
			{255, 228, 198},
			{255, 255, 255},
			{234, 234, 234},
			{214, 214, 214},
			{224, 193, 143},
		]
		hash = case hash do
			nil   -> :erlang.crc32(string)
			other -> other
		end
		idx       = rem(hash, length(bg_colors))
		bg_color  = Enum.fetch!(bg_colors, idx)
		with_bgcolor(string, bg_color)
	end

	@spec with_fgcolor(String.t, {integer, integer, integer}) :: String.t
	defp with_fgcolor(text, {red, green, blue}) do
		if IO.ANSI.enabled?() do
			# Requires a terminal with true color support: https://gist.github.com/XVilka/8346728
			fg = 38
			"\e[#{fg};2;#{red};#{green};#{blue}m#{text}\e[0m"
		else
			text
		end
	end

	@spec with_bgcolor(String.t, {integer, integer, integer}) :: String.t
	defp with_bgcolor(text, {red, green, blue}) do
		if IO.ANSI.enabled?() do
			# Requires a terminal with true color support: https://gist.github.com/XVilka/8346728
			bg = 48
			"\e[#{bg};2;#{red};#{green};#{blue}m#{text}\e[0m"
		else
			text
		end
	end

	defp bold_first_part_if_multiple_parts(tag) do
		if IO.ANSI.enabled?() do
			case String.split(tag, ":", parts: 2) do
				[first, rest] -> "#{bolded(first)}:#{rest}"
				[first]       -> first
			end
		else
			tag
		end
	end

	defp bolded(s) do
		if IO.ANSI.enabled?() do
			"#{IO.ANSI.bright()}#{s}#{IO.ANSI.normal()}"
		else
			s
		end
	end

	defp maybe_scramble_ip(inet) do
		# For demos
		case System.get_env("MACHINE_MANAGER_SCRAMBLE_IP") == "1" do
			true  -> scramble_ip(inet)
			false -> inet
		end
	end

	@random :rand.uniform(253)
	defp scramble_ip(%Postgrex.INET{address: {a, b, c, d}}) do
		use Bitwise
		address = cond do
			{a, b} == {192, 168} -> {a, b, c, d ^^^ @random}
			{a}    == {127}      -> {a, b, c, d}
			true                 -> {a, b, c ^^^ @random, d ^^^ @random}
		end
		%Postgrex.INET{address: address}
	end

	defp pretty_datetime(datetime) do
		datetime
		|> DateTime.to_iso8601
		|> String.split(".")
		|> hd
	end
end
