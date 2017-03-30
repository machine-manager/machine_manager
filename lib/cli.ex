alias Gears.{TableFormatter, StringUtil}

defmodule MachineManager.CLI do
	alias MachineManager.{Core, CPU}

	def main(argv) do
		hostname_regexp_help = "Regular expression used to match hostnames. Automatically wrapped with ^ and $."
		spec = Optimus.new!(
			name:               "machine_manager",
			description:        "machine_manager",
			allow_unknown_args: false,
			parse_double_dash:  true,
			subcommands: [
				ls: [
					name:    "ls",
					about:   "List machines",
					flags:   [
						no_header: [long: "--no-header", help: "Don't print the column header"],
					],
					options: [
						columns:   [short: "-c", long: "--column", multiple: true, help:
							"""
							Column to include in the output.  Can be specified multiple times.  One of: \
							#{get_column_spec() |> Map.keys |> Enum.join(" ")}.                                           \
							If no columns given, uses the default of: \
							#{default_columns() |> Enum.join(" ")}
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
				script: [
					name:  "script",
					about: "Write a configuration script suitable for a particular machine.  Note that tags must be passed in to the script as arguments.",
					args: [
						hostname:    [required: true],
						output_file: [required: true],
					],
					flags: [
						allow_warnings: [long: "--allow-warnings", help: "Write the script even if there are warnings during the build."],
					]
				],
				bootstrap: [
					name:  "bootstrap",
					about: "Bootstrap machines so that configure can be run on them",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
					],
				],
				configure: [
					name:  "configure",
					about: "Configure machines",
					flags: [
						show_progress: [long: "--progress", help:
							"""
							Show configure progress.  Works only when configuring a single server.
							Will not automatically bootstrap as needed.
							"""
						],
					],
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
					],
				],
				upgrade: [
					name:  "upgrade",
					about: "Upgrade all packages in our 'pending upgrades' list for machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
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
				probe: [
					name:  "probe",
					about: "Probe machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
					],
				],
				exec: [
					name:  "exec",
					about: "Execute command on machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
						command:         [required: true, help: "Command to execute on each machine"],
					],
				],
				add: [
					name:  "add",
					about: "Add a machine",
					args: [
						hostname: [required: true],
					],
					options: [
						public_ip:  [short: "-i", long: "--public-ip", required: true,                    help: "Public IP address"],
						datacenter: [short: "-d", long: "--dc",        required: true,                    help: "Datacenter"],
						ssh_port:   [short: "-p", long: "--ssh-port",  required: true,  parser: :integer, help: "SSH port"],
						tag:        [short: "-t", long: "--tag",       required: false, multiple: true,   help: "Tag"],
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
					about: "Get tags for a machine",
					args: [
						hostname: [required: true],
					],
				],
				set_public_ip: [
					name:  "set-public-ip",
					about: "Set new public IP for a machine",
					args: [
						hostname:  [required: true],
						public_ip: [required: true],
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
				rekey_wireguard: [
					name:  "rekey-wireguard",
					about: "Regenerate WireGuard keys for machines",
					args: [
						hostname_regexp: [required: true, help: hostname_regexp_help],
					],
				],
			],
		)
		{[subcommand], %{args: args, options: options, flags: flags, unknown: unknown}} = Optimus.parse!(spec, argv)
		case subcommand do
			:ls              -> list(args.hostname_regexp, options.columns, (if flags.no_header, do: false, else: true))
			:script          -> Core.write_script_for_machine(args.hostname, args.output_file, allow_warnings: flags.allow_warnings)
			:bootstrap       -> bootstrap_many(args.hostname_regexp)
			:configure       -> configure_many(args.hostname_regexp, flags.show_progress)
			:ssh_config      -> Core.ssh_config()
			:probe           -> probe_many(args.hostname_regexp)
			:exec            -> exec_many(args.hostname_regexp, args.command)
			:upgrade         -> upgrade_many(args.hostname_regexp)
			:reboot          -> reboot_many(args.hostname_regexp)
			:shutdown        -> shutdown_many(args.hostname_regexp)
			:add             -> Core.add(args.hostname, options.public_ip, options.ssh_port, options.datacenter, options.tag)
			:rm              -> Core.rm_many(args.hostname_regexp)
			:tag             -> Core.tag_many(args.hostname_regexp,   all_arguments(args.tag, unknown))
			:untag           -> Core.untag_many(args.hostname_regexp, all_arguments(args.tag, unknown))
			:get_tags        -> Core.get_tags(args.hostname) |> Enum.join(" ") |> IO.write
			:set_public_ip   -> Core.set_public_ip(args.hostname, args.public_ip)
			:set_ssh_port    -> Core.set_ssh_port_many(args.hostname_regexp, args.ssh_port)
			:rekey_wireguard -> Core.rekey_wireguard_many(args.hostname_regexp)
		end
	end

	# https://github.com/savonarola/optimus/issues/3
	defp all_arguments(maybe_first, rest) do
		case maybe_first do
			nil -> []
			_   -> [maybe_first | rest]
		end
	end

	def bootstrap_many(hostname_regexp) do
		Core.bootstrap_many(hostname_regexp, &handle_bootstrap_result/2, &handle_waiting/1)
	end

	defp handle_bootstrap_result(hostname, task_result) do
		pretty_hostname = hostname |> String.pad_trailing(16) |> bolded
		case task_result do
			{:ok, :bootstrapped} ->
				IO.puts("#{pretty_hostname} bootstrapped")
			{:ok, {:bootstrap_error, message}} ->
				IO.puts("#{pretty_hostname} bootstrap failed: #{message}")
			{:exit, reason} ->
				IO.puts("#{pretty_hostname} bootstrap task failed: #{reason}")
		end
	end

	def configure_many(hostname_regexp, show_progress) do
		# If Core.configure is printing converge output to the terminal, we don't
		# want to overlap it with "# Waiting on host" output.
		handle_waiting = case show_progress do
			true  -> fn _ -> nil end
			false -> &handle_waiting/1
		end
		Core.configure_many(hostname_regexp, &handle_configure_result/2, handle_waiting, show_progress)
	end

	defp handle_configure_result(hostname, task_result) do
		pretty_hostname = hostname |> String.pad_trailing(16) |> bolded
		case task_result do
			{:ok, :configured} ->
				IO.puts("#{pretty_hostname} configured")
			{:ok, {:configure_error, message}} ->
				IO.puts("#{pretty_hostname} configure failed: #{message}")
			{:ok, {:bootstrap_error, message}} ->
				IO.puts("#{pretty_hostname} bootstrap failed: #{message}")
			{:exit, reason} ->
				IO.puts("#{pretty_hostname} configure task failed: #{reason}")
		end
	end

	def upgrade_many(hostname_regexp) do
		Core.upgrade_many(hostname_regexp, &handle_upgrade_result/2, &handle_waiting/1)
	end

	defp handle_upgrade_result(hostname, task_result) do
		pretty_hostname = hostname |> String.pad_trailing(16) |> bolded
		case task_result do
			{:ok, :upgraded} ->
				IO.puts("#{pretty_hostname} upgraded")
			{:ok, :no_pending_upgrades} ->
				IO.puts("#{pretty_hostname} had no pending upgrades in database; probe again if needed")
			{:ok, {:upgrade_error, message}} ->
				IO.puts("#{pretty_hostname} upgrade failed: #{message}")
			{:ok, {:configure_error, message}} ->
				IO.puts("#{pretty_hostname} configure failed: #{message}")
			{:ok, {:bootstrap_error, message}} ->
				IO.puts("#{pretty_hostname} bootstrap failed: #{message}")
			{:exit, reason} ->
				IO.puts("#{pretty_hostname} upgrade task failed: #{reason}")
		end
	end

	def reboot_many(hostname_regexp) do
		Core.reboot_many(hostname_regexp, &handle_exec_result/2, &handle_waiting/1)
	end

	def shutdown_many(hostname_regexp) do
		Core.shutdown_many(hostname_regexp, &handle_exec_result/2, &handle_waiting/1)
	end

	def exec_many(hostname_regexp, command) do
		Core.exec_many(hostname_regexp, command, &handle_exec_result/2, &handle_waiting/1)
	end

	defp handle_exec_result(hostname, task_result) do
		pretty_hostname = hostname |> String.pad_trailing(16) |> bolded
		green           = {24,  154, 0}
		red             = {187, 10,  0}
		case task_result do
			{:ok, {output, exit_code}} ->
				code_color = if exit_code == 0, do: green, else: red
				code_text  = "code=#{exit_code |> to_string |> String.pad_trailing(3)}" |> with_fgcolor(code_color)
				IO.puts("#{pretty_hostname} #{code_text} #{inspect output}")
			{:exit, reason} ->
				code_text  = "code=nil" |> with_fgcolor(red)
				IO.puts("#{pretty_hostname} #{code_text} #{inspect reason}")
		end
	end

	def probe_many(hostname_regexp) do
		Core.probe_many(hostname_regexp, &handle_probe_result/2, &handle_waiting/1)
	end

	defp handle_probe_result(hostname, task_result) do
		pretty_hostname = hostname |> String.pad_trailing(16) |> bolded
		case task_result do
			{:ok, {:probed, nil}} ->
				IO.puts("#{pretty_hostname} probed")
			{:ok, {:probe_error, message}} ->
				IO.puts("#{pretty_hostname} probe failed: #{message}")
			{:exit, reason} ->
				IO.puts("#{pretty_hostname} probe task failed: #{reason}")
		end
	end

	defp handle_waiting(waiting_task_map) do
		IO.puts(
			"# Waiting on: #{waiting_task_map |> Map.keys |> Enum.join(" ")}"
			|> with_fgcolor({150, 150, 150})
		)
	end

	def list(hostname_regexp, columns, print_header) do
		hostname_regexp = case hostname_regexp do
			nil -> ".*"
			_   -> hostname_regexp
		end
		columns = case columns do
			[] -> default_columns()
			_  -> columns
		end
		rows          = Core.list(hostname_regexp)
		column_spec   = get_column_spec()
		header        = get_column_header(column_spec, columns)
		tag_frequency = make_tag_frequency(rows)
		table         = Enum.map(rows, fn row -> sql_row_to_table_row(column_spec, columns, row, tag_frequency) end)
		table         = case print_header do
			true  -> [header | table]
			false -> table
		end
		out           = TableFormatter.format(table, padding: 2, width_fn: &width_fn/1)
		:ok = IO.write(out)
	end

	defp get_column_header(column_spec, columns) do
		columns
		|> Enum.map(fn column ->
				tuple = column_spec[column]
				if tuple == nil do
					raise RuntimeError, message: "No such column #{inspect column}"
				end
				{header, _} = tuple
				header
			end)
		|> Enum.map(&bolded/1)
	end

	defp default_columns() do
		[
			"hostname", "public_ip", "wireguard_ip", "ssh_port", "tags", "datacenter",
			"country", "ram_mb", "cpu_model_name", "core_count", "thread_count",
			"last_probe_time", "boot_time", "kernel", "pending_upgrades",
		]
	end

	defp get_column_spec() do
		%{
			"hostname"         => {"HOSTNAME",         fn row, _ -> row.hostname end},
			"public_ip"        => {"PUBLIC IP",        fn row, _ -> row.public_ip    |> maybe_scramble_ip |> Core.inet_to_ip end},
			"wireguard_ip"     => {"WIREGUARD",        fn row, _ -> row.wireguard_ip |> Core.inet_to_ip end},
			"ssh_port"         => {"SSH",              fn row, _ -> row.ssh_port end},
			"tags"             => {"TAGS",             &format_tags/2},
			"datacenter"       => {"DC",               fn row, _ -> row.datacenter |> colorize end},
			"country"          => {"CC",               fn row, _ -> if row.country          != nil, do: row.country |> colorize end},
			"ram_mb"           => {"RAM",              fn row, _ -> row.ram_mb end},
			"cpu_model_name"   => {"CPU",              fn row, _ -> if row.cpu_model_name   != nil, do: row.cpu_model_name |> CPU.short_description end},
			"cpu_architecture" => {"ARCH",             fn row, _ -> row.cpu_architecture end},
			"core_count"       => {"CO",               fn row, _ -> row.core_count end},
			"thread_count"     => {"TH",               fn row, _ -> row.thread_count end},
			"last_probe_time"  => {"PROBE TIME",       fn row, _ -> if row.last_probe_time  != nil, do: row.last_probe_time |> pretty_datetime |> colorize_time end},
			"boot_time"        => {"BOOT TIME",        fn row, _ -> if row.boot_time        != nil, do: row.boot_time       |> pretty_datetime |> colorize_time end},
			"kernel"           => {"KERNEL",           fn row, _ -> if row.kernel           != nil, do: row.kernel |> String.replace_prefix("Linux ", "🐧  ") |> colorize end},
			"pending_upgrades" => {"PENDING UPGRADES", fn row, _ -> if row.pending_upgrades != nil, do: row.pending_upgrades |> Enum.map(&hd/1) |> Enum.join(" ") end},
		}
	end

	defp format_tags(row, tag_frequency) do
		row.tags
		|> Enum.sort_by(fn tag -> -tag_frequency[tag] end)
		|> Enum.map(fn tag ->
				# Compute our own hash to avoid including the bold ANSI codes
				# in the computation.
				hash = :erlang.crc32(tag)
				tag |> bold_first_part_if_multiple_parts |> colorize(hash)
			end)
		|> Enum.join(" ")
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

	def sql_row_to_table_row(column_spec, columns, row, tag_frequency) do
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
		idx       = rem(hash, bg_colors |> length)
		bg_color  = Enum.fetch!(bg_colors, idx)
		with_bgcolor(string, bg_color)
	end

	# Requires a terminal with true color support: https://gist.github.com/XVilka/8346728
	@spec with_fgcolor(String.t, {integer, integer, integer}) :: String.t
	defp with_fgcolor(text, {red, green, blue}) do
		fg = 38
		"\e[#{fg};2;#{red};#{green};#{blue}m#{text}\e[0m"
	end

	# Requires a terminal with true color support: https://gist.github.com/XVilka/8346728
	@spec with_bgcolor(String.t, {integer, integer, integer}) :: String.t
	defp with_bgcolor(text, {red, green, blue}) do
		bg = 48
		"\e[#{bg};2;#{red};#{green};#{blue}m#{text}\e[0m"
	end

	defp bold_first_part_if_multiple_parts(tag) do
		case tag |> String.split(":", parts: 2) do
			[first, rest] -> "#{bolded(first)}:#{rest}"
			[first]       -> first
		end
	end

	defp bolded(s) do
		"#{IO.ANSI.bright()}#{s}#{IO.ANSI.normal()}"
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

	def pretty_datetime(erlang_date) do
		erlang_date
		|> erlang_date_to_datetime
		|> DateTime.to_iso8601
		|> String.split(".")
		|> hd
	end

	# https://github.com/elixir-ecto/ecto/issues/1920
	def erlang_date_to_datetime({{year, month, day}, {hour, min, sec, usec}}) do
		%DateTime{
			year: year, month: month, day: day, hour: hour, minute: min,
			second: sec, microsecond: {usec, 6}, zone_abbr: "UTC", time_zone: "Etc/UTC",
			utc_offset: 0, std_offset: 0
		}
	end
end
