alias Gears.{TableFormatter, StringUtil, FileUtil}

defmodule MachineManager.CPU do
	@doc """
	Convert a CPU model name from /proc/cpuinfo into a shorter string.
	"""
	@spec short_description(String.t) :: String.t
	def short_description(cpu_model_name) do
		cpu_model_name
		|> String.replace_prefix("Intel Core Processor (Haswell, no TSX)", "Mystery Haswell")
		|> String.replace_prefix("Intel(R) Core(TM) ", "")
		|> String.replace_prefix("Intel(R) Xeon(R) ", "")
		|> String.replace_prefix("Intel(R) Atom(TM) ", "Atom ")
		|> String.replace(~r"(\b\d\.\d)\dGHz\b", "\\1GHz")
		|> String.replace(~r"\bCPU\b", "")
		|> String.replace(~r"\s+", " ")
		|> String.trim
	end
end

defmodule MachineManager.ScriptWriter do
	# We want to make a script for each combination of roles, not tags,
	# to avoid compiling a script for each tag combination.
	@spec write_script_for_roles([String.t], String.t) :: nil
	def write_script_for_roles(roles, output_filename) do
		dependencies = [{:converge,    ">= 0.1.0"},
		                {:base_system, ">= 0.1.0"}] ++ \
		               (roles |> Enum.map(fn role -> {"role_#{role}" |> String.to_atom, ">= 0.0.0"} end))
		role_modules = roles |> Enum.map(&module_for_role/1)
		temp_dir     = FileUtil.temp_dir("multi_role_script")
		app_name     = "multi_role_script"
		module       = MultiRoleScript
		lib          = Path.join([temp_dir, "lib", "#{app_name}.ex"])
		Mixmaker.create_project(temp_dir, app_name, module,
		                        dependencies, [main_module: module])
		File.write!(lib,
			"""
			defmodule #{inspect module} do
				def main(tags) do
					BaseSystem.Configure.configure_with_roles(tags, #{inspect role_modules})
				end
			end
			""")
		{_, 0} = System.cmd("mix", ["deps.get"],      cd: temp_dir)
		{_, 0} = System.cmd("mix", ["compile"],       cd: temp_dir, env: [{"MIX_ENV", "prod"}])
		{_, 0} = System.cmd("mix", ["escript.build"], cd: temp_dir, env: [{"MIX_ENV", "prod"}])
		File.cp!(Path.join(temp_dir, app_name), output_filename)
		nil
	end

	@doc """
	Extract a list of roles from a list of tags.
	"""
	@spec roles_for_tags([String.t]) :: [String.t]
	def roles_for_tags(tags) do
		tags
		|> Enum.filter(fn tag -> tag |> String.starts_with?("role:") end)
		|> Enum.map(fn tag -> tag |> String.replace_prefix("role:", "") end)
	end

	@doc """
	For a given role, return the module that contains the `role()` function.
	"""
	@spec module_for_role(String.t) :: module
	def module_for_role(role) do
		role
		|> String.split("_")
		|> Enum.map(&String.capitalize/1)
		|> Enum.join
		|> (fn s -> "Elixir.Role#{s}" end).()
		|> String.to_atom
	end
end

defmodule MachineManager.TooManyRowsError do
	defexception [:message]
end

defmodule MachineManager.ProbeError do
	defexception [:message]
end

defmodule MachineManager.UpgradeError do
	defexception [:message]
end

defmodule MachineManager.BadDataError do
	defexception [:message]
end

defmodule MachineManager.Core do
	alias MachineManager.{ScriptWriter, Repo, TooManyRowsError, ProbeError, UpgradeError, BadDataError}
	import Ecto.Query

	def list() do
		tags_aggregate =
			from("machine_tags")
			|> select([t], %{
					hostname: t.hostname,
					tags:     fragment("array_agg(?::character varying)", t.tag)
				})
			|> group_by([t], t.hostname)

		pending_upgrades_aggregate =
			from("machine_pending_upgrades")
			|> select([u], %{
					hostname:         u.hostname,
					pending_upgrades: fragment("array_agg(?::character varying)", u.package)
				})
			|> group_by([u], u.hostname)

		all_machines()
		|> select([m, t, u], %{
				hostname:         m.hostname,
				ip:               m.ip,
				ssh_port:         m.ssh_port,
				tags:             t.tags,
				pending_upgrades: u.pending_upgrades,
				last_probe_time:  m.last_probe_time,
				boot_time:        m.boot_time,
				country:          m.country,
				cpu_model_name:   m.cpu_model_name,
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
			all_machines()
			|> order_by(asc: :hostname)
			|> select([:hostname, :ip, :ssh_port])
			|> Repo.all
		for row <- rows do
			:ok = IO.write(sql_row_to_ssh_config_entry(row) <> "\n")
		end
	end

	defp sql_row_to_ssh_config_entry(row) do
		"""
		Host #{row.hostname}
		  Hostname #{inet_to_ip(row.ip)}
		  Port #{row.ssh_port}
		"""
	end

	def configure(hostname) do
		{:ok, {ip, ssh_port, tags}} = Repo.transaction(fn ->
			row =
				machine(hostname)
				|> select([:ip, :ssh_port])
				|> Repo.all
				|> one_row
			tags = get_tags_for_machine(hostname)
			{inet_to_ip(row.ip), row.ssh_port, tags}
		end)
		roles        = ScriptWriter.roles_for_tags(tags)
		script_cache = Path.expand("~/.cache/machine_manager/script_cache")
		basename     = roles |> Enum.sort |> Enum.join(",")
		output_file  = Path.join(script_cache, basename)
		File.mkdir_p!(script_cache)
		ScriptWriter.write_script_for_roles(roles, output_file)
		transfer_file(output_file, "root", hostname, ".cache/machine_manager/script",
		              before_rsync: "mkdir -p .cache/machine_manager")
		arguments    = [".cache/machine_manager/script"] ++ tags
		for arg <- arguments do
			if arg |> String.contains?(" ") do
				raise BadDataError, message:
					"""
					Argument list #{inspect arguments} contains an argument with a space: #{inspect arg}
					"""
			end
		end
		0 = ssh_no_capture("root", ip, ssh_port, arguments |> Enum.join(" "))
	end

	defp transfer_file(source, user, hostname, dest, opts) do
		before_rsync = opts[:before_rsync]
		args = case before_rsync do
			nil -> []
			_   -> ["--rsync-path", "#{before_rsync} && rsync"]
		end ++ \
		["--protect-args", "--executability", source, "#{user}@#{hostname}:#{dest}"]
		{"", 0} = System.cmd("rsync", args)
	end

	def probe(hostnames) do
		task_map = hostnames |> Enum.map(fn hostname ->
			{hostname, Task.async(fn ->
				probe_one(hostname)
			end)}
		end) |> Map.new
		block_on_tasks(task_map)
	end

	defp block_on_tasks(task_map) do
		pid_to_hostname  = task_map |> Enum.map(fn {hostname, task} -> {task.pid, hostname} end) |> Map.new
		waiting_task_map = for {task, result} <- Task.yield_many(task_map |> Map.values, 2000) do
			hostname = pid_to_hostname[task.pid] || raise RuntimeError, message: "hostname == nil for #{inspect task}"
			case result do
				{:ok, probe_out} ->
					IO.puts("PROBED #{hostname}: #{inspect probe_out}")
					write_probe_data_to_db(hostname, probe_out)
					nil
				{:exit, reason} ->
					IO.puts("FAILED #{hostname}: #{inspect reason}")
					nil
				nil ->
					{hostname, task}
			end
		end |> Enum.reject(&is_nil/1) |> Map.new
		if waiting_task_map != %{} do
			IO.puts("Still waiting on: #{waiting_task_map |> Map.keys |> Enum.join(" ")}")
			block_on_tasks(waiting_task_map)
		end
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

	def _atoms() do
		# Make sure these atoms are in the atom table
		[:ram_mb, :cpu_model_name, :cpu_architecture, :core_count, :thread_count,
		 :country, :kernel, :boot_time_ms, :pending_upgrades]
	end

	def upgrade(hostname) do
		packages = get_pending_upgrades_for_machine(hostname)
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
	end

	def reboot(hostname) do
		# Use `systemctl reboot` (which results in exit code 0 from ssh)
		# instead of `shutdown -r now` (exit code 255, cannot to distinguish from failure.)
		{_, 0} = run_on_machine(hostname, "systemctl reboot")
	end

	def shutdown(hostname) do
		{_, 0} = run_on_machine(hostname, "systemctl poweroff < /dev/null > /dev/null 2>/dev/null")
	end

	def probe_one(hostname) do
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
			0     -> Poison.decode!(output, keys: :atoms!)
			other -> raise ProbeError, message: "Probe of #{hostname} failed with exit code #{other}; output:\n\n#{output}"
		end
	end

	@spec run_on_machine(String.t, String.t) :: {String.t, integer}
	defp run_on_machine(hostname, command) do
		row =
			machine(hostname)
			|> select([:ip, :ssh_port])
			|> Repo.all
			|> one_row
		ssh("root", inet_to_ip(row.ip), row.ssh_port, command)
	end

	@doc """
	Runs `command` on machine at `ip` and `ssh_port` with user `user`, returns
	`{output, exit_code}`.  Output includes both stdout and stderr.
	"""
	@spec ssh(String.t, String.t, integer, String.t) :: {String.t, integer}
	def ssh(user, ip, ssh_port, command) do
		System.cmd("ssh", ["-q", "-p", "#{ssh_port}", "#{user}@#{ip}", command])
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
			               err: {:file, Process.group_leader})
		exit_code
	end

	@doc """
	Adds a machine from the database.
	"""
	@spec add(String.t, String.t, integer, [String.t]) :: nil
	def add(hostname, ip, ssh_port, tags) do
		{:ok, _} = Repo.transaction(fn ->
			Repo.insert_all("machines", [[
				hostname: hostname,
				ip:       ip_to_inet(ip),
				ssh_port: ssh_port,
			]])
			tag(hostname, tags)
		end)
	end

	@doc """
	Removes a machine from the database.
	"""
	@spec rm(String.t) :: nil
	def rm(hostname) do
		{:ok, _} = Repo.transaction(fn ->
			from("machine_tags")             |> where([t], t.hostname == ^hostname) |> Repo.delete_all
			from("machine_pending_upgrades") |> where([u], u.hostname == ^hostname) |> Repo.delete_all
			machine(hostname) |> Repo.delete_all
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
		nil
	end

	@doc """
	Remove tags in enumerable `remove_tags` from machine with hostname `hostname`.
	"""
	@spec untag(String.t, [String.t]) :: nil
	def untag(hostname, remove_tags) do
		from("machine_tags")
		|> where([t], t.hostname == ^hostname)
		|> where([t], t.tag in ^remove_tags)
		|> Repo.delete_all
		nil
	end

	@spec set_ip(String.t, String.t) :: nil
	def set_ip(hostname, ip) do
		from("machines")
		|> where([m], m.hostname == ^hostname)
		|> Repo.update_all(set: [ip: ip_to_inet(ip)])
		nil
	end

	@spec set_ssh_port(String.t, integer) :: nil
	def set_ssh_port(hostname, ssh_port) do
		from("machines")
		|> where([m], m.hostname == ^hostname)
		|> Repo.update_all(set: [ssh_port: ssh_port])
		nil
	end

	def write_script_for_machine(hostname, output_file) do
		tags  = get_tags_for_machine(hostname)
		roles = ScriptWriter.roles_for_tags(tags)
		ScriptWriter.write_script_for_roles(roles, output_file)
	end

	@spec get_tags_for_machine(String.t) :: [String.t]
	def get_tags_for_machine(hostname) do
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

	defp all_machines() do
		from("machines")
	end

	defp machine(hostname) do
		all_machines()
		|> where([hostname: ^hostname])
	end

	defp one_row(rows) do
		case rows do
			[row] -> row
			_     -> raise TooManyRowsError, message: "Expected just one row, got #{rows |> length} rows"
		end
	end

	defp ip_to_inet(ip) do
		%Postgrex.INET{address: ip_to_tuple(ip)}
	end

	defp ip_to_tuple(ip) do
		ip
		|> String.split(".")
		|> Enum.map(&String.to_integer/1)
		|> List.to_tuple
	end

	def inet_to_ip(%Postgrex.INET{address: {a, b, c, d}}) do
		"#{a}.#{b}.#{c}.#{d}"
	end
end

defmodule MachineManager.CLI do
	alias MachineManager.{Core, CPU}

	def main(argv) do
		spec = Optimus.new!(
			name:               "machine_manager",
			description:        "Machine Manager",
			about:              "Manages metadata about machines and probes them",
			allow_unknown_args: false,
			parse_double_dash:  true,
			subcommands: [
				ls: [
					name:  "ls",
					about: "List all machines",
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
				],
				configure: [
					name:  "configure",
					about: "Configure a machine",
					args: [
						hostname: [required: true],
					],
				],
				upgrade: [
					name:  "upgrade",
					about: "Upgrade all packages in our 'pending upgrades' list for a machine",
					args: [
						hostname: [required: true],
					],
				],
				reboot: [
					name:  "reboot",
					about: "Shut down and reboot a machine",
					args: [
						hostname: [required: true],
					],
				],
				shutdown: [
					name:  "shutdown",
					about: "Shut down and power-off a machine",
					args: [
						hostname: [required: true],
					],
				],
				probe: [
					name:  "probe",
					about: "Probe machines",
					args: [
						hostnames: [required: true, help: "Comma-separated list of hostnames"],
					],
				],
				add: [
					name:  "add",
					about: "Add a machine",
					args: [
						hostname: [required: true],
					],
					options: [
						ip:       [short: "-i", long: "--ip",       required: true],
						ssh_port: [short: "-p", long: "--ssh-port", required: true,  parser: :integer],
						tag:      [short: "-t", long: "--tag",      required: false, multiple: true],
					],
				],
				rm: [
					name:  "rm",
					about: "Remove a machine",
					args: [
						hostname: [required: true],
					],
				],
				tag: [
					name:  "tag",
					about: "Add tags to a machine",
					args: [
						hostname: [required: true],
						tag:      [required: false, help: "Tags to add", value_name: "TAG..."],
					],
					allow_unknown_args: true,
				],
				untag: [
					name:  "untag",
					about: "Remove tag from a machine",
					args: [
						hostname: [required: true],
						tag:      [required: false, help: "Tags to remove", value_name: "TAG..."],
					],
					allow_unknown_args: true,
				],
				set_ip: [
					name:  "set-ip",
					about: "Set new IP for a machine",
					args: [
						hostname: [required: true],
						ip:       [required: true],
					],
				],
				set_ssh_port: [
					name:  "set-ssh-port",
					about: "Set new SSH port for a machine",
					args: [
						hostname: [required: true],
						ssh_port: [required: true, parser: :integer],
					],
				],
			],
		)
		{[subcommand], %{args: args, options: options, unknown: unknown}} = Optimus.parse!(spec, argv)
		case subcommand do
			:ls           -> list()
			:script       -> Core.write_script_for_machine(args.hostname, args.output_file)
			:configure    -> Core.configure(args.hostname)
			:ssh_config   -> Core.ssh_config()
			:probe        -> Core.probe(args.hostnames |> String.split(","))
			:upgrade      -> Core.upgrade(args.hostname)
			:reboot       -> Core.reboot(args.hostname)
			:shutdown     -> Core.shutdown(args.hostname)
			:add          -> Core.add(args.hostname, options.ip, options.ssh_port, options.tag)
			:rm           -> Core.rm(args.hostname)
			:tag          -> Core.tag(args.hostname,   all_arguments(args.tag, unknown))
			:untag        -> Core.untag(args.hostname, all_arguments(args.tag, unknown))
			:set_ip       -> Core.set_ip(args.hostname, args.ip)
			:set_ssh_port -> Core.set_ssh_port(args.hostname, args.ssh_port)
		end
	end

	# https://github.com/savonarola/optimus/issues/3
	defp all_arguments(maybe_first, rest) do
		case maybe_first do
			nil -> []
			_   -> [maybe_first | rest]
		end
	end

	def list() do
		rows          = Core.list()
		header        = ["HOSTNAME", "IP", "SSH", "TAGS", "国", "RAM", "CPU", "核", "糸", "PROBE TIME", "BOOT TIME", "KERNEL", "PENDING UPGRADES"]
                      |> Enum.map(&maybe_bolded/1)
		tag_frequency = make_tag_frequency(rows)
		table         = [header | Enum.map(rows, fn row -> sql_row_to_table_row(row, tag_frequency) end)]
		out           = TableFormatter.format(table, padding: 2, width_fn: &width_fn/1)
		:ok = IO.write(out)
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

	def sql_row_to_table_row(row, tag_frequency) do
		[
			row.hostname,
			Core.inet_to_ip(maybe_scramble_ip(row.ip)),
			row.ssh_port,
			row.tags
				|> Enum.sort_by(fn tag -> -tag_frequency[tag] end)
				|> Enum.map(fn tag ->
						# Compute our own hash to avoid including the bold ANSI codes
						# in the computation.
						hash = :erlang.crc32(tag)
						tag |> bold_first_part_if_multiple_parts |> colorize(hash)
					end)
				|> Enum.join(" "),
			(if row.country != nil, do: row.country |> colorize),
			row.ram_mb,
			(if row.cpu_model_name   != nil, do: CPU.short_description(row.cpu_model_name)),
			row.core_count,
			row.thread_count,
			(if row.last_probe_time  != nil, do: pretty_datetime(row.last_probe_time) |> colorize_time),
			(if row.boot_time        != nil, do: pretty_datetime(row.boot_time)       |> colorize_time),
			(if row.kernel           != nil, do: row.kernel |> String.replace_prefix("Linux ", "🐧  ") |> colorize),
			(if row.pending_upgrades != nil, do: row.pending_upgrades |> Enum.join(" ")),
		]
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
		"#{date}#{with_fgcolor("T", {160, 160, 160})}#{time}"
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

	defp maybe_bolded(s) do
		case s =~ ~r/^\p{Han}+$/u do
			false -> bolded(s)
			true  -> s
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
