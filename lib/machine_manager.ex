alias Gears.{TableFormatter, StringUtil}

defmodule MachineManager.TooManyRowsError do
	defexception [:message]
end

defmodule MachineManager.Core do
	alias MachineManager.Repo
	import Ecto.Query

	def transfer(_machine, _file) do
		# rsync to /root/.cache/machine_manager/#{basename file}
	end

	def run_script(machine, script) do
		transfer(machine, script)
		# ssh and run
	end

	def list() do
		cols = [
			:hostname, :ip, :ssh_port, :tags, :last_probe_time, :boot_time, :country,
			:ram_mb, :core_count, :thread_count, :kernel, :pending_upgrades
		]
		all_machines()
		|> order_by(asc: :hostname)
		|> select(^cols)
		|> Repo.all
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
		machine(hostname)
		|> Repo.update_all(set: [
			ram_mb:           data.ram_mb,
			cpu_model_name:   data.cpu_model_name,
			core_count:       data.core_count,
			thread_count:     data.thread_count,
			country:          data.country,
			kernel:           data.kernel,
			boot_time:        data.boot_time_ms |> DateTime.from_unix!(:millisecond),
			pending_upgrades: data.pending_upgrades,
			last_probe_time:  DateTime.utc_now(),
		])
	end

	def _atoms() do
		# Make sure these atoms are in the atom table
		[:ram_mb, :cpu_model_name, :core_count, :thread_count, :country, :kernel, :boot_time_ms, :pending_upgrades]
	end

	def probe_one(hostname) do
		row =
			machine(hostname)
			|> select([:ip, :ssh_port])
			|> Repo.all
			|> one_row
		# machine_probe expects that we already ran an `apt-get update` when
		# it determines which packages can be upgraded.
		command = """
		apt-get update > /dev/null 2>&1;
		apt-get install -y --upgrade machine_probe > /dev/null 2>&1;
		machine_probe
		"""
		{output, 0} = ssh(inet_to_ip(row.ip), row.ssh_port, command)
		Poison.decode!(output, keys: :atoms!)
	end

	@doc """
	Runs `command` on machine at `ip` and `ssh_port`, returns `{output, exit_code}`.
	Output includes both stdout and stderr.
	"""
	def ssh(ip, ssh_port, command) do
		System.cmd("ssh", ["-q", "-p", "#{ssh_port}", "root@#{ip}", command])
	end

	def add(hostname, ip, ssh_port, tags) do
		Repo.insert_all("machines", [[
			hostname: hostname,
			ip:       ip_to_inet(ip),
			ssh_port: ssh_port,
			tags:     tags
		]])
	end

	def rm(hostname) do
		machine(hostname)
		|> Repo.delete_all
	end

	@doc """
	Add tags in MapSet `new_tags` to machine with hostname `hostname`.
	"""
	def tag(hostname, new_tags) do
		update_tags(hostname, fn existing_tags ->
			MapSet.union(existing_tags, new_tags)
		end)
	end

	@doc """
	Remove tags in MapSet `remove_tags` from machine with hostname `hostname`.
	"""
	def untag(hostname, remove_tags) do
		update_tags(hostname, fn existing_tags ->
			MapSet.difference(existing_tags, remove_tags)
		end)
	end

	defp update_tags(hostname, fun) do
		Repo.transaction(fn ->
			rows =
				machine(hostname)
				|> select([m], m.tags)
				|> Repo.all
			if rows |> length > 0 do
				existing_tags = one_row(rows) |> MapSet.new
				updated_tags  = fun.(existing_tags)
				machine(hostname)
				|> Repo.update_all(set: [tags: updated_tags |> Enum.sort])
			end
		end)
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
			_     -> raise MachineManager.TooManyRowsError,
			           message: "Expected just one row, got #{rows |> length} rows"
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
	alias MachineManager.Core

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
					options: [
						hostname: [short: "-h", long: "--hostname", required: true],
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
						tags:     [required: true, help: "Comma-separated list of tags to add"],
					],
				],
				untag: [
					name:  "untag",
					about: "Remove tag from a machine",
					args: [
						hostname: [required: true],
						tags:     [required: true, help: "Comma-separated list of tags to remove"],
					],
				],
			],
		)
		{[subcommand], %{args: args, options: options}} = Optimus.parse!(spec, argv)
		case subcommand do
			:ls         -> list()
			:ssh_config -> Core.ssh_config()
			:probe      -> Core.probe(args.hostnames |> String.split(","))
			:add        -> Core.add(options.hostname, options.ip, options.ssh_port, options.tag)
			:rm         -> Core.rm(args.hostname)
			:tag        -> Core.tag(args.hostname,   args.tags |> String.split(",") |> MapSet.new)
			:untag      -> Core.untag(args.hostname, args.tags |> String.split(",") |> MapSet.new)
		end
	end

	def list() do
		rows   = Core.list()
		header = ["HOSTNAME", "IP", "SSH", "TAGS", "国", "RAM", "核", "糸", "PROBE TIME", "BOOT TIME", "KERNEL", "PENDING UPGRADES"]
					|> Enum.map(&maybe_bolded/1)
		table  = [header | Enum.map(rows, &sql_row_to_table_row/1)]
		out    = TableFormatter.format(table, padding: 2, width_fn: fn s ->
		           s
		           |> StringUtil.strip_ansi
		           |> StringUtil.half_width_length
	            end)
		:ok = IO.write(out)
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

	def sql_row_to_table_row(row) do
		[
			row.hostname,
			Core.inet_to_ip(maybe_scramble_ip(row.ip)),
			row.ssh_port,
			row.tags |> Enum.join(" "),
			row.country,
			row.ram_mb,
			row.core_count,
			row.thread_count,
			pretty_datetime(row.last_probe_time),
			pretty_datetime(row.boot_time),
			if row.kernel != nil do
				row.kernel |> String.replace_prefix("Linux ", "🐧  ")
			end,
			if row.pending_upgrades != nil do
				row.pending_upgrades |> Enum.join(" ")
			end,
		]
		|> Enum.map(fn value ->
			case value do
				value when is_binary(value) -> value
				nil                         -> "?"
				_                           -> inspect(value)
			end
		end)
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
		if erlang_date != nil do
			erlang_date
			|> erlang_date_to_datetime
			|> DateTime.to_iso8601
			|> String.split(".")
			|> hd
		end
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
