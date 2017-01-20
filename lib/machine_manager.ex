alias Gears.TableFormatter

defmodule MachineManager.TooManyRowsError do
	defexception [:message]
end

defmodule MachineManager.SQL do
	def cols(cols) do
		cols
		|> Enum.map(&to_string/1)
		|> Enum.join(", ")
	end

	def as_maps(%Postgrex.Result{columns: columns, rows: rows}) do
		# Let's just hope PostgreSQL isn't trying to overflow our atom table
		atom_columns = columns |> Enum.map(&String.to_atom/1)
		rows
		|> Enum.map(fn row ->
			Enum.zip(atom_columns, row) |> Map.new
		end)
	end
end

defmodule MachineManager.Core do
	alias MachineManager.SQL
	import Ecto.Query, only: [select: 3]

	def transfer(_machine, _file) do
		# rsync to /root/.cache/machine_manager/#{basename file}
	end

	def run_script(machine, script) do
		transfer(machine, script)
		# ssh and run
	end

	def list(db) do
		cols = [
			:hostname, :ip, :ssh_port, :tags, :last_probe_time, :boot_time,
			:country, :ram_mb, :core_count, :pending_upgrades
		]
		SQL.as_maps(Postgrex.query!(db, "SELECT #{SQL.cols(cols)} FROM machines ORDER BY hostname", []))
	end

	def ssh_config(db) do
		rows = SQL.as_maps(Postgrex.query!(db, "SELECT #{SQL.cols([:hostname, :ip, :ssh_port])} FROM machines ORDER BY hostname", []))
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

	def probe(db, hostnames) do
		task_map = hostnames |> Enum.map(fn hostname ->
			{hostname, Task.async(fn ->
				probe_one(db, hostname)
			end)}
		end) |> Map.new
		block_on_tasks(db, task_map)
	end

	defp block_on_tasks(db, task_map) do
		pid_to_hostname  = task_map |> Enum.map(fn {hostname, task} -> {task.pid, hostname} end) |> Map.new
		waiting_task_map = for {task, result} <- Task.yield_many(task_map |> Map.values, 2000) do
			hostname = pid_to_hostname[task.pid] || raise RuntimeError, message: "hostname == nil for #{inspect task}"
			case result do
				{:ok, probe_out} ->
					IO.puts("PROBED #{hostname}: #{inspect probe_out}")
					write_probe_data_to_db(db, hostname, probe_out)
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
			block_on_tasks(db, waiting_task_map)
		end
	end

	# DELETEME
	defp machine(x), do: x

	defp write_probe_data_to_db(db, hostname, data) do
		MachineManager.Repo.update_all(machine(hostname), [set: [
			ram_mb:           data.ram_mb,
			cpu_model_name:   data.cpu_model_name,
			core_count:       data.core_count,
			thread_count:     data.thread_count,
			country:          data.country,
			kernel:           data.kernel,
			boot_time:        data.boot_time_ms |> DateTime.from_unix!(:millisecond),
			pending_upgrades: data.pending_upgrades,
		]])
	end

	def _atoms() do
		# Make sure these atoms are in the atom table
		[:ram_mb, :cpu_model_name, :core_count, :thread_count, :country, :kernel, :boot_time_ms, :pending_upgrades]
	end

	def probe_one(db, hostname) do
		row = MachineManager.Repo.all(machine(hostname) |> select([m], %{ip: m.ip, ssh_port: m.ssh_port})) |> one_row
		# Note: we use an echo at the very end because of
		# https://github.com/elixir-lang/elixir/issues/5673
		command = """
		# machine_probe expects that we already ran an apt-get update when it
		# determines which packages can be upgraded.
		apt-get update > /dev/null 2>&1;
		apt-get install -y --upgrade machine_probe > /dev/null 2>&1;
		machine_probe && echo
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

	def add(db, hostname, ip, ssh_port, tags) do
		MachineManager.Repo.insert_all("machines", [
			[hostname: hostname, ip: ip_to_inet(ip), ssh_port: ssh_port, tags: tags]
		])
	end

	def rm(db, hostname) do
		MachineManager.Repo.delete_all(machine(hostname))
	end

	@doc """
	Add tags in MapSet `new_tags` to machine with hostname `hostname`.
	"""
	def tag(db, hostname, new_tags) do
		MachineManager.Repo.transaction(fn ->
			rows = MachineManager.Repo.all(machine(hostname) |> select([m], m.tags))
			if rows |> length > 0 do
				existing_tags = one_row(rows) |> MapSet.new
				updated_tags  = MapSet.union(existing_tags, new_tags)
				MachineManager.Repo.update_all(
					machine(hostname), [set: [tags: updated_tags |> MapSet.to_list]])
			end
		end)
	end

	@doc """
	Remove tags in MapSet `remove_tags` from machine with hostname `hostname`.
	"""
	def untag(db, hostname, remove_tags) do
		MachineManager.Repo.transaction(fn ->
			rows = MachineManager.Repo.all(machine(hostname) |> select([m], m.tags))
			if rows |> length > 0 do
				existing_tags = one_row(rows) |> MapSet.new
				updated_tags  = MapSet.difference(existing_tags, remove_tags)
				MachineManager.Repo.update_all(
					machine(hostname), [set: [tags: updated_tags |> MapSet.to_list]])
			end
		end)
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
		db = get_db()
		case subcommand do
			:ls         -> list(db)
			:ssh_config -> Core.ssh_config(db)
			:probe      -> Core.probe(db, args.hostnames |> String.split(","))
			:add        -> Core.add(db, options.hostname, options.ip, options.ssh_port, options.tag)
			:rm         -> Core.rm(db, args.hostname)
			:tag        -> Core.tag(db, args.hostname,   args.tags |> String.split(",") |> MapSet.new)
			:untag      -> Core.untag(db, args.hostname, args.tags |> String.split(",") |> MapSet.new)
		end
	end

	def get_db() do
		config = Application.get_env(:machine_manager, MachineManager.Repo)
		{:ok, db} = Postgrex.start_link(
			hostname: config[:hostname],
			username: config[:username],
			password: config[:password],
			database: config[:database],
		)
		db
	end

	def list(db) do
		rows   = Core.list(db)
		header = ["HOSTNAME", "IP", "SSH PORT", "TAGS", "LAST PROBED", "BOOT TIME", "COUNTRY", "RAM", "CORES", "PENDING UPGRADES"]
					|> Enum.map(&bolded/1)
		table  = [header | Enum.map(rows, &sql_row_to_table_row/1)]
		out    = TableFormatter.format(table, padding: 2, width_fn: &(&1 |> strip_ansi |> String.length))
		:ok = IO.write(out)
	end

	defp bolded(s) do
		"#{IO.ANSI.bright()}#{s}#{IO.ANSI.normal()}"
	end

	defp strip_ansi(s) do
		# Based on https://github.com/chalk/ansi-regex/blob/dce3806b159260354de1a77c1db543a967f7218f/index.js
		s |> String.replace(~r/[\x{001b}\x{009b}][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/, "")
	end

	def sql_row_to_table_row(row) do
		[
			row.hostname,
			Core.inet_to_ip(row.ip),
			row.ssh_port,
			row.tags |> Enum.join(" "),
			row.last_probe_time,
			if row.boot_time != nil do
				row.boot_time |> DateTime.to_iso8601
			end,
			row.country,
			row.ram_mb,
			row.core_count,
			if row.pending_upgrades != nil do
				row.pending_upgrades |> Enum.join(" ")
			end,
		] |> Enum.map(&maybe_inspect/1)
	end

	defp maybe_inspect(value) when is_binary(value), do: value
	defp maybe_inspect(value),                       do: inspect(value)
end
