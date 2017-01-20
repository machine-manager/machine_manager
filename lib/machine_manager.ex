alias Gears.TableFormatter

defmodule MachineManager.TooManyRowsError do
	defexception [:message]
end

defmodule MachineManager.Core do
	import Ecto.Query, only: [from: 2, select: 3]

	def transfer(_machine, _file) do
		# rsync to /root/.cache/machine_manager/#{basename file}
	end

	def run_script(machine, script) do
		transfer(machine, script)
		# ssh and run
	end

	def list() do
		MachineManager.Repo.all(
			from m in "machines",
			select: %{
				hostname:         m.hostname,
				ip:               m.ip,
				ssh_port:         m.ssh_port,
				tags:             m.tags,
				last_probe_time:  m.last_probe_time,
				boot_time:        m.boot_time,
				country:          m.country,
				pending_upgrades: m.pending_upgrades,
				ram_mb:           m.ram_mb,
				core_count:       m.core_count,
			}
		)
	end

	def ssh_config() do
		rows = MachineManager.Repo.all(
			from m in "machines",
			select: %{
				hostname: m.hostname,
				ip:       m.ip,
				ssh_port: m.ssh_port,
			}
		)
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

	def _atoms() do
		# Make sure these atoms are in the atom table
		[:ram_mb, :cpu_model_name, :core_count, :thread_count, :country, :kernel, :boot_time_ms, :pending_upgrades]
	end

	def probe_one(hostname) do
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

	def add(hostname, ip, ssh_port, tags) do
		MachineManager.Repo.insert_all("machines", [
			[hostname: hostname, ip: ip_to_inet(ip), ssh_port: ssh_port, tags: tags]
		])
	end

	def rm(hostname) do
		MachineManager.Repo.delete_all(machine(hostname))
	end

	@doc """
	Add tags in MapSet `new_tags` to machine with hostname `hostname`.
	"""
	def tag(hostname, new_tags) do
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
	def untag(hostname, remove_tags) do
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

	defp machine(hostname) do
		from m in "machines", where: m.hostname == ^hostname
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
		header = ["HOSTNAME", "IP", "SSH PORT", "TAGS", "LAST PROBED", "BOOT TIME", "COUNTRY", "PENDING UPGRADES", "RAM", "CORES"]
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
			row.tags |> Enum.join(", "),
			row.last_probe_time,
			row.boot_time,
			row.country,
			row.pending_upgrades,
			row.ram_mb,
			row.core_count
		] |> Enum.map(&maybe_inspect/1)
	end

	defp maybe_inspect(value) when is_binary(value), do: value
	defp maybe_inspect(value),                       do: inspect(value)
end
