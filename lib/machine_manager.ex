alias Gears.TableFormatter

defmodule MachineManager do
	import Ecto.Query, only: [from: 2]

	def transfer(_machine, _file) do
		# rsync to /root/.cache/machine_manager/#{basename file}
	end

	def run_script(machine, script) do
		transfer(machine, script)
		# ssh and run
	end

	def list() do
		rows = MachineManager.Repo.all(
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
		header = ["HOSTNAME", "IP", "SSH PORT", "TAGS", "LAST PROBED", "BOOT TIME", "COUNTRY", "PENDING UPGRADES", "RAM", "CORES"]
					|> Enum.map(&bolded/1)
		table  = [header | Enum.map(rows, &sql_row_to_table_row/1)]
		out    = TableFormatter.format(table, padding: 2, width_fn: &(&1 |> strip_ansi |> String.length))
		IO.write(out)
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
			inet_to_ip(row.ip),
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

	def probe() do
		
	end

	def add(hostname, ip, ssh_port, tags) do
		MachineManager.Repo.insert_all("machines", [
			[hostname: hostname, ip: ip_to_inet(ip), ssh_port: ssh_port, tags: tags]
		])
	end

	def rm(hostname) do
		MachineManager.Repo.delete_all(from m in "machines", where: m.hostname == ^hostname)
	end

	defp maybe_inspect(value) when is_binary(value), do: value
	defp maybe_inspect(value),                       do: inspect(value)

	defp ip_to_inet(ip) do
		%Postgrex.INET{address: ip_to_tuple(ip)}
	end

	defp ip_to_tuple(ip) do
		ip
		|> String.split(".")
		|> Enum.map(&String.to_integer/1)
		|> List.to_tuple
	end

	defp inet_to_ip(%Postgrex.INET{address: {a, b, c, d}}) do
		"#{a}.#{b}.#{c}.#{d}"
	end
end

defmodule MachineManager.CLI do
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
					about: "Probe all machines",
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
					options: [
						hostname: [short: "-h", long: "--hostname", required: true],
					],
				],
			],
		)
		{[subcommand], %{options: options}} = Optimus.parse!(spec, argv)
		case subcommand do
			:ls         -> MachineManager.list()
			:ssh_config -> MachineManager.ssh_config()
			:probe      -> MachineManager.probe()
			:add        -> MachineManager.add(options.hostname, options.ip, options.ssh_port, options.tag)
			:rm         -> MachineManager.rm(options.hostname)
		end
	end
end
