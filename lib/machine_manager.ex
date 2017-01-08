defmodule MachineManager do
	import Ecto.Query, only: [from: 2]

	def transfer(_machine, _file) do
		# rsync to /root/.cache/machine_manager/#{basename file}
	end

	def run_script(machine, script) do
		transfer(machine, script)
		# ssh and run
	end

	def add(hostname, ip, ssh_port, tags) do
		MachineManager.Repo.insert_all("machines", [
			[hostname: hostname, ip: ip_to_inet(ip), ssh_port: ssh_port, tags: tags]
		])
	end

	def list() do
		out = MachineManager.Repo.all(
			from m in "machines",
			select: %{hostname: m.hostname, ip: m.ip, ssh_port: m.ssh_port, tags: m.tags}
		)
		IO.inspect(out)
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
				add: [
					name:  "add",
					about: "Add a machine",
					options: [
						hostname: [short: "-h", long: "--hostname", required: true],
						ip:       [short: "-i", long: "--ip",       required: true],
						ssh_port: [short: "-p", long: "--ssh-port", required: true,  parser: :integer],
						tag:      [short: "-t", long: "--tag",      required: false, multiple: true],
					]
				],
				list: [
					name:  "list",
					about: "List all machines",
				],
				probe: [
					name:  "probe",
					about: "Probe all machines",
				]
			]
		)
		{[subcommand], %{options: options}} = Optimus.parse!(spec, argv)
		case subcommand do
			:add  -> MachineManager.add(options.hostname, options.ip, options.ssh_port, options.tag)
			:list -> MachineManager.list()
		end
	end
end
