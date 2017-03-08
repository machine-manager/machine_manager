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
		{"", 0} = run_on_machine(hostname, "nohup sh -c 'sleep 2; systemctl reboot' > /dev/null 2>&1 < /dev/null &")
	end

	def shutdown(hostname) do
		{"", 0} = run_on_machine(hostname, "nohup sh -c 'sleep 2; systemctl poweroff' > /dev/null 2>&1 < /dev/null &")
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
		System.cmd("ssh", ["-q", "-p", "#{ssh_port}", "#{user}@#{ip}", command], stderr_to_stdout: true)
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
