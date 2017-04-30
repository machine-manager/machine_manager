defmodule MachineManager.WireGuard do
	@doc """
	Generate a new private key for WireGuard.
	"""
	@spec make_wireguard_privkey() :: String.t
	def make_wireguard_privkey() do
		{privkey, 0} = System.cmd("/usr/bin/wg", ["genkey"])
		privkey = privkey |> String.trim_trailing("\n")
		if byte_size(privkey) != 44 do
			raise(RuntimeError, "Private key from `wg genkey` was of the wrong size")
		end
		privkey
	end

	@doc """
	Get the public key associated with WireGuard private key `privkey`.
	"""
	@spec get_wireguard_pubkey(String.t) :: String.t
	def get_wireguard_pubkey(privkey) when byte_size(privkey) == 44 do
		# `wg pubkey` waits for EOF, but Erlang can't close stdin, so use erlexec.
		{:ok, pid, os_pid} =
			Exexec.run(["/usr/bin/wg", "pubkey"], stdin: true, stdout: true, monitor: true)
		Exexec.send(pid, privkey <> "\n")
		Exexec.send(pid, :eof)
		pubkey = receive do
			{:stdout, ^os_pid, stdout} -> stdout
		after
			5000 -> raise(RuntimeError, "No stdout from `wg pubkey` after 5 seconds")
		end
		|> String.trim_trailing("\n")
		receive do
			{:DOWN, ^os_pid, :process, ^pid, :normal}                   -> nil
			{:DOWN, ^os_pid, :process, ^pid, {:exit_status, exit_code}} ->
				raise(RuntimeError, "Got exit code #{exit_code} from `wg pubkey`")
		after
			5000 -> raise(RuntimeError, "`wg pubkey` did not exit after 5 seconds")
		end
		if byte_size(pubkey) != 44 do
			raise(RuntimeError, "Public key from `wg pubkey` was of the wrong size")
		end
		if pubkey == privkey do
			raise(RuntimeError, "Public key from `wg pubkey` was equal to the private key")
		end
		pubkey
	end

	@doc """
	Return a WireGuard config file as a string.
	"""
	@spec make_wireguard_config(String.t, String.t, integer, [map]) :: String.t
	def make_wireguard_config(private_key, address, listen_port, peers) do
		"""
		[Interface]
		PrivateKey = #{private_key}
		ListenPort = #{listen_port}
		Address    = #{address}

		""" <> (
		peers
		|> Enum.map(fn %{public_key: public_key, endpoint: endpoint, allowed_ips: allowed_ips, comment: comment} ->
				if comment =~ ~r/\n/ do
					raise "WireGuard comment cannot contain a newline: #{inspect comment}"
				end
				endpoint_line = case endpoint do
					nil -> ""
					_   -> "Endpoint   = #{endpoint}\n"
				end
				"""
				# #{comment}
				[Peer]
				PublicKey  = #{public_key}
				#{endpoint_line}\
				AllowedIPs = #{allowed_ips |> Enum.join(", ")}
				"""
		end)
		|> Enum.join("\n"))
	end
end
