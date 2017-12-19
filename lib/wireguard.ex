defmodule MachineManager.WireGuard do
	@doc """
	Generate a new private key for WireGuard.
	"""
	@spec make_wireguard_privkey() :: String.t
	def make_wireguard_privkey() do
		{privkey, 0} = System.cmd("/usr/bin/wg", ["genkey"])
		privkey = String.trim_trailing(privkey, "\n")
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
		# `wg pubkey` waits for EOF, but Erlang can't close stdin, so use some
		# bash that reads a single line and pipes it into `wg pubkey`.
		# https://github.com/alco/porcelain/issues/37
		%Porcelain.Result{status: 0, out: pubkey} =
			Porcelain.exec("bash", ["-c", "head -n 1 | wg pubkey"], in: privkey <> "\n")
		pubkey = String.trim_trailing(pubkey, "\n")
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
	@spec make_wireguard_config(String.t, [String.t], integer, [map]) :: String.t
	def make_wireguard_config(private_key, addresses, listen_port, peers) do
		peer_sections = Enum.map(peers, &peer_section/1)
		"""
		[Interface]
		PrivateKey = #{private_key}
		ListenPort = #{listen_port}
		Address    = #{Enum.join(addresses, ", ")}

		#{Enum.join(peer_sections, "\n")}\
		"""
	end

	defp peer_section(peer) do
		%{
			public_key:  public_key, 
			endpoint:    endpoint,
			allowed_ips: allowed_ips,
			comment:     comment
		} = peer
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
		AllowedIPs = #{Enum.join(allowed_ips, ", ")}
		"""
	end
end
