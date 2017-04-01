defmodule MachineManager.WireGuard do
	@doc """
	Generate a new 32-byte private key for wireguard.
	"""
	def make_wireguard_privkey() do
		{privkey_base64, 0} = System.cmd("wg", ["genkey"])
		privkey = privkey_base64
			|> String.trim_trailing("\n")
			|> Base.decode64!
		if byte_size(privkey) != 32 do
			raise RuntimeError, message: "Private key from `wg genkey` was of the wrong size"
		end
		privkey
	end

	@doc """
	Get the 32-byte public key associated with wireguard private key `privkey`.
	"""
	def get_wireguard_pubkey(privkey) when byte_size(privkey) == 32 do
		# `wg pubkey` waits for EOF, but Erlang can't close stdin, so use some
		# bash that reads a single line and pipes it into `wg pubkey`.
		# https://github.com/alco/porcelain/issues/37
		%Porcelain.Result{status: 0, out: pubkey_base64} =
			Porcelain.exec("bash", ["-c", "head -n 1 | wg pubkey"], in: (privkey |> Base.encode64) <> "\n")
		pubkey = pubkey_base64
			|> String.trim_trailing("\n")
			|> Base.decode64!
		if byte_size(pubkey) != 32 do
			raise RuntimeError, message: "Public key from `wg pubkey` was of the wrong size"
		end
		if pubkey == privkey do
			raise RuntimeError, message: "Public key from `wg pubkey` was equal to the private key"
		end
		pubkey
	end
end
