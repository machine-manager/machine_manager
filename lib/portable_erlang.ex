defmodule MachineManager.PortableErlang do
	@doc """
	Create a portable Erlang installation at `dest` (must be an already-existing empty directory)
	"""
	def make_portable_erlang(dest) do
		{:ok, []} = File.ls(dest)
		# TODO: exclude things not needed to run converge scripts
		{"", 0} = System.cmd("rsync", ["-a", "--", "/usr/lib/erlang/", dest], stderr_to_stdout: true)
		erl_file = Path.join(dest, "bin/erl")
		# Make bin/erl work when installed to any location
		erl_content =
			File.read!(erl_file)
			|> String.replace(
					~s[ROOTDIR=/usr/lib/erlang\n],
					~s[ROOTDIR=$(dirname -- "$(dirname -- "$(readlink -f -- "$0")")")\n]
				)
		File.write!(erl_file, erl_content)
	end
end
