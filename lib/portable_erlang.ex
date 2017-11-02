defmodule MachineManager.PortableErlang do
	@doc """
	Create a portable Erlang installation at `dest` (must be an already-existing empty directory)
	"""
	def make_portable_erlang(dest) do
		erlang_base = "/usr/lib/erlang"
		{:ok, []} = File.ls(dest)
		erlang_libs   = File.ls!("#{erlang_base}/lib")
		unwanted_libs = Enum.reject(erlang_libs, fn lib -> lib =~ ~r/\A(kernel|stdlib|compiler)-/ end)
		excludes      = [
			"/erts-*/include",
			"/erts-*/lib",
			"/erts-*/bin/dialyzer",
			"/erts-*/bin/epmd",
			"/erts-*/bin/heart",
		] ++ Enum.map(unwanted_libs, fn lib -> "/lib/#{lib}" end)
		exclude_args = Enum.flat_map(excludes, fn path -> ["--exclude", path] end)
		{"", 0} = System.cmd("rsync", exclude_args ++ ["-a", "--", "#{erlang_base}/", dest], stderr_to_stdout: true)
		fix_bin_erl(Path.join(dest, "bin/erl"))
	end

	# Make bin/erl work when installed to any location
	defp fix_bin_erl(erl_file) do
		erl_content =
			File.read!(erl_file)
			|> String.replace(
					~s[ROOTDIR=/usr/lib/erlang\n],
					~s[ROOTDIR=$(dirname -- "$(dirname -- "$(readlink -f -- "$0")")")\n]
				)
		File.write!(erl_file, erl_content)
	end
end
