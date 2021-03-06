defmodule MachineManager.PortableErlang do
	@doc """
	Create a portable Erlang installation at `dest` (must be an already-existing empty directory)
	"""
	def make_portable_erlang(dest, arch) do
		unless arch =~ ~r/\A[a-z0-9]{3,10}\z/ do
			raise("Unexpected architecture: #{inspect arch}")
		end
		unpacked_base      = __DIR__ |> Path.dirname |> Path.dirname |> Path.join("portable_erlang") |> Path.join(arch)
		erlang_base        = "#{unpacked_base}/usr/lib/erlang"
		[erts]             = Path.wildcard("#{erlang_base}/erts-*")
		erlang_libs        = File.ls!("#{erlang_base}/lib")
		erlang_bins        = File.ls!("#{erlang_base}/bin")
		erlang_erts_bins   = File.ls!("#{erts}/bin")
		# We include compiler because 1) escript.build.ex's :application.ensure_all_started(:elixir)
		# will crash if it is not available (because compiler is listed in elixir.app.src)
		# 2) some users of converge may want to use the compiler for some reason
		unwanted_libs      = Enum.reject(erlang_libs,      fn n -> n =~ ~r/\A(kernel|stdlib|compiler)-/ end)
		unwanted_bins      = Enum.reject(erlang_bins,      fn n -> n =~ ~r/\A(erl|escript|start\.boot|no_dot_erlang\.boot)\z/ end)
		unwanted_erts_bins = Enum.reject(erlang_erts_bins, fn n -> n =~ ~r/\A(erlexec|erl_child_setup|inet_gethost|beam\.smp)\z/ end)
		excludes           =
			Enum.map(unwanted_libs,      fn n -> "/lib/#{n}" end) ++
			Enum.map(unwanted_bins,      fn n -> "/bin/#{n}" end) ++
			Enum.map(unwanted_erts_bins, fn n -> "/erts-*/bin/#{n}" end) ++
			[
				"/usr",
				"/include",
				"/releases",
				"/erts-*/lib",
				"/erts-*/include",
			]
		{:ok, []} = File.ls(dest)
		exclude_args = Enum.flat_map(excludes, fn path -> ["--exclude", path] end)
		{"", 0} = System.cmd("rsync", exclude_args ++ ["-a", "--", "#{erlang_base}/", dest], stderr_to_stdout: true)
		fix_bin_erl(Path.join(dest, "bin/erl"))
		nil
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
