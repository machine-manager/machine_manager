defmodule MachineManager.CPU do
	@doc """
	Convert a CPU model name from /proc/cpuinfo into a shorter string.
	"""
	@spec short_description(String.t) :: String.t
	def short_description(cpu_model_name) do
		cpu_model_name
		|> String.replace_prefix("Intel Core Processor (Haswell, no TSX)", "Mystery Haswell")
		|> String.replace_prefix("Intel(R) Core(TM) ", "")
		|> String.replace_prefix("Intel(R) Xeon(R) ", "")
		|> String.replace_prefix("Intel(R) Atom(TM) ", "Atom ")
		|> String.replace(~r"(\b\d\.\d)\dGHz\b", "\\1GHz")
		|> String.replace(~r"\bCPU\b", "")
		|> String.replace(~r"\s+", " ")
		|> String.trim
	end
end
