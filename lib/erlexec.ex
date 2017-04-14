defmodule MachineManager.ErlExecUtil do
	def ret_to_tuple(ret) do
		case ret do
			{:ok,    []}                                    -> {"",                         0}
			{:ok,    [stdout: out]}                         -> {out |> IO.iodata_to_binary, 0}
			{:ok,    [exit_status: exit_code]}              -> {"",                         exit_code}
			{:error, [exit_status: exit_code]}              -> {"",                         exit_code}
			{:error, [exit_status: exit_code, stdout: out]} -> {out |> IO.iodata_to_binary, exit_code}
		end
	end
end
