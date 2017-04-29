defmodule MachineManager.Graph do
	def bidirectionalize(graph) do
		graph
		|> normalize
		|> Enum.reduce(%{}, fn {a, b}, acc ->
			acc
			|> put_in([a], (acc[a] || MapSet.new) |> MapSet.put(b))
			|> put_in([b], (acc[b] || MapSet.new) |> MapSet.put(a))
		end)
	end

	# Convert {"a" => ["b", "c"]} to [{"a", "b"}, {"a", "c"}]
	def normalize(graph) do
		Enum.flat_map(graph, fn {a, bs} ->
			Enum.map(bs, fn b -> {a, b} end)
		end)
	end
end
