defmodule MachineManager.Mixfile do
	use Mix.Project

	def project do
		[
			app: :machine_manager,
			version: "0.1.0",
			elixir: "~> 1.4",
			build_embedded: Mix.env == :prod,
			start_permanent: Mix.env == :prod,
			escript: [main_module: MachineManager.CLI],
			deps: deps(),
		]
	end

	def application do
		[
			extra_applications: [:logger],
			mod: {MachineManager.Application, []}
		]
	end

	defp deps do
		[
			{:gears,    ">= 0.10.0"},
			{:mixmaker, ">= 0.1.0"},
			{:ecto,     ">= 2.1"},
			{:postgrex, ">= 0.13.0"},
			{:optimus,  ">= 0.1.0"},
			{:poison,   ">= 3.1.0"},
			{:bunt,     ">= 0.2.0"},
		]
	end
end
