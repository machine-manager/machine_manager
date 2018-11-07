defmodule MachineManager.Mixfile do
	use Mix.Project

	def project do
		[
			app:             :machine_manager,
			version:         "0.1.0",
			elixir:          "~> 1.7",
			build_embedded:  Mix.env == :prod,
			start_permanent: Mix.env == :prod,
			escript:         [main_module: MachineManager.CLI],
			deps:            deps(),
		]
	end

	def application do
		[
			extra_applications: [:logger],
			mod:                {MachineManager.Application, []},
		]
	end

	defp deps do
		[
			{:gears,       ">= 0.10.0"},
			{:converge,    ">= 0.1.0"},
			{:mixmaker,    ">= 0.1.0"},
			{:porcelain,   ">= 2.0.3"},
			{:ecto,        ">= 3.0.0"},
			{:ecto_sql,    ">= 3.0.0"},
			{:postgrex,    ">= 0.14.0"},
			{:optimus,     ">= 0.1.0"},
			{:jason,       ">= 1.0.0"},
			{:decimal,     ">= 1.3.1"},
			{:chronocache, ">= 1.0.0"},
			{:dialyxir,    "~> 1.0.0-rc.3", only: [:dev], runtime: false},
		]
	end
end
