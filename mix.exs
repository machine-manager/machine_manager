defmodule Machines.Mixfile do
	use Mix.Project

	def project do
		[
			app: :machines,
			version: "0.1.0",
			elixir: "~> 1.5-dev",
			build_embedded: Mix.env == :prod,
			start_permanent: Mix.env == :prod,
			deps: deps()
		]
	end

	def application do
		[extra_applications: [:logger]]
	end

	defp deps do
		[]
	end
end
