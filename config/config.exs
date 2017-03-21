use Mix.Config

config :machine_manager, MachineManager.Repo,
	adapter: Ecto.Adapters.Postgres,
	database: "machine_manager",
	username: "machine_manager",
	password: "xphxLTUX1o4zuAVnHTYj1Q",
	hostname: "localhost",
	pool_size: 3

config :machine_manager, ecto_repos: [MachineManager.Repo]

config :logger,
	level: :warn,
	truncate: 4096
