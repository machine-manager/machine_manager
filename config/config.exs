use Mix.Config

config :porcelain, goon_warn_if_missing: false

config :machine_manager, MachineManager.Repo,
	database: "machine_manager",
	username: "machine_manager",
	password: "xphxLTUX1o4zuAVnHTYj1Q",
	hostname: "localhost",
	pool: DBConnection.ConnectionPool,
	pool_size: 3

config :machine_manager, ecto_repos: [MachineManager.Repo]

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{Mix.env}.exs"
