defmodule MachineManager.Repo.Migrations.CreateMachines do
	use Ecto.Migration

	def change do
		create table(:machines) do
			add :hostname,         :string
			add :ip,               :string
			add :ssh_port,         :string
			# lowercase two-letter country code
			add :country,          :string
			add :cloud,            :string
			add :pending_upgrades, {:array, :string}
			# state = :mess, :zygote, :converged, :needs_converge, :decommissioning
			add :state,            :string
			add :needs_reboot,     :boolean
		end
	end
end
