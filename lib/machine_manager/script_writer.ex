alias Gears.FileUtil

defmodule MachineManager.ScriptCompilationError do
	defexception [:message]
end

defmodule MachineManager.ScriptWriter do
	alias MachineManager.ScriptCompilationError

	# We want to make a script for each combination of roles, not tags,
	# to avoid compiling a script for each tag combination.
	@spec write_script_for_roles([String.t], String.t) :: nil
	def write_script_for_roles(roles, output_filename) do
		dependencies = [{:converge,    ">= 0.1.0"},
		                {:base_system, ">= 0.1.0"}] ++ \
		               (roles |> Enum.map(fn role -> {"role_#{role}" |> String.to_atom, ">= 0.0.0"} end))
		role_modules = roles |> Enum.map(&module_for_role/1)
		temp_dir     = FileUtil.temp_dir("multi_role_script")
		app_name     = "multi_role_script"
		module       = MultiRoleScript
		lib          = Path.join([temp_dir, "lib", "#{app_name}.ex"])
		Mixmaker.create_project(temp_dir, app_name, module,
		                        dependencies, [main_module: module])
		File.write!(lib,
			"""
			defmodule #{inspect module} do
				def main(tags) do
					BaseSystem.Configure.configure_with_roles(tags, #{inspect role_modules})
				end
			end
			""")
		{_, 0} = System.cmd("mix", ["deps.get"], cd: temp_dir)
		case System.cmd("mix", ["compile", "--warnings-as-errors"], cd: temp_dir, env: [{"MIX_ENV", "prod"}], stderr_to_stdout: true) do
			{out, 0} ->
				# Even with --warnings-as-errors, warnings in dependencies don't
				# result in a non-0 exit from `mix compile`.  Parse the output and
				# fail the build if there were any warnings.
				if out |> String.contains?("warning:") do
					raise ScriptCompilationError, message: "mix compile had a warning:\n\n#{out}"
				end
			{out, _code} ->
				raise ScriptCompilationError, message: "mix compile failed:\n\n#{out}"
		end
		{_, 0} = System.cmd("mix", ["escript.build"], cd: temp_dir, env: [{"MIX_ENV", "prod"}])
		File.cp!(Path.join(temp_dir, app_name), output_filename)
		nil
	end

	@doc """
	Extract a list of roles from a list of tags.
	"""
	@spec roles_for_tags([String.t]) :: [String.t]
	def roles_for_tags(tags) do
		tags
		|> Enum.filter(fn tag -> tag |> String.starts_with?("role:") end)
		|> Enum.map(fn tag -> tag |> String.replace_prefix("role:", "") end)
	end

	@doc """
	For a given role, return the module that contains the `role()` function.
	"""
	@spec module_for_role(String.t) :: module
	def module_for_role(role) do
		role
		|> String.split("_")
		|> Enum.map(&String.capitalize/1)
		|> Enum.join
		|> (fn s -> "Elixir.Role#{s}" end).()
		|> String.to_atom
	end
end