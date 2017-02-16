alias MachineManager.ScriptWriter

defmodule MachineManagerTest do
	use ExUnit.Case

	test "basic functionality" do
		
	end
end

defmodule MachineManager.ScriptWriterTest do
	use ExUnit.Case

	test "roles_for_tags" do
		assert ScriptWriter.roles_for_tags([])                                        == []
		assert ScriptWriter.roles_for_tags(["unrelated"])                             == []
		assert ScriptWriter.roles_for_tags(["unrelated", "role:hello"])               == ["hello"]
		assert ScriptWriter.roles_for_tags(["unrelated", "role:hello", "role:world"]) == ["hello", "world"]
	end

	test "module_for_role" do
		assert ScriptWriter.module_for_role("hello")             == Hello
		assert ScriptWriter.module_for_role("hello_world")       == HelloWorld
		assert ScriptWriter.module_for_role("hello_world_again") == HelloWorldAgain
	end
end
