alias MachineManager.{Core, CPU, ScriptWriter, WireGuard, Graph}

defmodule MachineManager.CoreTest do
	use ExUnit.Case

	test "increment_ip_tuple" do
		assert Core.increment_ip_tuple({0, 0,   0,   0})       == {0, 0, 0,   1}
		assert Core.increment_ip_tuple({0, 0,   0,   1})       == {0, 0, 0,   2}
		assert Core.increment_ip_tuple({0, 0,   1,   255})     == {0, 0, 2,   0}
		assert Core.increment_ip_tuple({0, 0,   255, 0})       == {0, 0, 255, 1}
		assert Core.increment_ip_tuple({0, 2,   255, 255})     == {0, 3, 0,   0}
		assert Core.increment_ip_tuple({3, 255, 255, 255})     == {4, 0, 0,   0}
		assert_raise(
			FunctionClauseError,
			fn -> Core.increment_ip_tuple({255, 255, 255, 255}) end
		)
	end

	test "get_unused_wireguard_ip" do
		{_, _, _, _} = Core.get_unused_wireguard_ip()
	end
end


defmodule MachineManager.WireGuardTest do
	use ExUnit.Case

	test "make_wireguard_privkey" do
		privkey = WireGuard.make_wireguard_privkey()
		assert privkey |> byte_size == 44
	end

	test "get_wireguard_pubkey" do
		privkey = WireGuard.make_wireguard_privkey()
		pubkey  = WireGuard.get_wireguard_pubkey(privkey)
		assert pubkey |> byte_size == 44
		assert pubkey != privkey
		assert pubkey == WireGuard.get_wireguard_pubkey(privkey)
	end
end


defmodule MachineManager.CPUTest do
	use ExUnit.Case

	test "short_description" do
		assert CPU.short_description("Intel(R) Core(TM) i7-4790K CPU @ 4.00GHz")   == "i7-4790K @ 4.0GHz"
		assert CPU.short_description("Intel(R) Core(TM) i7-2620M CPU @ 2.70GHz")   == "i7-2620M @ 2.7GHz"
		assert CPU.short_description("Intel(R) Core(TM) i3-2130 CPU @ 3.40GHz")    == "i3-2130 @ 3.4GHz"
		assert CPU.short_description("Intel(R) Xeon(R) CPU E3-1230 v3 @ 3.30GHz")  == "E3-1230 v3 @ 3.3GHz"
		assert CPU.short_description("Intel(R) Xeon(R) CPU E5-2650L v3 @ 1.80GHz") == "E5-2650L v3 @ 1.8GHz"
		assert CPU.short_description("Intel(R) Xeon(R) CPU E5-2640 v2 @ 2.00GHz")  == "E5-2640 v2 @ 2.0GHz"
		assert CPU.short_description("Intel(R) Atom(TM) CPU  C2750  @ 2.40GHz")    == "Atom C2750 @ 2.4GHz"
		assert CPU.short_description("Intel Core Processor (Haswell, no TSX)")     == "Mystery Haswell"
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
		assert ScriptWriter.module_for_role("hello")             == RoleHello
		assert ScriptWriter.module_for_role("hello_world")       == RoleHelloWorld
		assert ScriptWriter.module_for_role("hello_world_again") == RoleHelloWorldAgain
	end
end


defmodule MachineManager.GraphTest do
	use ExUnit.Case

	test "bidirectionalize" do
		assert Graph.bidirectionalize(%{}) == %{}
		assert Graph.bidirectionalize(%{"a" => ["b"]})               == %{"a" => MapSet.new(["b"]),      "b" => MapSet.new(["a"])}
		assert Graph.bidirectionalize(%{"a" => ["b"] |> MapSet.new}) == %{"a" => MapSet.new(["b"]),      "b" => MapSet.new(["a"])}
		assert Graph.bidirectionalize(%{"a" => ["b", "c"]})          == %{"a" => MapSet.new(["b", "c"]), "b" => MapSet.new(["a"]), "c" => MapSet.new(["a"])}
	end
end
