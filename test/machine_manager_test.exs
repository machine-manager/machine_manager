alias Gears.FileUtil
alias MachineManager.{Core, CPU, ScriptWriter, WireGuard, Graph, PortableErlang}

defmodule MachineManager.CoreTest do
	use ExUnit.Case

	test "increment_ip_tuple" do
		assert Core.increment_ip_tuple({0, 0,   0,   0})   == {0, 0, 0,   1}
		assert Core.increment_ip_tuple({0, 0,   0,   1})   == {0, 0, 0,   2}
		assert Core.increment_ip_tuple({0, 0,   1,   255}) == {0, 0, 2,   0}
		assert Core.increment_ip_tuple({0, 0,   255, 0})   == {0, 0, 255, 1}
		assert Core.increment_ip_tuple({0, 2,   255, 255}) == {0, 3, 0,   0}
		assert Core.increment_ip_tuple({3, 255, 255, 255}) == {4, 0, 0,   0}
		assert_raise(
			FunctionClauseError,
			fn -> Core.increment_ip_tuple({255, 255, 255, 255}) end
		)
	end

	test "get_unused_wireguard_ip" do
		{_, _, _, _} = Core.get_unused_wireguard_ip()
	end

	test "increment_host_port" do
		assert_raise(RuntimeError, fn -> Core.increment_host_port(904) end)
		assert_raise(RuntimeError, fn -> Core.increment_host_port(1023) end)
		assert Core.increment_host_port(905) == 906
		assert Core.increment_host_port(987) == 988
		assert Core.increment_host_port(988) == 994
		assert Core.increment_host_port(994) == 996
	end

	@invalid_ipv4_addresses [
		{"a", "b", "c", "d"},
		{-1, 2, 3, 4},
		{1, -2, 3, 4},
		{1, 2, -3, 4},
		{1, 2, 3, -4},
		{1.5, 2, 3, 4},
		{1, 2.5, 3, 4},
		{1, 2, 3.5, 4},
		{1, 2, 3, 4.5},
		{1, 2, 3, "4e1"},
		{256, 2, 3, 4},
		{1, 256, 3, 4},
		{1, 2, 256, 4},
		{1, 2, 3, 256},
	]

	test "to_ip_tuple" do
		assert Core.to_ip_tuple("1.2.3.4")                                          == {1, 2, 3, 4}
		assert Core.to_ip_tuple(%Postgrex.INET{address: {0, 1, 2, 3}, netmask: 32}) == {0, 1, 2, 3}
		for {a, b, c, d} <- @invalid_ipv4_addresses do
			assert_raise(ArgumentError, fn -> Core.to_ip_tuple("#{a}.#{b}.#{c}.#{d}") end)
			assert_raise(ArgumentError, fn -> Core.to_ip_tuple(%Postgrex.INET{address: {a, b, c, d}}) end)
		end
	end

	test "to_ip_postgrex" do
		assert Core.to_ip_postgrex("1.2.3.4")    == %Postgrex.INET{address: {1, 2, 3, 4}, netmask: 32}
		assert Core.to_ip_postgrex({0, 1, 2, 3}) == %Postgrex.INET{address: {0, 1, 2, 3}, netmask: 32}
		for {a, b, c, d} <- @invalid_ipv4_addresses do
			assert_raise(ArgumentError, fn -> Core.to_ip_postgrex("#{a}.#{b}.#{c}.#{d}") end)
			assert_raise(ArgumentError, fn -> Core.to_ip_postgrex({a, b, c, d}) end)
		end
	end

	test "make_hosts_json_file" do
		self_row         = %{hostname: "me", public_ip: "1.1.1.1", wireguard_ip: "10.10.0.1"}
		graphs           = %{wireguard: %{}, public: %{}}
		subdomains       = %{wireguard: %{}, public: %{}}
		all_machines_map = %{"me" => self_row}
		assert Core.make_hosts_json_file(self_row, graphs, subdomains, all_machines_map) |> Jason.decode! == [
			["10.10.0.1", "me.wg"],
			[],
			["1.1.1.1",   "me.pi"],
		]
	end

	test "make_hosts_file with a public connection" do
		self_row         = %{hostname: "me",   public_ip: "1.1.1.1", wireguard_ip: "10.10.0.1"}
		peer_row         = %{hostname: "peer", public_ip: "1.1.1.2", wireguard_ip: "10.10.0.2"}
		graphs           = %{wireguard: %{}, public: %{"me" => ["peer"]}}
		subdomains       = %{wireguard: %{},                 public: %{}}
		all_machines_map = %{"me" => self_row, "peer" => peer_row}
		assert Core.make_hosts_json_file(self_row, graphs, subdomains, all_machines_map) |> Jason.decode! == [
			["10.10.0.1", "me.wg"],
			[],
			["1.1.1.1",   "me.pi"],
			["1.1.1.2",   "peer.pi"],
		]
	end

	test "make_hosts_file with a WireGuard connection" do
		self_row         = %{hostname: "me",   public_ip: "1.1.1.1", wireguard_ip: "10.10.0.1"}
		peer_row         = %{hostname: "peer", public_ip: "1.1.1.2", wireguard_ip: "10.10.0.2"}
		graphs           = %{wireguard: %{"me" => ["peer"]}, public: %{}}
		subdomains       = %{wireguard: %{},                 public: %{}}
		all_machines_map = %{"me" => self_row, "peer" => peer_row}
		assert Core.make_hosts_json_file(self_row, graphs, subdomains, all_machines_map) |> Jason.decode! == [
			["10.10.0.1", "me.wg"],
			["10.10.0.2", "peer.wg"],
			[],
			["1.1.1.1",   "me.pi"],
		]
	end

	test "make_hosts_file with subdomains" do
		self_row         = %{hostname: "me",   public_ip: "1.1.1.1", wireguard_ip: "10.10.0.1"}
		peer_row         = %{hostname: "peer", public_ip: "1.1.1.2", wireguard_ip: "10.10.0.2"}
		graphs           = %{wireguard: %{"me" => ["peer"]},         public: %{}}
		subdomains       = %{wireguard: %{"me" => ["chat", "mail"]}, public: %{"me" => ["public"]}}
		all_machines_map = %{"me" => self_row, "peer" => peer_row}
		assert Core.make_hosts_json_file(self_row, graphs, subdomains, all_machines_map) |> Jason.decode! == [
			["10.10.0.1", "me.wg"],
			["10.10.0.1", "chat.me.wg"],
			["10.10.0.1", "mail.me.wg"],
			["10.10.0.2", "peer.wg"],
			[],
			["1.1.1.1",   "me.pi"],
			["1.1.1.1",   "public.me.pi"],
		]
	end
end


defmodule MachineManager.WireGuardTest do
	use ExUnit.Case

	test "make_wireguard_privkey" do
		privkey = WireGuard.make_wireguard_privkey()
		assert byte_size(privkey) == 44
	end

	test "get_wireguard_pubkey" do
		privkey = WireGuard.make_wireguard_privkey()
		pubkey  = WireGuard.get_wireguard_pubkey(privkey)
		assert byte_size(pubkey) == 44
		assert pubkey != privkey
		assert pubkey == WireGuard.get_wireguard_pubkey(privkey)
	end

	test "make_wireguard_config" do
		private_key = String.duplicate("X", 44)
		addresses   = ["1.2.3.4"]
		listen_port = 51820
		peers       = []
		conf        = WireGuard.make_wireguard_config(private_key, addresses, listen_port, peers)
		assert conf ==
			"""
			[Interface]
			PrivateKey = #{private_key}
			ListenPort = #{listen_port}
			Address    = #{Enum.join(addresses, ", ")}

			"""
	end

	test "make_wireguard_config with peers" do
		private_key = String.duplicate("X", 44)
		addresses   = ["1.2.3.4", "1.2.4.0/24"]
		listen_port = 51820
		public_key  = String.duplicate("Y", 44)
		peers       = [
			%{public_key: public_key, endpoint: "5.6.7.8", allowed_ips: ["10.10.0.1"],              comment: "Comment"},
			%{public_key: public_key, endpoint: nil,       allowed_ips: ["10.10.0.2", "10.10.0.3"], comment: "Comment"},
		]
		conf        = WireGuard.make_wireguard_config(private_key, addresses, listen_port, peers)
		assert conf ==
			"""
			[Interface]
			PrivateKey = #{private_key}
			ListenPort = #{listen_port}
			Address    = #{Enum.join(addresses, ", ")}

			# Comment
			[Peer]
			PublicKey  = #{public_key}
			Endpoint   = 5.6.7.8
			AllowedIPs = 10.10.0.1

			# Comment
			[Peer]
			PublicKey  = #{public_key}
			AllowedIPs = 10.10.0.2, 10.10.0.3
			"""
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


defmodule MachineManager.PortableErlangTest do
	use ExUnit.Case

	test "make_portable_erlang" do
		temp = FileUtil.temp_dir("machine_manager_portable_erlang_test")
		PortableErlang.make_portable_erlang(temp, "amd64")
	end
end
