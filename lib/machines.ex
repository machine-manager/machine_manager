defmodule Machines do
	def machines do
		[
			%{host: "lab",     roles: [], cloud: :virtualbox       },
			%{host: "sbuild",  roles: [], cloud: :virtualbox       },
			%{host: "torrent", roles: [], cloud: :virtualbox       },
			%{host: "sandlin", roles: [], cloud: :virtualbox       },
			%{host: "do2",     roles: [], cloud: :digitalocean     },
			%{host: "bhsvps1", roles: [], cloud: :ovh_vm           },
			%{host: "ksca2",   roles: [], cloud: :ovh_dedicated    },
			%{host: "paris2",  roles: [], cloud: :online_dedicated },
			%{host: "osaka1",  roles: [], cloud: :ablenet          },
			%{host: "scale4",  roles: [], cloud: :scaleway         },
			%{host: "scale5",  roles: [], cloud: :scaleway         },
			%{host: "scale6",  roles: [], cloud: :scaleway         },
		]
	end
end
