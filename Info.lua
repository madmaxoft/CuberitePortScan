-- Info.lua

-- Provides the metadata about the plugin, as well as command registrations





g_PluginInfo =
{
	Description =
	[[
		Scans a specified IP address / hostname for open ports in a specified range.

		Up to 200 simultaneous connections are used, if the port range is larger, the rest of the connections
		form a queue that is satisfied as the current connections either succeed or fail.
	]],

	ConsoleCommands =
	{
		portscan =
		{
			Handler = handleConsoleCmdPortScan,
			HelpString = "Scans a range of ports over TCP",
			ParameterCombinations =
			{
				{
					Params = "host beginport endport",
					Help = "Starts a TCP port scan of the specified port range on the specified host",
				},
				{
					Params = "stop",
					Help = "Stops all portscans",
				},
			},
		}
	}
}
