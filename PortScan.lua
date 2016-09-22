-- PortScan.lua

-- Implements the entire plugin





--- Maximum simultaneously running network requests
local MAX_REQUESTS = 200





--- Active network connection requests
-- Array-table of request info
-- Includes the "n" member tracking the number of items to facilitate fast insertion-at-end
-- Contains a maximum of MAX_REQUESTS items
local g_NetRequests =
{
	n = 0
}





--- Queue of portscan requests
-- The request at [1] is the currently running one
-- Each item is a table: { host = <host>, rangeBegin = <beginPortNr>, rangeEnd = <endPortNr>, reportFn = <function>, finishFn = <function> }
--   reportFn is a function that is called for each open port found, a single number param specifies the port number
--   finishFn is a function that is called once the scan is complete, receives the request table as its param
-- The current scan also has a "nextPort" member specifying the next port to attempt connection to, once g_NetRequests has a free slot
-- A request that has at least one connection active will have numConnRequestsMade member specifying the number of network connections attempted
local g_ScanRequests = {}





--- Returns the next hostname, port and the entire request to scan, based on g_ScanRequests
-- Updates g_ScanRequests for the next call
-- If there is no request, returns nothing
local function getNextScanPair()
	-- If no more requests, return nothing:
	if not(g_ScanRequests[1]) then
		return
	end

	-- Process the request:
	local req = g_ScanRequests[1]
	local host = req.host
	local port = req.nextPort or req.rangeBegin
	if (port < req.rangeEnd) then
		req.nextPort = port + 1
	else
		-- The request has just been been depleted by this call, remove it from the queue:
		table.remove(g_ScanRequests, 1)
	end
	return host, port, req
end





--- Removes the specified network request from g_NetRequests
-- Checks if this was the last connection request for the scan, if so, reports it
-- Starts more connection requests if there are any left in the scan queue
function removeNetRequest(a_Host, a_Port, a_ScanRequest)
	for idx, conn in ipairs(g_NetRequests) do
		if (
			(conn.host == a_Host) and
			(conn.port == a_Port) and
			(conn.req  == a_ScanRequest)
		) then
			-- This is the request, remove it:
			table.remove(g_NetRequests, idx)
			g_NetRequests.n = g_NetRequests.n - 1

			-- Check if this was the last conn request to make:
			a_ScanRequest.numConnRequestsMade = (a_ScanRequest.numConnRequestsMade or 0) + 1
			if (a_ScanRequest.numConnRequestsMade == a_ScanRequest.rangeEnd - a_ScanRequest.rangeBegin + 1) then
				a_ScanRequest.finishFn(a_ScanRequest)
			end

			-- Start new requests from the queue:
			startScanning()
			return
		end
	end
end





--- Starts scanning on as many ports as possible to fill g_NetRequests
function startScanning()
	while (g_NetRequests.n < MAX_REQUESTS) do
		local host, port, req = getNextScanPair()
		if not(host) then
			-- Depleted the request queue
			return
		end
		local callbacks =
		{
			OnConnected = function(a_TCPLink)
				-- Report an open port
				req.reportFn(port)
				a_TCPLink:Close()
				removeNetRequest(host, port, req)
			end,
			OnError = function()
				-- Closed port, don't report
				-- DEBUG: LOG(string.format("Port %d is closed", port))
				removeNetRequest(host, port, req)
			end,
		}
		local conn = cNetwork:Connect(host, port, callbacks)
		if (conn) then
			local n = g_NetRequests.n + 1
			g_NetRequests[n] =
			{
				host = host,
				port = port,
				conn = conn,
				req = req,
			}
			g_NetRequests.n = n
		else
			-- Immediate error when connecting, don't even add to NetRequests; check if last conn request:
			req.numConnRequestsMade = (req.numConnRequestsMade or 0) + 1
			if (req.numConnRequestsMade == req.rangeEnd - req.rangeBegin + 1) then
				req.finishFn(req)
			end
		end
	end
end





--- Handles the PortScan console command
function handleConsoleCmdPortScan(a_Split)
	-- "portscan stop" terminates all scans:
	if ((a_Split[2] == "stop") and not(a_Split[3])) then
		-- Clear the scan request queue:
		g_ScanRequests = {}
		return true, "Port scan has been stopped"
	end

	-- "portscan <host> <begin> <end>" queues the scan of the specified port range:
	local scanRequest =
	{
		host = a_Split[2],
		rangeBegin = tonumber(a_Split[3] or 1024) or 1024,
		rangeEnd   = tonumber(a_Split[4] or 32768) or 32768,
		reportFn = function (a_OpenPort)
			LOG(string.format("Port %d is open for connections", a_OpenPort))
		end,
		finishFn = function (a_Request)
			LOG(string.format("Portscan of %s range %d .. %d has finished.", a_Request.host, a_Request.rangeBegin, a_Request.rangeEnd))
		end,
	}
	table.insert(g_ScanRequests, scanRequest)
	startScanning()
	return true, "Port scan has been queued"
end





function Initialize(a_Plugin)
	-- Register commands:
	dofile(cPluginManager:GetPluginsPath() .. "/InfoReg.lua")
	RegisterPluginInfoCommands()
	RegisterPluginInfoConsoleCommands()

	return true
end
