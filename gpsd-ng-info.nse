description = [[
Retrieves device and version information from a listening GPSD-NG daemon.

gpsd is a service daemon that monitors one or more GPSes or AIS receivers attached to a host computer through serial or USB ports, making all data on the location/course/velocity of the sensors available to be queried on TCP port 2947 of the host computer.

For more information about GPSD-NG, see:
http://gpsd.berlios.de/gpsd.html
http://en.wikipedia.org/wiki/Gpsd
http://gpsd.berlios.de/protocol-evolution.html
]]

---
-- @usage
-- nmap --script gpsd-ng-info --script-args gpsd-ng-info.timeout=5 -p <port> <host>
--
-- @args gpsd-ng-info.timeout
--		   Set timeout in seconds. The default value is 5.
--
-- @output
-- PORT   STATE SERVICE   REASON
-- 2947/tcp open  gpsd-ng syn-ack
-- | gpsd-ng-info: 
-- |     VERSION:
-- |     	rev = 2011-04-15T13:37:50.73
-- |     	release = 3.0~dev
-- |     	proto_major = 3
-- |     	proto_minor = 4
-- |     DEVICES:
-- |         DEVICE:
-- |         	parity = N
-- |         	path = /dev/ttyS0
-- |         	subtype = GSW3.2.4_3.1.00.12-SDK003P1.00a 
-- |         	stopbits = 1
-- |         	flags = 1
-- |         	driver = SiRF binary
-- |         	bps = 38400
-- |         	native = 1
-- |         	activated = 2011-05-15T11:11:34.450Z
-- |         	cycle = 1
-- |         DEVICE:
-- |         	parity = N
-- |         	path = /dev/cuaU0
-- |         	stopbits = 1
-- |         	flags = 1
-- |         	driver = uBlox UBX binary
-- |         	bps = 9600
-- |         	mincycle = 0.25
-- |         	native = 1
-- |         	activated = 2011-05-15T01:19:34.200Z
-- |_        	cycle = 1
--
-- @changelog
-- 2011-06-18 - v0.1 - created by Brendan Coles - itsecuritysolutions.org
--

author = "Brendan Coles [itsecuritysolutions.org]"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

require("stdnse")
require("comm")
require("shortport")
require("json")

portrule = shortport.port_or_service (2947, "gpsd-ng", {"tcp"})

--- parse GPSD-NG data in table format
-- This function parses replies to GPSD-NG commands:
-- "?VERSION;" and "?DEVICES;" -- TODO: "?POLL;"
-- @param data a table containg JSON data
-- @return a table containing GPSD-NG in NSE output format
local function parseGPSDNG(data)

	local result = {}

	-- use class nodes as table keys
	if data["class"] then table.insert(result,("%s:"):format(tostring(data["class"]))) end

	-- extract node properties
	for k,v in pairs(data) do
		if type(v) ~= 'table' and k ~= "class" then
			table.insert(result,(("\t%s = %s"):format(tostring(k), tostring(v))))
		end
	end

	-- parse child node of type table
	for k,v in pairs(data) do
		if type(v) == 'table' then table.insert(result,parseGPSDNG(v)) end
	end

	return result

end

action = function(host, port)

	local result = {}
	local timeout = tonumber(nmap.registry.args[SCRIPT_NAME .. '.timeout'])
	if not timeout or timeout < 0 then timeout = 5 end

	-- Connect and retrieve "?DEVICES;" data
	local command = "?DEVICES;"
	stdnse.print_debug(1, ("%s: Connecting to %s:%s [Timeout: %ss]"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, timeout))
	local status, json_data = comm.exchange(host, port, command,{lines=3, proto=port.protocol, timeout=timeout*1000})
	if not status or not json_data then
		stdnse.print_debug(1, ("%s: Retrieving data from %s:%s failed [Timeout expired]"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
		return
	end

	-- Convert received JSON data to table
	stdnse.print_debug(1, ("%s: Parsing JSON data from %s:%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
	for line in string.gmatch(json_data, "[^\n]+") do
		local status, data = json.parse(line)
		if not status or not data or not data["class"] then
			stdnse.print_debug(1, ("%s: Failed to parse data from %s:%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
			return
		end
		table.insert(result, parseGPSDNG(data))
	end

	-- Return results
	return stdnse.format_output(true, result)

end
