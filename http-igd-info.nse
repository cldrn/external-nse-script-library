description = [[
Attempts to retrieve device information from an Internet Gateway Device (IGD) 
UPnP configuration file.

For more information, see:
http://upnp.org/specs/gw/igd2
http://en.wikipedia.org/wiki/Internet_Gateway_Device_Protocol
]]

---
-- @usage
-- nmap --script http-igd-info -p <port> <host>
--
-- @output
-- PORT   STATE SERVICE   REASON
-- 80/tcp open  http    syn-ack
-- | http-igd-info: 
-- |   Friendly Name: Belkin Wireless Router
-- |   Manufacturer: Belkin Corporation
-- |   Model Description: Internet Gateway Device with UPnP support
-- |   Model Name: F5D7230-4
-- |   Model Number: 9.01.07
-- |_  Serial Number: BE700692012
--
-- @changelog
-- 2012-01-29 - v0.1 - created by Brendan Coles - itsecuritysolutions.org
--

author = "Brendan Coles [itsecuritysolutions.org]"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe","discovery"}

require("url")
require("http")
require("stdnse")
require("shortport")

portrule = shortport.port_or_service ({80,433}, {"http","https"}, {"tcp"})

action = function(host, port)

	local config_file = ""
	local result = {}
	local paths = {
		"/igd.xml",
		"/upnp/IGD.xml",
		"/IGatewayDeviceDescDoc",
		"/devicedesc.xml",
		"/gatedesc.xml",
		"/rootDesc.xml",
		"/allxml/",
		"/dslf/IGD.xml"
	}

	-- Loop through potential files
	stdnse.print_debug(1, ("%s: Connecting to %s:%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
	for _, path in ipairs(paths) do

		-- Retrieve file
  	data = http.get(host, port, tostring(path))
  	stdnse.print_debug(2, "%s: HTTP %s: %s", SCRIPT_NAME, data.status, tostring(path))
  	if data and data.status and tostring(data.status):match("200") and data.body and data.body ~= "" then

			-- Check if the HTTP response contains a valid IGD config file
			if string.match(data.body, '<?xml version=\"1\.0\"') and string.match(data.body, '<root xmlns=\"urn\:schemas.upnp.org\:device.1.0\">') then
				config_file = data.body
				break
			else
				stdnse.print_debug(2, "%s: Invalid config file: %s", SCRIPT_NAME, tostring(path))
			end

		end

	end

	-- No config file found
	if config_file == "" then
  	stdnse.print_debug(1, ("%s: Could not locate IGD info on %s:%s."):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
		return
	end

	-- Extract configuration info
	stdnse.print_debug(1, "%s: Extracting info from IGD configuration file.", SCRIPT_NAME)

	-- Extract system info
	local vars = {
		--{"Device Type", "deviceType"},
		{"Friendly Name","friendlyName"},
		{"Manufacturer","manufacturer"},
		--{"Manufacturer URL","manufacturerURL"},
		{"Model Description","modelDescription"},
		{"Model Name","modelName"},
		{"Model Number","modelNumber"},
		--{"Model URL","modelURL"},
		{"Serial Number","serialNumber"},
		{"Server Type","serverType"},
		--{"Presentation URL","presentationURL"},
		--{"UDN","UDN"},
		--{"UPC","UPC"},
	}
	for _, var in ipairs(vars) do
		local var_match = string.match(config_file, string.format("<%s>([^<]+)<\/%s>", var[2], var[2]))
		if var_match then table.insert(result, string.format("%s: %s", var[1], var_match)) end
	end

	-- Return results
	return stdnse.format_output(true, result)

end
