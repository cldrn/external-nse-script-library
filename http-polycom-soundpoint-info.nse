description = [[
Attempts to retrieve the configuration settings from a Polycom SoundPoint VoIP 
phone. The information is retrieved from "/reg_1.htm" and "/reg_2.htm" which is 
only available when authentication is disabled.

The web administration interface runs on port 80 by default.
]]

---
-- @usage
-- nmap --script http-polycom-soundpoint-info -p <port> <host>
--
-- @output
-- PORT   STATE SERVICE   REASON
-- 80/tcp open  http    syn-ack
-- | http-polycom-soundpoint-info: 
-- |   [Line #1]
-- |   Username: 21009
-- |   Display Name: John Doe
-- |   Address: 21009
-- |   Server #1: sip.example.com
-- |   Server #2: sip2.example.com
-- |   [Line #2]
-- |   Server #1: sip.example.com
-- |_  Server #2: sip2.example.com
--
-- @changelog
-- 2011-09-22 - created by Brendan Coles - itsecuritysolutions.org
--

author = "Brendan Coles [itsecuritysolutions.org]"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery"}

require("url")
require("http")
require("stdnse")
require("shortport")

portrule = shortport.port_or_service (80, "VoIP phone", {"tcp"})

action = function(host, port)

	local result = {}
	local paths = {"/reg_1.htm","/reg_2.htm"}
	local config_file = ""

	-- Retrieve file
	stdnse.print_debug(1, ("%s: Connecting to %s:%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
	for line, path in ipairs(paths) do

		-- Check if file exists
	 	data = http.get(host, port, tostring(path))
	 	if data and data.status and tostring(data.status):match("200") and data.body and data.body ~= "" then
	
			-- Check if the config file is valid
			stdnse.print_debug(1, "%s: HTTP %s: %s", SCRIPT_NAME, data.status, tostring(path))
			if string.match(data.body, "<title>SoundPoint IP Configuration Utility") and string.match(data.body, '<div align="center" class="bN">SoundPoint IP Configuration</div>') then
				config_file = data.body
			else
				stdnse.print_debug(1, ("%s: %s:%s uses an invalid config file."):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
				return
			end
	
		else
			stdnse.print_debug(1, "%s: Failed to retrieve file: %s", SCRIPT_NAME, tostring(path))
			return
		end

		-- Extract system info from config file
		stdnse.print_debug(1, "%s: Extracting line #%s info from %s", SCRIPT_NAME, line, path)
		table.insert(result, string.format("[Line #%s]", line))
		local vars = {
	
			-- System settings --
			{"Display Name","reg."..line..".displayName"},
			{"Label","reg."..line..".label"},
			{"Address","reg."..line..".address"},
	
			-- Server 1 settings
			{"Server #1","reg."..line..".server.1.address"},
			{"Server #1 Port","reg."..line..".server.1.port"},
	
			-- Server 2 settings
			{"Server #2","reg."..line..".server.2.address"},
			{"Server #2 Port","reg."..line..".server.2.port"},
	
		}

		-- username and password
		local var_match = string.match(config_file, string.format('<td width="200" bgcolor="#999999"><input value="([^"]+)" name="%s"\/><\/td>', "reg."..line..".auth.userId"))
		if var_match then table.insert(result, string.format("Username: %s", var_match)) end
		local var_match = string.match(config_file, string.format('<td width="200" bgcolor="#999999"><input value="([^"]+)" type="password" name="%s"\/><\/td>', "reg."..line..".auth.password"))
		if var_match then table.insert(result, string.format("Password: %s", var_match)) end

		for _, var in ipairs(vars) do
			local var_match = string.match(config_file, string.format('<td width="200" bgcolor="#999999"><input value="([^"]+)" name="%s"\/><\/td>', var[2]))
			if var_match then table.insert(result, string.format("%s: %s", var[1], var_match)) end
		end

	end

	-- Return results
	return stdnse.format_output(true, result)

end
