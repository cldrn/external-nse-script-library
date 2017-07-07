description = [[
Attempts to retrieve all valid usernames from the HTTP component of Carel 
Pl@ntVisor (CarelDataServer.exe).
]]

---
-- @usage
-- nmap --script http-carel-data-server-users -p <port> <host>
--
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-carel-data-server-users: 
-- |   Administrator
-- |   Bob
-- |_  Carel
--
-- @changelog
-- 2012-02-02 - created by Brendan Coles - itsecuritysolutions.org
--

author = "Brendan Coles [itsecuritysolutions.org]"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

require("url")
require("http")
require("stdnse")
require("shortport")

portrule = shortport.port_or_service (80, "http", "tcp")

action = function(host, port)

	local result = {}
	local path = "/"
	local http_content = ""

	-- Retrieve file
	stdnse.print_debug(1, ("%s: Connecting to %s:%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
	data = http.get(host, port, path)

	-- Check if file exists
	if data and data.status and data.status == 200 and data.body and data.body ~= "" then

		-- Check if the config file is valid
		stdnse.print_debug(2, "%s: HTTP %s: %s", SCRIPT_NAME, data.status, path)
		if string.match(data.body, '<script type="text\/javascript" language="JavaScript" src="\/MPwebCoreFn\.js"><\/script>') then
			http_content = data.body
		else
			stdnse.print_debug(1, ("%s: %s:%s is not a Corel Print Server."):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
			return
		end

	else
		stdnse.print_debug(1, "%s: Failed to retrieve HTTP content: %s", SCRIPT_NAME, path)
		return
	end

	-- Extract usernames
	stdnse.print_debug(1, "%s: Extracting usernames", SCRIPT_NAME)
	for username in string.gmatch(http_content, "<option value=\"[^\"]+\">([^<]+)<\/option>") do
		table.insert(result, username)
	end

	-- Return results
	return stdnse.format_output(true, result)

end
