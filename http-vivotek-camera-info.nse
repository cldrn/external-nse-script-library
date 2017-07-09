description = [[
Attempts to retrieve the configuration settings from a Vivotek network camera. 
The information is retrieved from "/cgi-bin/admin/getparamjs.cgi" which is not 
available on all models.

The web administration interface runs on port 80 by default.
]]

---
-- @usage
-- nmap --script http-vivotek-camera-info -p <port> <host>
--
-- @output
-- PORT   STATE SERVICE   REASON
-- 80/tcp open  http    syn-ack
-- | http-vivotek-camera-info: 
-- |   Device Model: PT7135
-- |   Version: PT7135-VVTK-0400a
-- |   Hostname: Network Camera with Pan/Tilt
-- |   IP Address: 192.168.1.100
-- |   Router: 192.168.1.254
-- |   Primary DNS: 192.168.1.254
-- |   Wireless SSID: example network
-- |   Wireless Channel: 6
-- |   Wireless Preshared Key: 00000000
-- |_  Username: root
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

portrule = shortport.port_or_service (80, "webcam", {"tcp"})

action = function(host, port)

	local result = {}
	local path = "/cgi-bin/admin/getparamjs.cgi"
	local config_file = ""

	-- Retrieve file
	stdnse.print_debug(1, ("%s: Connecting to %s:%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
 	data = http.get(host, port, tostring(path))

	-- Check if file exists
 	if data and data.status and tostring(data.status):match("200") and data.body and data.body ~= "" then

		-- Check if the config file is valid
		stdnse.print_debug(1, "%s: HTTP %s: %s", SCRIPT_NAME, data.status, tostring(path))
		if string.match(data.body, "system_modelname=") and string.match(data.body, "system_firmwareversion=") then
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
	stdnse.print_debug(1, "%s: Extracting system info from %s", SCRIPT_NAME, path)
	local vars = {

		-- System settings --
		{"Device Model", "system_modelname"},
		{"Version","system_firmwareversion"},
		{"Hostname","system_hostname"},
		--{"UPnP Enabled","upnp_enable"},

		-- Network settings --
		{"IP Address","network_ipaddress"},
		{"Router","network_router"},
		{"Primary DNS","network_dns1"},
		{"Secondary DNS","network_dns2"},
		--{"HTTP Port","network_httpport"},
		--{"RTSP Port","network_rtspport"},
		--{"Audio Port","network_audioport"},
		--{"Video Port","network_videoport"},

		-- PPPoE settings --
		{"PPPoE Username","network_pppoeuser"},
		{"PPPoE Password","network_pppoepass"},

		-- Wireless settings --
		{"Wireless SSID","wireless_ssid"},
		{"Wireless Channel","wireless_channel"},
		{"Wireless Preshared Key","wireless_presharedkey"},
		--{"Wireless Encryption","wireless_authmode"},

		-- username and password -- first user only --
		{"Username","security_username.0"},
		{"Password Key","security_userpass.0"},

		-- DDNS settings --
		{"DDNS Hostname","ddns_hostname"},
		{"DDNS Servername","ddns_servername"},
		{"DDNS Username","ddns_usernameemail"},
		{"DDNS Password","ddns_passwordkey"},

		-- SMTP settings -- first user only --
		{"SMTP Server","network_smtp1"},
		{"SMTP Username","network_mailuser1"},
		{"SMTP Password","network_mailpass1"},

		-- FTP settings -- first user only --
		{"FTP Server","network_ftp1"},
		{"FTP Username","network_ftpuser1"},
		{"FTP Password","network_ftppass1"},

		-- Syslog settings --
		--{"Syslog Enabled","syslog_enableremotelog"},
		--{"Syslog Server IP","syslog_serverip"},
		--{"Syslog Server Port","syslog_serverport"},

		-- Multicast settings --
		--{"Multicast IP Address","multicast_ipaddress"},
		--{"Multicast Video Port","multicast_videoport"},
		--{"Multicast Audio Port","multicast_audioport"},

	}
	for _, var in ipairs(vars) do
		local var_match = string.match(config_file, string.format('%s="([^"]+)"', var[2]))
		if var_match then table.insert(result, string.format("%s: %s", var[1], var_match)) end
	end

	-- Return results
	return stdnse.format_output(true, result)

end
