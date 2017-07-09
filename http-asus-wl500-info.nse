description = [[
Attempts to retrieve the configuration settings from an Asus WL500 series 
wireless router. The information is retrieved from "/Settings.CFG" which is only 
available when authentication is disabled.

The web administration interface runs on port 80 by default.
]]

---
-- @usage
-- nmap --script http-asus-wl500-info -p <port> <host>
--
-- @output
-- PORT   STATE SERVICE   REASON
-- 80/tcp open  http    syn-ack
-- | http-asus-wl500-info:
-- |   Device Model: WL520gc
-- |   Hardware Version: WL520GC-01-07-02-00
-- |   Software Version: 4.131.31.0
-- |   Operating System: linux
-- |   IP Address: 192.168.1.1
-- |   LAN Gateway: 192.168.1.1
-- |   DHCP Enabled: 1
-- |   PPPoE Username: pppoe_username
-- |   PPPoE Password: pppoe_password
-- |   WAN DNS:  127.0.0.1
-- |   Wireless Primary SSID: wireless_ssid1
-- |   Wireless Secondary SSID: wireless_ssid2
-- |   Wireless Channel: 1
-- |   Wireless Preshared Key: wireless_password
-- |   HTTP Username: admin
-- |_  DDNS Enabled: 0
--
-- @changelog
-- 2012-01-24 - created by Brendan Coles - itsecuritysolutions.org
--

author = "Brendan Coles [itsecuritysolutions.org]"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery"}

require("url")
require("http")
require("stdnse")
require("shortport")

portrule = shortport.port_or_service (80, "http", {"tcp"})

action = function(host, port)

	local result = {}
	local path = "/Settings.CFG"
	local config_file = ""

	-- Retrieve file
	stdnse.print_debug(1, ("%s: Connecting to %s:%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
 	data = http.get(host, port, tostring(path))

	-- Check if file exists
 	if data and data.status and tostring(data.status):match("200") and data.body and data.body ~= "" then

		-- Check if the config file is valid
		stdnse.print_debug(1, "%s: HTTP %s: %s", SCRIPT_NAME, data.status, tostring(path))
		if string.match(data.body, "productid=") and string.match(data.body, "hardware_version=") and string.match(data.body, "s_version=") then
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
		{"Device Model", "productid"},
		{"Hardware Version","hardware_version"},
		{"Software Version","s_version"},
		{"Operating System","os_name"},

		-- LAN settings --
		{"IP Address","lan_ipaddr_t"},
		{"LAN Gateway","lan_gateway_t"},

		-- DHCP settings --
		{"DHCP Enabled","dhcp_enable_x"},
		--{"DHCP Range Start","dhcp_start"},
		--{"DHCP Range End","dhcp_end"},

		-- PPPoE settings --
		{"PPPoE Username","wan_pppoe_username"},
		{"PPPoE Password","wan_pppoe_passwd"},

		-- WAN settings --
		--{"WAN IP Address","wan_ipaddr_t"},
		{"WAN DNS","wan_dns_t"},

		-- Wireless settings --
		{"Wireless Primary SSID","wl_ssid"},
		{"Wireless Secondary SSID","wl_ssid2"},
		{"Wireless Channel","wl_radio_x"},
		{"Wireless Preshared Key","wl_wpa_psk"},
		--{"Wireless Encryption","wl_auth_mode"},

		-- username and password --
		{"HTTP Username","http_username"},
		{"HTTP Password","http_passwd"},

		-- DDNS settings --
		{"DDNS Enabled","ddns_enable_x"},
		{"DDNS Username","ddns_username_x"},
		{"DDNS Password","ddns_passwd_x"},

	}
	for _, var in ipairs(vars) do
		local var_match = string.match(config_file, string.format('%s=(%s)%s', var[2], "[^%c]+", "\0x00"))
		if var_match then table.insert(result, string.format("%s: %s", var[1], var_match)) end
	end

	-- Return results
	return stdnse.format_output(true, result)

end
