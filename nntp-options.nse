description = [[
Retrieves the available commands and banners from a listening NNTP daemon.

The Network News Transfer Protocol (NNTP) is an Internet application protocol used for transporting Usenet news articles (netnews) between news servers and for reading and posting articles by end user client applications.

For more information about NNTP, see:
http://tools.ietf.org/html/rfc3977
http://tools.ietf.org/html/rfc6048
http://en.wikipedia.org/wiki/Network_News_Transfer_Protocol
]]

---
-- @usage
-- nmap --script nntp-options --script-args nntp-options.timeout=10 -p <port> <host>
--
-- @args nntp-options.timeout
--		   Set the timeout in seconds. The default value is 10.
--
-- @output
-- PORT    STATE SERVICE REASON
-- 119/tcp open  nntp    syn-ack
-- | nntp-options:
-- |   Banners:
-- |     news.example.com - colobus 2.1 ready - (posting ok).
-- |     Colobus 2.1
-- |   Commands:
-- |     authinfo user Name|pass Password
-- |     article [MessageID|Number]
-- |     body [MessageID|Number]
-- |     check MessageID
-- |     group newsgroup
-- |     head [MessageID|Number]
-- |     list [active|active.times|newsgroups|subscriptions]
-- |     listgroup newsgroup
-- |     mode stream
-- |     mode reader
-- |     newgroups yymmdd hhmmss [GMT] [<distributions>]
-- |     newnews newsgroups yymmdd hhmmss [GMT] [<distributions>]
-- |     stat [MessageID|Number]
-- |     takethis MessageID
-- |     xgtitle [group_pattern]
-- |     xhdr header [range|MessageID]
-- |     xover [range]
-- |_    xpat header range|MessageID pat [morepat...]

--
-- @changelog
-- 2011-06-28 - v0.1 - created by Brendan Coles <bcoles@gmail.com>
--

author = "Brendan Coles"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery"}

require("stdnse")
require("comm")
require("shortport")

portrule = shortport.port_or_service (119, "nntp", {"tcp"})

action = function(host, port)

	local result = {}
	local banners = {}
	local commands = {}

	-- Set timeout
	local timeout = tonumber(nmap.registry.args[SCRIPT_NAME .. '.timeout'])
	if not timeout or timeout < 0 then timeout = 10 end

	-- Connect and retrieve banner and commands
	local command = "HELP\n"
	stdnse.print_debug(1, ("%s: Connecting to %s:%s [Timeout: %ss]"):format(SCRIPT_NAME, host.targetname or host.ip, port.number, timeout))
	local status, data = comm.exchange(host, port, command,{lines=100, proto=port.protocol, timeout=timeout*1000})
	if not status or not data then
		stdnse.print_debug(1, ("%s: Retrieving data from %s:%s failed [Timeout expired]"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
		return
	end

	-- Parse NNTP banners and commands
	stdnse.print_debug(1, ("%s: Parsing data from %s:%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
	for line in string.gmatch(data, "[^\r^\n]+") do
		if line ~= "" then
			local banner = string.match(line, "^20[01] (.+)$")
			if banner then table.insert(banners, string.format("%s", banner)) else
				local cmd = string.match(line, "^  ([a-z]+ .+)$")
				if cmd then table.insert(commands, string.format("%s", cmd)) end
			end
		end
	end

	-- Add banners to results table
	if next(banners) == nil then
		stdnse.print_debug(1, ("%s: No banners were returned by %s:%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
	else
		table.insert(result, "Banners:")
		table.insert(result, banners)
	end

	-- Add commands to results table
	if next(commands) == nil then
		stdnse.print_debug(1, ("%s: No commands were returned by %s:%s"):format(SCRIPT_NAME, host.targetname or host.ip, port.number))
	else
		table.insert(result, "Commands:")
		table.insert(result, commands)
	end

	-- Return results
	return stdnse.format_output(true, result)

end
