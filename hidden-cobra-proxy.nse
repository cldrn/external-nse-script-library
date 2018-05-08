local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local bit = require "bit"

description = [[
Tests for the presence of the Hidde Cobra backdoor reported by the US-CERT 
on November 2017. This script attempts to identify the bidirectional proxy
component used by this APT by sending an innocuous TCP packet with certain
control code.

References:

* https://www.us-cert.gov/HIDDEN-COBRA-North-Korean-Malicious-Cyber-Activity
]]

---
-- @usage
-- nmap -n --script hidden-cobra-proxy --script-args='timeout=500' -p 443 <host>
--
-- @args timeout
--       Set the timeout in milliseconds. Default value: 500.
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- |_hidden-cobra-proxy: Hidden Cobra Proxy found!
--
-- Version 0.1
--
---

author = "Borja Merino"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "malware", "safe"}

portrule = shortport.portnumber(443, "tcp")

function get_code(signature)
  local const = "\x00\x12\x34\x84"
  local xor, alu = 0
  local code = ""

  for i = 4,1,-1
    do
        xor = bit.bxor(string.byte(const,i),string.byte(signature,-1))
	alu = string.unpack(">I",signature) + xor
	alu = alu % 1726 + 38361
	signature = string.pack(">I",alu)
	code = code..string.char(xor)
    end
    
  return code
end


action = function(host, port)
  local timeout = 500
  local status, recv

  local socket = nmap.new_socket()
  local timeout = stdnse.get_script_args("timeout")
  timeout = tonumber(timeout) or 500
  socket:set_timeout(timeout)
  status, result = socket:connect(host, port, "tcp")

  if not status then
    return nil
  end

  -- Send code to check the proxy installation
  local CODE = string.char(0x30, 0x30, 0x30, 0x30, 0xBE, 0xD9, 0x59, 0x6B, 0xA4, 0x7B)
  status = socket:send(CODE)
 
  -- Receive and analyze the answer 
  status, recv = socket:receive_bytes(1024)
  if #recv == 10 then
    stdnse.print_debug(1, "Data received from the peer: %s", stdnse.tohex(recv))
    local temp = string.sub(recv,0,4)
    local signature = string.reverse(temp)
    local code = get_code(signature)
    stdnse.print_debug(1, "Code obtained: %s", stdnse.tohex(code))
    if code == string.sub(recv,5,8) then 
	return ("Hidden Cobra Proxy found!")
    end
  end
  return nil
end
