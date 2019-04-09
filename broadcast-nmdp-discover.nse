local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local packet = require "packet"
local target = require "target"
local os = require "os"
local table = require "table"

description = [[
Discovers MikroTik devices on a LAN by sending a MikroTik Neighbor Discovery Protocol (NMDP) network broadcast probe.

For more information about MNDP, see:
* https://mikrotik.com/testdocs/ros/2.9/ip/mndp.php
* https://wiki.mikrotik.com/wiki/Manual:IP/Neighbor_discovery
* https://www.wireshark.org/docs/dfref/m/mndp.html
* https://hadler.me/cc/mikrotik-neighbor-discovery-mndp/
]]

---
-- @usage nmap --script broadcast-nmdp-discover
-- @usage nmap --script broadcast-nmdp-discover --script-args timeout=5s -e eth0
--
-- @output
-- Pre-scan script results:
-- | broadcast-nmdp-discover:
-- |   MAC Address: 00:0c:29:6d:a7:63, IP Address: 0.0.0.0; Identity: MikroTik; Version: 6.42.12 (long-term); Platform: MikroTik; Software ID: GXCE-KYGV; Uptime: 1h14m; Board: x86; Unpacking: None; Interface: ether1
-- |   MAC Address: 00:0c:29:6d:a7:63, IP Address: fe80::20c:29ff:fe6d:a763; Identity: MikroTik; Version: 6.42.12 (long-term); Platform: MikroTik; Software ID: GXCE-KYGV; Uptime: 1h14m; Board: x86; Unpacking: None; Interface: ether1
-- |   MAC Address: 00:0c:29:8b:de:c6, IP Address: 10.1.1.123; Identity: MikroTik; Version: 6.10; Platform: MikroTik; Software ID: 33UY-8JI2; Uptime: 0h42m; Board: x86; Unpacking: None; Interface: ether1
-- |_  MAC Address: 00:0c:29:8b:de:c6, IP Address: fe80::20c:29ff:fe8b:dec6; Identity: MikroTik; Version: 6.10; Platform: MikroTik; Software ID: 33UY-8JI2; Uptime: 0h42m; Board: x86; Unpacking: None; Interface: ether1
--
-- @args broadcast-nmdp-discover.address
--       address to which the probe packet is sent. (default: 255.255.255.255)
-- @args broadcast-nmdp-discover.timeout
--       socket timeout (default: 5s)
---

author = "Brendan Coles"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "broadcast", "safe"}

prerule = function() return ( nmap.address_family() == "inet") end

local arg_address = stdnse.get_script_args(SCRIPT_NAME .. ".address")
local arg_timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout"))

-- Listens for NMDP response messages.
--@param interface Network interface to listen on.
--@param timeout Time to listen for a response.
--@param responses table to insert response data into.
local nmdpListen = function(interface, timeout, responses)
  local condvar = nmap.condvar(responses)
  local start = nmap.clock_ms()
  local listener = nmap.new_socket()
  local status, l3data
  local filter = 'udp src port 5678 and udp dst port 5678 and src host not ' .. interface.address
  listener:set_timeout(500)
  listener:pcap_open(interface.device, 1024, true, filter)

  while (nmap.clock_ms() - start) < timeout do
    status, _, _, l3data = listener:pcap_receive()

    if not status then
      goto continue
    end

    local p = packet.Packet:new(l3data, #l3data)
    local data = l3data:sub(p.udp_offset + 9)

    if #data < 4 then
      goto continue
    end

    stdnse.print_debug(1, "Received NMDP response from %s (%s bytes)", p.ip_src, string.len(data))

    local tlv_type, tlv_len, tlv_value, pos
    pos = 1
    --local header = data:sub(pos, pos + 1)
    pos = pos + 2
    --local seqno = data:sub(pos, pos + 1)
    pos = pos + 2

    local mac_address, identity, version, platform, uptime, software_id, board, unpacking, interface
    while (pos < #data) do
      -- TLV Type - Unsigned integer (2 bytes)
      tlv_type = string.unpack(">I2", data:sub(pos, pos + 1))
      pos = pos + 2

      -- TLV Length - Unsigned integer (2 bytes)
      tlv_len  = string.unpack(">I2", data:sub(pos, pos + 1))
      pos = pos + 2

      -- TLV Value
      tlv_value = data:sub(pos, pos + tlv_len - 1)
      pos = pos + tlv_len

      --stdnse.print_debug(2, "TLV Type: %s", tlv_type)
      --stdnse.print_debug(2, "TLV Length: %s", tlv_len)
      --stdnse.print_debug(2, "TLV Value: %s", stdnse.tohex(tlv_value))

      -- MAC address
      if tlv_type == 0x01 then
        mac_address = stdnse.format_mac(tlv_value)

      -- Identity
      elseif tlv_type == 0x05 then
        identity = tlv_value

      -- Version
      elseif tlv_type == 0x07 then
        version = tlv_value

      -- Platform
      elseif tlv_type == 0x08 then
        platform = tlv_value

      -- Uptime - unsigned integer (big endian)
      elseif tlv_type == 0x0a then
        uptime_num = string.unpack("<I", tlv_value)
        local h = math.floor(uptime_num / 3600)
        local m = math.floor((uptime_num - (h * 3600)) / 60)
        uptime = h .. "h" .. m .. "m"

      -- Software ID
      elseif tlv_type == 0x0b then
        software_id = tlv_value

      -- Board
      elseif tlv_type == 0x0c then
        board = tlv_value

      -- Unpacking - unsigned integer
      elseif tlv_type == 0x0e then
        if tlv_value:byte(1) == 0x01 then
          unpacking = "None"
        else
          unpacking = "Unknown"
        end

      -- Interface
      elseif tlv_type == 0x10 then
        interface = tlv_value

      -- Unknown
      else
        stdnse.print_debug(2, "Unknown TLV Type: %s", tlv_type)
      end
    end

    local str = ("MAC Address: %s, IP Address: %s; Identity: %s; Version: %s; Platform: %s; Software ID: %s; Uptime: %s; Board: %s; Unpacking: %s; Interface: %s"):format(
      mac_address, p.ip_src, identity, version, platform, software_id, uptime, board, unpacking, interface)

    table.insert(responses, str)

    ::continue::
  end

  condvar("signal")
end

-- Returns the network interface used to send packets to a target host.
--@param target host to which the interface is used.
--@return interface Network interface used for target host.
local getInterface = function(target)
  -- First, create dummy UDP connection to get interface
  local sock = nmap.new_socket()
  local status, err = sock:connect(target, "12345", "udp")
  if not status then
    stdnse.verbose1("%s", err)
    return
  end
  local status, address, _, _, _ = sock:get_info()
  if not status then
    stdnse.verbose1("%s", err)
    return
  end
  for _, interface in pairs(nmap.list_interfaces()) do
    if interface.address == address then
      return interface
    end
  end
end

action = function()
  local host = { ip = arg_address or "255.255.255.255" }

  -- Check if a valid interface was provided
  local interface = nmap.get_interface()
  if interface then
    interface = nmap.get_interface_info(interface)
  else
    interface = getInterface(host)
  end
  if not interface then
    return ("\n ERROR: Couldn't get interface for %s"):format(host)
  end

  -- Launch listener thread
  local results = {}
  local timeout = (tonumber(arg_timeout) or 5) * 1000
  stdnse.new_thread(nmdpListen, interface, timeout, results)
  stdnse.sleep(0.5)

  -- send two packets, just in case
  local port = { number = 5678, protocol = "udp" }
  local socket = nmap.new_socket("udp")
  socket:set_timeout(500)
  for i=1,2 do
    local status = socket:sendto(host, port, "\x00\x00\x00\x00")
    if ( not(status) ) then
      return stdnse.format_output(false, "Failed to send broadcast probe")
    end
  end

  -- Wait for listener thread to finish
  local condvar = nmap.condvar(results)
  condvar("wait")

  -- Create output table
  local output = stdnse.output_table()
  if #results > 0 then
    -- remove duplicates
    local hash = {}
    for _,v in ipairs(results) do
      if (not hash[v]) then
        table.insert( output, v )
        hash[v] = true
      end
    end
    return output
  end
end
