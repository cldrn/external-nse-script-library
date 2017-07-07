description = [[
Joins the bitcoin client channel that all default bitcoin clients are hardcoded to
and then decodes every nickname to its corresponding IP address.

Note that bitcoin clients with non-routable IPs or connected through proxies will
NOT encode their address in the nickname and instead use a
random nickname starting with an 'x'.

The script is based on the irc-info script.

See https://en.bitcoin.it/wiki/Network#IRC for more details.
]]

---
-- @usage
-- nmap -sL --script bitcoin-enum-targets --script-args=newtargets
-- @args bitcoin-enum-targets.server The IRC server to connect to
-- @args bitcoin-enum-targets.port The IRC server port to connect on
-- @args bitcoin-enum-targets.channel The IRC channel to join
-- @args newtargets If true, add discovered targets to the scan queue.
-- @output
-- Pre-scan script results:
-- | bitcoin-enum-targets: Found 1764 address(es). 
-- | x.x.x.x
-- | y.y.y.y
-- |_z.z.z.z

author = "Sebastian Dragomir"

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"

categories = {"discovery"}

require("bin")
require("stdnse")
require("nsedebug")
require("comm")
require("target")

prerule = function()
  return true
end

local init = function()
  -- Start of MOTD, we'll take the server name from here
  nmap.registry.ircserverinfo_375 = nmap.registry.ircserverinfo_375
    or pcre.new("^:([\\w-_.]+) 375", 0, "C")

  -- MOTD could be missing, we want to handle that scenario as well
  nmap.registry.ircserverinfo_422 = nmap.registry.ircserverinfo_422
    or pcre.new("^:([\\w-_.]+) 422", 0, "C")

  -- NICK already in use
  nmap.registry.ircserverinfo_433 = nmap.registry.ircserverinfo_433
    or pcre.new("^:[\\w-_.]+ 433", 0, "C")

  -- PING/PONG
  nmap.registry.ircserverinfo_ping = nmap.registry.ircserverinfo_ping
    or pcre.new("^PING :(.+)", 0, "C")

  nmap.registry.ircserverinfo_353 = nmap.registry.ircserverinfo_353
    or pcre.new("^:[\\w-_.]+ 353 \\w+ = #\\w+ :(.*)", 0, "C")

  nmap.registry.ircserverinfo_error = nmap.registry.ircserverinfo_error
    or pcre.new("^ERROR :(.*)", 0, "C")

end

local decode_ip = function(str)
  local base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  local a,b,c,d,sz
  local acc = 0
  local bitstr = ""

  for i = 1,#str do
    c = base58:find(str:sub(i,i)) - 1
    acc = acc*58 + c
  end
  
  while acc > 0 do
    bitstr = ("%d"):format(acc%2) .. bitstr
    acc = math.floor(acc/2)
  end
 
  sz = #bitstr % 8 
  if sz ~= 0 then
   sz = 24 + sz
  else
   sz = 32
  end

  local ip = bin.pack("B", string.rep("0", 32 - sz) .. bitstr:sub(1, sz))
  _, a, b, c, d = bin.unpack(">CCCC", ip)
  
  return ("%d.%d.%d.%d"):format(a,b,c,d)
end

action = function()
  local host = stdnse.get_script_args("bitcoin-enum-targets.server") or "irc.lfnet.org"
  local port = stdnse.get_script_args("bitcoin-enum-targets.port") or 6667
  local channel = stdnse.get_script_args("bitcoin-enum-targets.channel") or "#bitcoin"

  local unique_addresses = {}
  local all_addresses = {}

  local sd = nmap.new_socket()
  local curr_nick = random_nick()
  local nicks
  local s, e, t, a, off
  local buf, nick
  local banner_timeout = 60

  init()

  local sd, line = comm.tryssl(host, port, "USER nmap +iw nmap :Nmap Wuz Here\nNICK " .. curr_nick .. "\n")
  if not sd then return "Unable to open connection" end
  
  -- set a healthy banner timeout
  sd:set_timeout(banner_timeout * 1000)

  buf = stdnse.make_buffer(sd, "\r?\n")

  while true do
    if (not line) then break end

    -- This one lets us know we've connected, pre-PONGed, and got a NICK
    s, e, t = nmap.registry.ircserverinfo_375:exec(line, 0, 0)
    if (s) then
      sd:send("JOIN " .. channel .. "\nNAMES " .. channel .. "\nQUIT\n")
    end

    s, e, t = nmap.registry.ircserverinfo_422:exec(line, 0, 0)
    if (s) then
      sd:send("JOIN " .. channel .. "\nNAMES " .. channel .. "\nQUIT\n")
    end

    s, e, t = nmap.registry.ircserverinfo_433:exec(line, 0, 0)
    if (s) then
      curr_nick = random_nick()
      sd:send("NICK " .. curr_nick .. "\n")
    end

    s, e, t = nmap.registry.ircserverinfo_ping:exec(line, 0, 0)
    if (s) then
      sd:send("PONG :" .. string.sub(line, t[1], t[2]) .. "\n")
    end

    s, e, t = nmap.registry.ircserverinfo_353:exec(line, 0, 0)
    if (s) then
      nicks = string.sub(line, t[1], t[2])
      off = 1
      a = nicks:find(" ", off)
      while a do
        nick = nicks:sub(off, a - 1)
        if (nick:sub(1,1) == "u" and nick:len() == 15) then
          local ip = decode_ip(nick:sub(2))
          if not unique_addresses[ip] then
            unique_addresses[ip] = true
            table.insert(all_addresses, ip)
          end
        end
        off = a + 1
        a = nicks:find(" ", off)
      end

      nick = nicks:sub(off, nicks:len() - 1)
      if (nick:sub(1,1) == "u" and nick:len() == 15) then
        local ip = decode_ip(nick:sub(2))
        if not unique_addresses[ip] then
          unique_addresses[ip] = true
          table.insert(all_addresses, ip)
        end
      end
    end

    s, e, t = nmap.registry.ircserverinfo_error:exec(line, 0, 0)
    if (s) then
      return "ERROR: " .. string.sub(line, t[1], t[2]) .. "\n"
    end

    line = buf()
  end

  if target.ALLOW_NEW_TARGETS == true then
    for _,v in pairs(all_addresses) do
      target.add(v)
   end
    else
      stdnse.print_debug(1,"Not adding targets to newtargets. If you want to do that use the 'newtargets' script argument.")
  end

  if #all_addresses>0 then
    stdnse.print_debug(1,"Added %s address(es) to newtargets", #all_addresses)
  end

  return string.format("Found %s address(es). \n", #all_addresses) .. stdnse.strjoin("\n",all_addresses)
end

random_nick = function()
  local nick = ""

  -- NICKLEN is at least 9
  for i = 0, 8, 1 do
    nick = nick .. string.char(math.random(97, 122)) -- lowercase ascii
  end

  return nick
end
