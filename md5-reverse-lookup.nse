local stdnse = require "stdnse"
local shortport = require "shortport"
local http = require "http"
local string = require "string"
local url = require "url"
local table = require "table"

description = [[
Checks a given hash against a reverse md5 database 
at http://md5.noisette.ch/ which is an agregate of
multiple reverse md5 databases.

 ]]

---
-- @usage
-- nmap --script=md5-reverse-lookup --script-args hashfile=hashes.txt
--
-- @args md5-reverse-lookup.hashfile File containing hashes to try. One hash per line.
-- @args md5-reverse-lookup.hash Single hash to try.
-- Pre-scan script results:
-- | md5-reverse-lookup:
-- |   0cc175b9c0f1b6a831c399e269772661:a
-- |   92eb5ffee6ae2fec3ad71c777531578f:b
-- |   4a8a08f09d37b73795649038408b5f33:c
-- |_  5f4dcc3b5aa765d61d8327deb882cf99:password 
 
author = "Aleksandar Nikolic"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"external", "safe"}

-- The script can be run either as a host- or pre-rule
hostrule = function() return true end
prerule = function() return true end

local arg_hash 		= stdnse.get_script_args(SCRIPT_NAME .. ".hash")
local arg_hashfile	= stdnse.get_script_args(SCRIPT_NAME .. ".hashfile")


local query_hash = function(hash)
	local host = "md5.noisette.ch"
	local data
	local reverse
	data = http.get( host, 80, "/md5.php?hash=" .. hash )
	stdnse.print_debug(data.body)
	if data and data.status and data.status == 200 then
		if string.find(data.body,"No value in MD5 database for this hash.") then
			stdnse.print_debug("No value in MD5 database for this hash: " .. hash)
			return nil
		end
		if string.find(data.body,"The string provided is not a true MD5 hash. Please try again.") then
			stdnse.print_debug("The string provided is not a true MD5 hash.")
			return nil
		end
		if string.find(data.body,"<string>") then
			reverse = string.match(data.body,"<string><!%[CDATA%[(.-)%]%]></string>")
			if reverse then 
				stdnse.print_debug(hash .. ":" .. reverse)
				return reverse
			end
		end
	end
	return nil
end
action = function(...)
	
	local reverse
	
	if arg_hash then
			-- query for a single hash
		reverse = query_hash(arg_hash)
		if(reverse) then
			return stdnse.format_output(true,arg_hash .. ":" .. reverse)
		end
	end
	if arg_hashfile then
				f = nmap.fetchfile(arg_hashfile)
		if ( not(f) ) then
			return ("\n  ERROR: Failed to find %s"):format(arg_hashfile)
		end

		f = io.open(f)
		if ( not(f) ) then
			return ("\n  ERROR: Failed to open %s"):format(arg_hashfile)
		end
			local results = {}
			for line in f:lines() do
				reverse = query_hash(line)
				if(reverse) then
					table.insert(results,line .. ":" .. reverse)
				end
			end
		if #results > 0 then
			return stdnse.format_output(true,results)
		end
	end

end
