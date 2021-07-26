# qncpy

Quick network check using either http or tcp.            

## Requirements

- python 3.7 or above

### Use cases

- Quick sanity check that the internet has not disappeared. If I think my network or a chunk
of the internet has gone, I have a .conf file populated with a handful of sites that should b
e up e.g. my default gateway, google, my external DNS provider. Anything that would help quickly determine if there is an issue and perhaps indicate what that might be.
- Daily report. I use this for infrastructure that I know should be operational but not critical enough to get an alert on. 
  - I check server remote boards e.g. iDRACs, ilos etc to make sure these are still plugged in and available (you know they disappear from time to time… especially when you need them).
  - PBX, check all of the ports are operational and web-server running
  - Is my IP phone talking to the network
  - Has my printer gone offline 
  - Anything that would be really annoying to find out at the least opportune time that it is not there!

### Configuration

`qncpy.py` is the script. There is some simple error checking to make sure the `qncpy.conf` file makes sense e.g. DNS lookup, is the port number valid etc.
`qncpy.conf` is the configuration file that the script looks for in the same directory. The default file included shows some examples
There are 3 fields required separated by ::

   - Hostname or IP address
   - connection type either http or tcp
   - port(s) separated by , e.g. 80,8080

e.g.

```bash
1.1.1.1::tcp::53,80
https://cloudflare.com::http::443
https://google.com::http::443
```

### Output

The output is displayed on the console as well as writing out to a file called e.g. `qncpy_26.txt`, where 26 is the current day. It will overwrite an existing file of the same name. If used with a daily cron, this will give a rolling last month check. 



