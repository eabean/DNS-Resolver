# DNS-Resolver

A simple domain name server resolver client. This client takes a domain name as input 
and returns its IPV4 or IPV6 address.

## Project Setup

1. Clone the repo.
2. In the root directory, run the command `make`.
3. Run the program with the command `java -jar DNSLookupService.jar <rootDNS>` where `rootDNS` is the DNS server to start the search at. For example `java -jar DNSLookupService.jar 199.7.83.42`.


## Available Commands

| Command | Description |
| --- | --- |
| `server <SERVERNAME>` | Changes the starting DNS server. |
| `trace on | off` | Toggles verbose tracing. |
| `lookup <HOSTNAME> [type]` | Looks up the provided hostname and allows you to specify the record type. For example, `lookup google.ca AAAA` |
| `dump` | Prints all currently cached host names and records.|
