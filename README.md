# dynlbd.py

simple DNS load balancer written in python.


## configuration

The program read its configuration from a YAML configuration file /etc/dynlbd.conf

the configuration structure is the following:

<pre>
option: value
FQDNpoolname:
   IPaddress:
      - module
</pre>

FQDNpoolname is a valid DNS FQDN which identifies a series of A records for that specific pool, for example:

login.mydomain.org has two A records in the DNS:

<pre>
login.mydomain.org has address 192.168.122.151
login.mydomain.org has address 192.168.122.150
</pre>

we define those in the configuration file:

<pre>
login.mydomain.org:
   192.168.122.150:
       - all
   192.168.122.151:
       - all
</pre>

the program will check for the hosts in the config file to be in a healthy status.
All the hosts are running Prometheus node_exporter and checks are made by inquiring the hosts node_Exporter directly.
If they aren't healthy, the specific IP address belonging to the unhealthy host will be removed by the DNS using a rfc2136 query.

The same host will be added later to the DNS record A pool whenever in healthy status

The available modules for health check are:

<pre>
- cpu 	// check for cpu usage
- mem   // check for memory usage
- load  // check for load averages
- all   // all of the above modules
- net   // check for network usage
</pre>

### cpu
if the cpu usage is more than 90% the host is marked as BAD

### mem
if the free memory percent is lower than 5% the host is marked as BAD

### load
if one minute load average is greater then the number of cores on the system the host is marked as BAD

### net
if RX or TX bandwidth his above 80% the node is marked as BAD

the "net" module tag needs to reference the interface name stats to be gathered on the remote host:

<pre>
login.mydomain.org:
   192.168.122.150:
       - net.enp0f0s0
</pre>

The ICMP ping module is always run by default and only if the host answers to ICMP echo queries it will be probed
for subsequent health checks.

To run just a ICMP probe do not add any module option. For example:

<pre>
login.mydomain.org:
   192.168.122.150:
   192.168.122.151:
       - all
</pre>

host 192.168.122.150 will just have a ICMP probe.

IPv6 is supported, in that case for Link Local IPv6 a "%<device>" will need to be appended to the IPv6 address. For example:

<pre>
bastion.mydomain.org:
   fe80::2245:fa:febc:2008%virbr0:
       - cpu
   192.168.122.180:
       - all
</pre>
   
## Usage

usage: dynlbd.py [-h] [-cf CONFIG_FILE] [-pm PING_METHOD]
                 [-d | -f | -k KUBELOG]

./dynlbd.py

optional arguments:
  -h, --help            show this help message and exit
  -cf CONFIG_FILE, --config-file CONFIG_FILE
  -pm PING_METHOD, --ping-method PING_METHOD
                        OS|internal
  -d, --Daemon          run as a Daemon
  -f, --foreground      run in foreground, NO Daemon
  -k KUBELOG, --kubelog KUBELOG
                        log file path for kubernetes mode








