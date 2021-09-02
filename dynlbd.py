#!/usr/bin/python3.9
#
# veraldi@slac.stanford.edu
#
import yaml
import sys
import os
import re
import time
import argparse
from datetime import datetime
import sys
import socket
import subprocess
import ipaddress
from threading import Thread
import daemon
import signal
import itertools
#
import dns.resolver
import dns.exception
import dns.reversename
import dns.query
import dns.update
import dns.tsigkeyring
#
import logging
import logging.handlers
#
import numpy as np
#
import requests
from requests.models import ProtocolError
#
from ping3 import ping, verbose_ping
from elevate import elevate
#
##
import sysv_ipc
#
import ctypes
sodir = os.getcwd()
so_file = sodir+"/shm.so"
shm = ctypes.cdll.LoadLibrary(so_file)
##
#
cpu_tag = "cpu" # 'cpu' TAG yaml conf file
mem_tag = "mem" # 'mem' TAG yaml conf file
load_tag = "load" # 'loadave' TAG yaml conf file
net_tag = "net" # 'net' TAG yaml conf file
all_tag = "all" # 'all' TAG yaml conf file
conf_tags = [cpu_tag, mem_tag, load_tag, net_tag, all_tag]
#
opr = ("add","delete")
rr = ("A", "PTR", "AAAA")
isrunning = b'run\x00'
#
all_opts = ( 'dns_mode', 'thread_timeout', 'dnsttl', 'ping_timeout', 'tsig_key_name', 'tsig_key_value', 'nameserver', 'shm_key')
#
node_exporter_err = "node_exporter_connection_error"
icmp = re.compile(r"(\d*[.,]?\d*)% packet loss") # match packet loss output ping pattern
idlcpu = re.compile(r"node_cpu_seconds_total{cpu=.*mode=\"idle\"}\ (.*)")
memtot = re.compile(r"node_memory_MemTotal_bytes\ (\d.*)")
memfree = re.compile(r"node_memory_MemFree_bytes\ (\d.*)")
loadave = re.compile(r"node_load1\ (\d.*.\d.*)")


class isAliveMetrics(Thread):
	def __init__ (self, host, ip, param, method, t):
		Thread.__init__(self)
		self.host = host
		self.ip = ip
		_type = type(ipaddress.ip_address(self.ip))
		if (_type == ipaddress.IPv4Address):
			self.url = "http://"+self.ip+":9100/metrics"
		elif (_type == ipaddress.IPv6Address):
			self.url = "http://["+self.ip+"]:9100/metrics"
		self.param = param
		self.method = method
		self.t = t # sleep between CPU or Iface counter subsequent calls
		self.status = -1
		self.pingonly = 0
		self.all_metrics = []
		self.node_exporter = 0
		self.cpu_usage_percent = -1
		self.cpu_ncores = -1
		self.mem_tot = -1
		self.mem_free = -1
		self.load_ave = -1
		self.net_usage_rx_percent = -1
		self.net_usage_tx_percent = -1

	def run(self):
		isAliveMetrics.isAlive(self)
		if (self.status):
			if (self.param is None): # continue to next thread if ping only
				self.pingonly = 1
				return 0
			#start_time = datetime.now()
			isAliveMetrics.allMetrics(self) # get all metrics at the begining when Class is instanced
			#end_time = datetime.now()
			#print('Debug: duration allMetrics(): {}'.format(end_time - start_time))
			#start_time = datetime.now()
			for metr in self.all_metrics:
				if ( metr == node_exporter_err ): # check for node exporter connection problems
					self.node_exporter = -1 # mark node_exporter as broken for this thread
					return -1
			if (cpu_tag in self.param or all_tag in self.param):
				isAliveMetrics.CPUpercent(self)
			if (mem_tag in self.param or all_tag in self.param) :
				isAliveMetrics.Mem(self)
			if (load_tag in self.param or all_tag in self.param) :
				isAliveMetrics.loadAve(self)
			for p in self.param:
				if (p[:3] == net_tag):
					isAliveMetrics.NetPercent(self)
			#end_time = datetime.now()
			#print('Debug: Duration all modules: {}'.format(end_time - start_time))

	def isAlive(self):
		if ( self.method == "OS" ):
			pinga = os.popen("ping -q -t"+ping_timeout+" -c"+ping_timeout+" "+self.ip,"r")
			while 1:
				line = pinga.readline()
				if not line: break
				res = re.findall(icmp,line)
				if res:
					if (float(res[0]) < 5.0):
						self.status = 1
					else:
						self.status = 0
		if ( self.method == "internal"):
			pinga = ping(self.ip)
			if (pinga):
				self.status = 1
			else:
				self.status = 0

	def allMetrics(self): # collect metrics at self.t time distance
		c = 0
		while(1):
			try:
				res = requests.get(self.url)
				self.all_metrics.append(res.text)
			except requests.exceptions.RequestException as cerr:
				self.all_metrics.append(node_exporter_err)
			if (c):
				break
			time.sleep(self.t)
			c += 1

	def CPUpercent(self):
		# self.all_metrics[0] metrics at t = 0
		# self.all_metrics[1] metrics at self.t
		#
		idlestr1 = re.findall(idlcpu, self.all_metrics[0])
		idlestr2 = re.findall(idlcpu, self.all_metrics[1])
		#
		idle1 = sToInt(idlestr1)
		idle2 = sToInt(idlestr2)
		#
		idle = np.subtract(idle2,idle1)
		cpu_usage_cores_percent = 100 - (idle/self.t) * 100
		cpu_usage_percent = np.mean(cpu_usage_cores_percent)
		cpu_usage_percent_round = np.rint(cpu_usage_percent)
		self.cpu_usage_percent = cpu_usage_percent_round.astype(int)
		self.cpu_ncores = len(cpu_usage_cores_percent)

	def NetPercent(self):
		# self.all_metrics[0] metrics at t = 0
		# self.all_metrics[1] metrics at self.t
		#
		# get network interface name
		net_param = [s for s in self.param if net_tag in s]
		iface = net_param[0].split(".")[1] # interface name
		# get interface speed bytes/sec
		iface_speed_find = re.compile(r'node_network_speed_bytes{device=\"'+iface+'\"}\ (.*)')
		iface_speed_s = re.findall(iface_speed_find, self.all_metrics[0])
		iface_speed =  sToInt(iface_speed_s)[0]
		# transm bytes 
		tx_bytes_find = re.compile(r'node_network_transmit_bytes_total{device=\"'+iface+'\"}\ (.*)')
		tx_bytes_s1 = re.findall(tx_bytes_find, self.all_metrics[0])
		tx_bytes1 = sToInt(tx_bytes_s1)
		tx_bytes_s2 = re.findall(tx_bytes_find, self.all_metrics[1])
		tx_bytes2 = sToInt(tx_bytes_s2)
		tx_bytes = np.subtract(tx_bytes2, tx_bytes1)[0]
		tx_bytes_sec = tx_bytes/self.t
		# recv bytes
		rx_bytes_find = re.compile(r'node_network_receive_bytes_total{device=\"'+iface+'\"}\ (.*)')
		rx_bytes_s1 = re.findall(rx_bytes_find, self.all_metrics[0])
		rx_bytes1 = sToInt(rx_bytes_s1)
		rx_bytes_s2 = re.findall(rx_bytes_find, self.all_metrics[1])
		rx_bytes2 = sToInt(rx_bytes_s2)
		rx_bytes = np.subtract(rx_bytes2, rx_bytes1)[0]
		rx_bytes_sec = rx_bytes/self.t
		_net_usage_rx_percent = 100 * rx_bytes_sec/iface_speed
		_net_usage_rx_percent_round = np.rint(_net_usage_rx_percent)
		_net_usage_tx_percent = 100 * tx_bytes_sec/iface_speed
		_net_usage_tx_percent_round = np.rint(_net_usage_tx_percent)
		self.net_usage_rx_percent = _net_usage_rx_percent_round.astype(int)
		self.net_usage_tx_percent = _net_usage_tx_percent_round.astype(int)


	def Mem(self):
		memtotstr = re.findall(memtot, self.all_metrics[0])
		memfreestr = re.findall(memfree, self.all_metrics[0])
		self.mem_tot = sToInt(memtotstr[0])
		self.mem_free = sToInt(memfreestr[0])

	def loadAve(self):
		loadstr = re.findall(loadave, self.all_metrics[0])
		if (not loadstr):
			self.load_ave = 0.0
		else:
			load_f = np.asarray(loadstr[0], dtype=np.float64)
			self.load_ave = load_f.item()


def sToInt(s): # convert numeric string to int with approximation (avoid truncation)
    stofloat = np.asarray(s, dtype=np.float64)
    sround = np.rint(stofloat)
    stoint = sround.astype(int)
    return stoint

def sudosu(): # elevate privileges
	elevate()

def is_root():
    return os.getuid() == 0

def readYAMLconf(cf):
	srvdb = {}
	try:
		with open(cf, 'r') as cf:
			config = yaml.full_load(cf)
			counter = 0
			for host, ip in config.items():
				srvdb[host] = ip
				# check if it is a parameter or a host pool configuration
				if (isinstance(ip, dict)):
					# check hostname to be FQDN
					if ("." not in host): # abort if not FQDN
						return(-1)
					for ips, metrics in ip.items(): # check metrics conf syntax
						if (metrics is None): # pingonly
							continue
						for m in metrics:
							if ((m not in conf_tags) and (m[:3] != net_tag)):
								print("config file error, unknown option {}".format(m))
								return -2
			return srvdb
	except EnvironmentError as err:
		return err

def DNSgetRR(query):
	try: # PTR record
		ip = query
		ipaddress.ip_address(query)
		rrptr = []
		res = dns.resolver.Resolver()
		res.nameservers = [nameserver]
		revip = dns.reversename.from_address(ip)
		try:
			ans = res.resolve(revip,rr[1])
		except dns.resolver.NXDOMAIN:
			return "UNKNOWN"
		else:
			for i in ans:
				rrptr.append(i.to_text())
			return rrptr
	except ValueError as err: # A or AAAA record
		fqdn = query
		rras = []
		dnsexcept_A = False
		dnsexcept_AAAA = False
		res = dns.resolver.Resolver()
		res.nameservers = [nameserver]
		try:
			ansA = res.resolve(fqdn,rr[0])
			for i in ansA:
				rras.append(i.to_text())
		except dns.exception.DNSException as dnserr:
			dnsexcept_A = True
		try:
			ansAAAA = res.resolve(fqdn,rr[2])
			for i in ansAAAA:
				rras.append(i.to_text())
		except dns.exception.DNSException as dnserr:
			dnsexcept_AAAA = True
		if (dnsexcept_A and dnsexcept_AAAA):
			return "UNKOWN"
		else:
			return rras
		

def DNSupdate(drv, operator, host, ttl, rrecord, ipaddr, tsig_key): # host is FQDN, n is hostname, zone is domain name
	if (drv == dns_mode): # nsupdate method rfc2136
		if (rrecord == rr[0] or rrecord == rr[2]): # A record or AAAA record
			n = host.split(".")[0] # hostname
			zone = host[len(n)+1:] # domain/zone
			updt = dns.update.Update(zone, keyring=tsig_key, keyalgorithm='HMAC-SHA512')
			if (operator == opr[0]): # add record
				updt.add(n, ttl, rrecord, ipaddr)
			elif (operator == opr[1]): # delete record
				dns_datatype = dns.rdatatype.from_text(rrecord)
				rdata = dns.rdata.from_text(dns.rdataclass.IN, dns_datatype, ipaddr)
				updt.delete(n, rdata)
			response = dns.query.tcp(updt, nameserver)
			return response

def hostStatus(threadsList, log):
	statdb = {}
	# build dictionary with hosts status from metrics
	for h in threadsList:
		h.join(timeout = sToInt(thread_timeout))
		host_is_good = 1
		if (h.status): # if ping is alive
			if (h.node_exporter < 0): # if node_exporter does not respond
				log.info("%s: %s node_exporter failure, please fix ASAP, DNS will not be modified", h.host, h.ip)
				host_is_good = -1
			elif (h.pingonly == 0 and h.cpu_usage_percent < 0 and h.cpu_ncores < 0 and h.mem_tot < 0 and h.mem_free < 0 and h.load_ave < 0 and h.net_usage_rx_percent < 0 and h.net_usage_tx_percent < 0):
				# thread failure
				log.info("%s: %s Thread failure, DNS will not be modified", h.host, h.ip)
				host_is_good = -1
			if (not h.pingonly): # if at least a Metric is defined in yaml file
				if (host_is_good > 0):
					if (cpu_tag in h.param or all_tag in h.param):
						if (h.cpu_usage_percent > 90): # BAD host if CPU usage greater than 90%
							log.info('%s: %s %s ==== high CPU usage %s%%, node marked as BAD ====', pname, h.host, h.ip, h.cpu_usage_percent)
							host_is_good = 0
					if (load_tag in h.param or all_tag in h.param):
						if ( h.load_ave > h.cpu_ncores ): # BAD host if load ave is greater than number of cores
							log.info("%s: %s %s ==== high loadave %s, node marked as BAD ====", pname, h.host, h.ip, h.load_ave)
							host_is_good = 0
					if (mem_tag in h.param or all_tag in h.param):
						mem_free_percent = 100*h.mem_free/h.mem_tot
						if (mem_free_percent < 5): # BAD host if free mem is less than 5%
							log.info("%s: %s %s ==== low free Mem %s%%, node marked as BAD ====", pname, h.host, h.ip, mem_free_percent)
							host_is_good =  0
					for p in h.param:
						if (p[:3] == net_tag):
							if (h.net_usage_tx_percent > 80): # BAD host if net tx usage is more than 80%
								log.info("%s: %s %s ==== TX net usage too high %s%%, node marked as BAD ====", pname, h.host, h.ip, h.net_usage_tx_percent)
								host_is_good =  0
							if (h.net_usage_rx_percent > 80): # BAD host if net tx usage is more than 80%
								log.info("%s: %s %s ==== RX net usage too high %s%%, node marked as BAD ====", pname, h.host, h.ip, h.net_usage_rx_percent)
								host_is_good =  0
		else: # if ping is not alive
			host_is_good = 0
		if (h.host in statdb): # append host status, HOST IS GOOD = 1, HOST IS BAD = 0, HOST STATUS UNKNOWN = -1
			statdb[h.host].append([h.ip, host_is_good])
		else:
			statdb[h.host] = [[h.ip, host_is_good]]
	return statdb
			

def checkConf(dict): # check configuration options are in the yaml config file eg: dynlbd.conf
	keylist = []
	for key in all_opts:
		if key not in dict.keys():
			keylist.append(key)
	return keylist

def setupLogger(pname, _Daemon, kubeLog):
	# setup logging console for nodaemon mode and file for kubernetes mode
	log = logging.getLogger(pname)
	log.setLevel(logging.INFO)
	if _Daemon:
		syslog = logging.handlers.SysLogHandler(address = '/dev/log')
		log.addHandler(syslog)
	elif kubeLog:
		try:
			with open(kubeLog) as kf:
				if (not os.access(kubeLog, os.W_OK)):
					print("{}: write access violation".format(kubeLog))
					print("{}: aborted".format(pname))
					sys.exit(0)
		except IOError as kferr:
			print(kferr)
			sys.exit(0)
		logkube = logging.FileHandler(kubeLog)
		logkubeFMT = logging.Formatter("%(asctime)s:%(levelname)s:%(message)s",datefmt="%H:%M:%S")
		logkube.setFormatter(logkubeFMT)
		log.addHandler(logkube)
		print("{}: kubernetes mode logging to {}".format(pname,kubeLog))
	elif not _Daemon:
		console = logging.StreamHandler()
		log.addHandler(console)
		print("{}: Foreground mode logging console".format(pname))
	return log

def refreshDaemon():
    with daemon.DaemonContext(
        #files_preserve = [ ],
        chroot_directory=None,working_directory=os.getcwd(),
        signal_map={ signal.SIGTERM: shutdown, signal.SIGTSTP: shutdown }):
        main()

def shutdown(signum, frame):
    _exit4Ever()

def _exit4Ever(): # free shm segment before exiting, custom C module shm
	shm.shm_free(shmID)
	sys.exit(0)

def main():
	# global paramenters from conf file
	global dns_mode
	global thread_timeout
	global dnsttl
	global ping_timeout
	global tsig_key_name
	global tsig_key_value
	global nameserver
	global shm_key

	log = setupLogger(pname, _Daemon, kubeLog)
	log.info("%s started", pname)

	if (method == "internal"):
		# privilege elevation
		sudosu()
	if (is_root()):
		log.info("%s Running with elevated privileges", pname)
	#

	srvdb = readYAMLconf(conf) # read yaml configuraiton file
	if (srvdb == -1): 
		log.info("host name in config file not in FQDN format")
		sys.exit(0)
	if (srvdb == -2):
		log.info("unknown options in YAML config file")
		sys.exit(0)
	if (isinstance(srvdb, Exception)):
		log.info("%s", srvdb)
		sys.exit(0)
	#
	# check onfiguration options to be in yaml config file
	chk = checkConf(srvdb)
	for opt in chk:
		log.info("missing %s in config file", opt)
	if (len(chk)):
		log.info("%s aborted", pname)
		sys.exit(0)

	# set paramenters from config file
	dns_mode = srvdb[all_opts[0]]
	if (not dns_mode):
		log.info("%s: bad value", all_opts[0])
		log.info("%s aborted", pname)
		sys.exit(0)
	thread_timeout = srvdb[all_opts[1]]
	if (not thread_timeout):
		log.info("%s: bad value", all_opts[1])
		log.info("%s aborted", pname)
		sys.exit(0)
	dnsttl = srvdb[all_opts[2]]
	if (not dnsttl):
		log.info("%s: bad value", all_opts[2])
		log.info("%s aborted", pname)
		sys.exit(0)
	ping_timeout = srvdb[all_opts[3]]
	if (not ping_timeout):
		log.info("%s: bad value", all_opts[3])
		log.info("%s aborted", pname)
		sys.exit(0)
	tsig_key_name = srvdb[all_opts[4]]
	if (not tsig_key_name):
		log.info("%s: bad value", all_opts[4])
		log.info("%s aborted", pname)
		sys.exit(0)
	tsig_key_value = srvdb[all_opts[5]]
	if (not tsig_key_value):
		log.info("%s: bad value", all_opts[5])
		log.info("%s aborted", pname)
		sys.exit(0)
	nameserver = srvdb[all_opts[6]]
	if (not nameserver):
		log.info("%s: bad value", all_opts[6])
		log.info("%s aborted", pname)
		sys.exit(0)
	shm_key = srvdb[all_opts[7]] # shared memory IPC key access
	if (not shm_key):
		log.info("%s: bad value", all_opts[7])
		log.info("%s aborted", pname)
		sys.exit(0)

	# use custom C module for systemV shared mem IPC
	shmKey = sToInt(shm_key)
	# check whether a dynlbd instance is not already running
	try:
		memory = sysv_ipc.SharedMemory(int(shmKey))
		if (memory.read() == isrunning):
			log.info("%s instance already running", pname)
			log.info("%s ABORT", pname)
			sys.exit(0)
	except sysv_ipc.ExistentialError as memerr:
		pass
	# if not already running then write into shm
	global shmID
	shmID = shm.shm_w(int(shmKey))
	if (shmID == -10):
		log.info("%s: Error getting shared memory shm_id, from C module shm", pname)
	elif (shmID == -20):
		log.info("%s: Error attaching shared moemory ID, from C module shm", pname)
	#

	tsig_key = dns.tsigkeyring.from_text({tsig_key_name:tsig_key_value})

	# start main loop
	metricSpan = int(sToInt(thread_timeout)*2/3)
	main_loop = metricSpan

	while True:
		threadedMetrics = [] # init thread array empty
		try: # launch threading probes
			for srv, ips in srvdb.items(): # 
				if (isinstance(srvdb[srv], str)): # exclude configuration file options from Threads
					continue
				for ip in ips.items():
					ipaddr = ip[0]
					param = ip[1] # array of metrics to look for
					current = isAliveMetrics(srv, ipaddr, param, method, metricSpan)
					current.start()
					threadedMetrics.append(current)
		except EnvironmentError as err:
			log.info("%s", err)
			sys.exit(0)

		hoststats = hostStatus(threadedMetrics, log)

		# modify DNS according to hosts status
		for pool, hosts in hoststats.items(): # h[0] IP, h[1] status [0|1]
			RRlist = DNSgetRR(pool)
			for h in hosts:
				dnsrr = ""
				_type = type(ipaddress.ip_address(h[0]))
				if (_type == ipaddress.IPv4Address):
					dnsrr = rr[0] # record A
				elif (_type == ipaddress.IPv6Address):
					dnsrr = rr[2] # record AAAA
				ip_addr = h[0]
				if ("%" in h[0]): # look for % in ipv6 address
					ip_addr = h[0][:h[0].index("%")] # remove the % loopback interface reference
				if (h[1] == 1): # host/ip is healthy
					# check whether ip is already in the DNS
					if (ip_addr in RRlist): # do not update A record
						log.info("%s: %s %s is up and healthy, RR %s in DNS, no RR update", pname, pool, ip_addr, dnsrr)
					else: # add record A or AAAA if host is not in the DNS
						log.info("%s: %s %s is up and healthy, RR %s not in DNS, adding RR", pname, pool, ip_addr, dnsrr)
						DNSupdate(dns_mode, opr[0], pool, dnsttl, dnsrr, ip_addr, tsig_key)
						if (ip_addr not in DNSgetRR(pool)): # check if RR has been successfully added
							log.info("%s: %s adding %s RR %s failed!! Check on nameserver!!", pname, pool, ip_addr, dnsrr)
				elif (not h[1]): # host/ip is unhealthy
					# check whether ip is already in the DNS
					if (ip_addr in RRlist): # delete record A or AAAA
						pool_hosts = len(RRlist)
						if (pool_hosts > 1): # make sure number of host in the DNS pool is > 1 or do not delete DNS RR
							log.info("%s: %s %s is unhealthy, RR %s in DNS, deleting RR", pname, pool, ip_addr, dnsrr)
							DNSupdate(dns_mode, opr[1], pool, dnsttl, dnsrr, ip_addr, tsig_key)
							if (ip_addr in DNSgetRR(pool)): # check if RR has been successfully deleted
								log.info("%s: %s deleting %s RR %s failed!! Check on nameserver!!", pname, pool, ip_addr, dnsrr)
						else:
							log.info("%s: %s %s is unhealthy, RR %s in DNS, CANNOT DELETE RR, last valid entry!!", pname, pool, ip_addr, dnsrr)
					else: #  if ip/host not in DNS then do nothing
						log.info("%s: %s %s is unhealthy, RR %s not in DNS, no RR needs to be updated", pname, pool, ip_addr, dnsrr)
				else: # status UNKNOWN (node_exporter or thread error)
					pass
		time.sleep(main_loop)


if __name__ == "__main__":
	pname = sys.argv[0]
	# parse cmd
	parser = argparse.ArgumentParser(description=pname)
	parser.add_argument('-cf', '--config-file', default='/etc/dynlbd.conf')
	parser.add_argument('-pm', '--ping-method', default="OS", help="OS|internal")
	forkubelog = parser.add_mutually_exclusive_group()
	forkubelog.add_argument('-d', '--Daemon', action='store_true', help="run as a Daemon")
	forkubelog.add_argument('-f', '--foreground', action='store_true', help="run in foreground, NO Daemon")
	forkubelog.add_argument('-k', '--kubelog',  help="log file path for kubernetes mode")
	args = parser.parse_args()
	#
	conf = args.config_file # get config file
	method = args.ping_method # get ping method
	#_Daemon = not ( args.foreground or args.kubelog) # daemon or foreground mode ? kubernetes logging ?
	_Daemon = args.Daemon
	foreground = args.foreground
	kubeLog =  args.kubelog
	#
	if (not foreground and not _Daemon and not kubeLog):
		print("{}: -d or -f or -k are MANDATORY options".format(pname))
		sys.exit(0)
	#
	if _Daemon:
		sys.stdout.write("Init "+pname+" refresh daemon" )
		spinner = itertools.cycle(['-', '/', '|', '\\','.'])
		for _ in range(30):
			sys.stdout.write(".")
			sys.stdout.write(next(spinner))
			sys.stdout.flush()
			sys.stdout.write('\b') 
			time.sleep(.1)
		sys.stdout.write("\n")
		print("{}: daemon mode logging to journald/syslog".format(pname))
		refreshDaemon()
	else:
		try:
			main()
		except KeyboardInterrupt:
			shm.shm_free(shmID)
			pass