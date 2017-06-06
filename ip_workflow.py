import requests
from requests.auth import HTTPBasicAuth
import ConfigParser
import os
import sys
import dns.resolver

# Specify the config file to read from
configFile = 'api.cfg'

# Read the config file to get settings
config = ConfigParser.RawConfigParser()
config.read(configFile)

# Threat Grid configuration
TGapiKey = config.get('ThreatGrid', 'apiKey')
TGapiKey = str.rstrip(TGapiKey)

hostName = config.get('ThreatGrid', 'hostName')
hostName = str.rstrip(hostName)

# X-Force Configuration
XFapiKey = config.get('X-Force', 'apiKey')
XFapiKey = str.rstrip(XFapiKey)

XFpassword = config.get('X-Force', 'password')
XFpassword = str.rstrip(XFpassword)

# Virustotal Configuration
VTKey = config.get('VirusTotal', 'apiKey')
VTKey = str.rstrip(VTKey)

# Investigate Configuration
UIToken = config.get('Investigate', 'token')
UIToken = str.rstrip(UIToken)

# PassiveTotal Configuration
PTUser = config.get('PassiveTotal', 'username')
PTUser = str.rstrip(PTUser)

PTKey = config.get('PassiveTotal', 'apiKey')
PTKey = str.rstrip(PTKey)

# Validate a parameter was provited
if len(sys.argv) < 2:
    sys.exit('Usage:\n %s IOC' % sys.argv[0])

# IP Example:
# 171.25.193.9:80
IP = sys.argv[1]

# X-Force Query
XForceURL = 'https://api.xforce.ibmcloud.com/ipr/{}'.format(IP)
XFQuery = requests.get(XForceURL, auth=requests.auth.HTTPBasicAuth(XFapiKey,XFpassword)).json()

score = XFQuery['score']
categories = XFQuery['cats']

print 'IBM X-Force:'
print '  Score: {}'.format(score)
print '  Catagories:'
for cat in categories:
	print '     {}'.format(cat)

# Investigate Query
print '\r'
url = 'https://investigate.api.umbrella.com/dnsdb/ip/a/{}.json'.format(IP)

headers = {'Authorization': 'Bearer ' + UIToken}
r = requests.get(url, headers=headers).json()
print 'Domains in Investigate:'
for rr in r['rrs']:
	domain = rr['rr'][:-1]
	print '  {}'.format(domain)

# VT Query
print '\r'
params = {'apikey': VTKey, 'ip': IP}
headers = {"Accept-Encoding": "gzip, deflate"}

VTURL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
VTQuery = requests.get(VTURL, params=params, headers=headers).json()

print 'VirusTotal hits:'

if VTQuery['verbose_msg'] == 'IP address in dataset':
	detectedURLs = VTQuery['detected_urls']
	detectedSamples = VTQuery['detected_communicating_samples']
	undetectedSamples = VTQuery['undetected_communicating_samples']
	
	print '  URL Count: {}'.format(len(detectedURLs))
	print '  Detected Sample Count: {}'.format(len(detectedSamples))
	print '  Undetected Sample Count: {}'.format(len(undetectedSamples))

# The Tor Project Onionoo Query
print '\r'
TorURL = 'https://onionoo.torproject.org/details?search={}'.format(IP)
TorQuery = requests.get(TorURL).json()

relays = TorQuery['relays']
print 'The Tor Project Onionoo hits:'
if len(relays) > 0:
	print '  Number of relays: {}'.format(len(relays))
	for relay in relays:
		print '  Hostname: {}'.format(relay['host_name'])
		print '  Nickname: {}'.format(relay['nickname'])
		print '  OR Addresses:'
		for address in relay['or_addresses']:
			print '    {}'.format(address)

#TG Query
print '\r'
TGURL = 'https://panacea.threatgrid.com/api/v2/search/submissions?state=succ&q={}&api_key={}'.format(IP,TGapiKey)
TGQuery = requests.get(TGURL).json()

TGHighScore = 0

items = TGQuery['data']['items']
for sample in items:
    threat_score = sample['item']['analysis']['threat_score']
    if threat_score > TGHighScore:
    	TGHighScore = threat_score

TGTotal = TGQuery ['data']['current_item_count']

print 'Threat Grid has {} samples with this IP, the highest score is: {}'.format(TGTotal,TGHighScore)

# PassiveTotal Query
print '\r'
PTURL = 'https://api.passivetotal.org/v2/dns/passive'
PTAuth = (PTUser, PTKey)
PTData = {'query': IP}
PTQuery = requests.get(PTURL, auth=PTAuth, json=PTData).json()

print 'PassiveTotal hits:'
if PTQuery['totalRecords'] > 0:
	print '  Number of resolutions: {}'.format(PTQuery['totalRecords'])
	print '  The first record is from: {}'.format(PTQuery['firstSeen'])