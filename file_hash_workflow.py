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

# Validate a parameter was provited
if len(sys.argv) < 2:
    sys.exit('Usage:\n %s IOC' % sys.argv[0])

MD5 = ''
SHA256 = sys.argv[1]

# X-Force Query
XForceURL = 'https://api.xforce.ibmcloud.com/malware/{}'.format(SHA256)
XFQuery = requests.get(XForceURL, auth=requests.auth.HTTPBasicAuth(XFapiKey,XFpassword)).json()

print 'IBM X-Force Risk: {}'.format(XFQuery['malware']['risk'])

# VT Query
params = {'apikey': VTKey, 'resource': SHA256}
headers = {"Accept-Encoding": "gzip, deflate"}

VTURL = 'https://www.virustotal.com/vtapi/v2/file/report'
VTQuery = requests.get(VTURL, params=params, headers=headers).json()

MD5 = VTQuery['md5']

print 'Virus Total Engine Convictions: {} of {}'.format(VTQuery['positives'],VTQuery['total'])

#TG Query
TGURL = 'https://panacea.threatgrid.com/api/v2/search/submissions?state=succ&q={}&api_key={}'.format(SHA256,TGapiKey)
TGQuery = requests.get(TGURL).json()

TGHighScore = 0

items = TGQuery['data']['items']
for sample in items:
    threat_score = sample['item']['analysis']['threat_score']
    if threat_score > TGHighScore:
    	TGHighScore = threat_score

TGTotal = TGQuery ['data']['current_item_count']

print 'Threat Grid has seen this file {} times, the highest score is: {}'.format(TGTotal,TGHighScore)

# Team Cymru Query
detectionRatePercentage = 0
qdata = '{}.malware.hash.cymru.com'.format(MD5)
query = dns.resolver.query(qdata, 'TXT')
for answers in query:
	for txt in answers.strings:
		detectionRatePercentage = int(txt.split()[1])

print 'Team Cymru MHR has a detection rate of: {}'.format(detectionRatePercentage)