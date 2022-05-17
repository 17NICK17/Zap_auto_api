#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 17 20:02:42 2022

@author: nick
"""

'''
This script aims to be the most generic and the most explicit possible.
It works with OWASP ZAP API Python client.
To use it, you have to load the Python API client module and start ZAP
Before starting this script for the first time: Open ZAP, go to
Tools -> Options -> API -> Generate random Key, copy and paste the key in the
variable "apiKey" of the configuration area
This script is divided into two parts : a configuration area, where you have to
change variables according to your needs, and the part with API calls.
Author : aine-rb on Github, from Sopra Steria
'''
import sys
import time
from pprint import pprint
from zapv2 import ZAPv2
import json


#######################################
### BEGINNING OF CONFIGURATION AREA ###
#######################################
## The user only needs to change variable values bellow to make the script
## work according to his/her needs. MANDATORY parameters must not be empty


################OPEN AND READ INPUT FILE################
########################################################

f = open('inputData.json')
data = json.load(f)
apiKey = data['apiKey']
sessionName = data['sessionName']

########################################################
########################################################



# MANDATORY. Define the listening address of ZAP instance
localProxy = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

###################SETTING BOOLEAN VARIABILES###################
################################################################

# OBBLIGATORIA. Settarla vera se si desidera creare una nuova sessione di ZAP,
# altrimenti falsa per utilizzarne una già esistente
isNewSession = True

# OBBLIGATORIA. Determina se il contesto debba essere configurato e poi usato durante gli scan.
# Se impostato a vero, ZAP effettuerà gli scan dal punto di vista di uno specifico utente. 
#useContextForScan = False

# OBBLIGATORIA. Definisce se si utilizza un server di uscita proxy
#useProxyChain = False

# OBBLIGATORIA solo nel caso in cui "useProxyChain" sia vera; ignorata altrimenti.
# Definisce se il server proxy necessita di un'autenticazione
#useProxyChainAuth = False

# OBBLIGATORIA determina se si deve caricare uno script proxy. Tali script 
# verranno eseguiti per ogni richiesta che attraverserà ZAP
#useProxyScript = False

#OBBLIGATORIA solo se useContextForScan è True. Ignorato altrimenti.
# Impostare il valore su True se è necessario utilizzare un indicatore di accesso. Falso se è un indicatore disconnesso che deve essere utilizzato
#isLoggedInIndicator = False

# OBBLIGATORIO solo se useContextForScan è True. Ignorato altrimenti. Impostare il valore su
# True per definire un nuovo contesto. Impostare il valore su False per utilizzarne uno esistente.
#defineNewContext = True

# OBBLIGATORIO solo se useContextForScan è True. Ignorato altrimenti.
# Impostare il valore su True per creare nuovi utenti, altrimenti su False
#createUser = True

# OBBLIGATORIO. Impostare il valore su True se si desidera personalizzare e utilizzare un criterio di scansione
useScanPolicy = True

# OBBLIGATORIO solo se useScanPolicy è True. Ignorato altrimenti.
# Impostare il valore su True per disabilitare tutti i tipi di scansione tranne quelli impostati in ascanIds,
# False per abilitare tutti i tipi di scansione tranne quelli impostati in ascanIds
isWhiteListPolicy = True

# OBBLIGATORIO. Impostare True per utilizzare Ajax Spider, False in caso contrario.
useAjaxSpider = True

# OBBLIGATORIO. Imposta True per spegnere ZAP una volta terminato, False in caso contrario
shutdownOnceFinished = False

################################################################
################################################################

# Define the list of global exclude URL regular expressions. List can be empty.
# The expressions must follow the java.util.regex.Pattern class syntax
# The following example excludes every single URL except http://localhost:8081
globalExcludeUrl = ['^(?:(?!http:\/\/localhost:8081).*).$']


# MANDATORY only if useProxyChain is True, ignored otherwise.
# Outgoing proxy address and port
#proxyAddress = 'my.corp.proxy'
#proxyPort = '8080'
# Define the addresses to skip in case useProxyChain is True. Ignored
# otherwise. List can be empty.
#skipProxyAddresses = ('127.0.0.1;'
#                      'localhost')

# MANDATORY only if useProxyChainAuth is True. Ignored otherwise
#proxyUsername = ''
#proxyPassword = ''
#proxyRealm = ''


# MANDATORY only if useProxyScript is True. Ignored otherwise
#proxyScriptName = 'proxyScript.js'
# Script engine values: "Oracle Nashorn" for Javascript,
# "jython" for python, "JSR 223 JRuby Engine" for ruby
#proxyScriptEngine = 'Oracle Nashorn'
# Asolute local path
#proxyScriptFileName = '/zap/scripts/proxy/proxyScript.js'
#proxyScriptDescription = 'Zap proxy'




# MANDATORY only if defineNewContext is True. Ignored otherwise
#contextName = 'Km4Cityscript'
# MANDATORY only if defineNewContext is False. Disregarded otherwise.
# Corresponds to the ID of the context to use
#contextId = 0
# Define Context Include URL regular expressions. Ignored if useContextForScan
# is False. You have to put the URL you want to test in this list.
#contextIncludeURL = ['https://www.km4city.org/swagger/internal/',
#                     'https://www.km4city.org/swagger/external/']
# Define Context Exclude URL regular expressions. Ignored if useContextForScan
# is False. List can be empty.
#contextExcludeURL = []

# MANDATORY only if useContextForScan is True. Ignored otherwise. Define the
# session management method for the context. Possible values are:
# "cookieBasedSessionManagement"; "httpAuthSessionManagement"
#sessionManagement = 'cookieBasedSessionManagement'

# MANDATORY only if useContextForScan is True. Ignored otherwise. Define
# authentication method for the context. Possible values are:
# "manualAuthentication"; "scriptBasedAuthentication"; "httpAuthentication";
# "formBasedAuthentication"
#authMethod = 'scriptBasedAuthentication'

# MANDATORY only if authMethod is set to scriptBasedAuthentication.
# Ignored otherwise
#authScriptName = 'TwoStepAuthentication.js'
# Script engine values: Oracle Nashorn for Javascript
# jython for python, JSR 223 JRuby Engine for ruby
#authScriptEngine = 'Oracle Nashorn'
# Absolute local path
#authScriptFileName = '/zap/scripts/authentication/TwoStepAuthentication.js'
#authScriptDescription = 'This is a description'

# MANDATORY only if useContextForScan is True. Ignored otherwise. Each
# name/value pair of authParams are expected to be "x-www-form-urlencoded"
# Here is an example for scriptBasedAuthentication method:
#authParams = ''



# MANDATORY only if useContextForScan is True. Ignored otherwise.
# Define either a loggedin or a loggedout indicator regular expression.
# It allows ZAP to see if the user is always authenticated during scans.
#indicatorRegex = ''



# MANDATORY only if createUser is True. Ignored otherwise. Define the list of
# users, with name and credentials (in x-www-form-urlencoded format)
## Here is an example with the script NashornTwoStepAuthentication.js:
#userList = [
#    {'name': 'guest', 'credentials': 'Username=guest&Password=guest'},
#    {'name': 'webgoat', 'credentials': 'Username=webgoat&Password=webgoat'}
#]


# MANDATORY only if useContextForScan is True. Ignored otherwise. List can be
# empty. Define the userid list. Created users will be added to this list later
#userIdList = []

# MANDATORY. Define the target site to test
target = ['https://www.km4city.org/swagger/internal/',
          'https://www.km4city.org/swagger/external/']

# You can specify other URL in order to help ZAP discover more site locations
# List can be empty
#applicationURL = ['https://www.km4city.org/swagger/external/']




# MANDATORY only if useScanPolicy is True. Ignored otherwise. Set a policy name
scanPolicyName = 'SQL Injection and XSS'

# MANDATORY only if useScanPolicy is True. Ignored otherwise. Set the scan IDs
# to use with the policy. Other scan types will be disabled if
# isWhiteListPolicy is True, enabled if isWhiteListPolicy is False.
# Use zap.ascan.scanners() to list all ascan IDs.
## In the example bellow, the first line corresponds to SQL Injection scan IDs,
## the second line corresponds to some XSS scan IDs
ascanIds = [40018, 40019, 40020, 40021, 40022, 40024, 90018,
            40012, 40014, 40016, 40017]
# MANDATORY only if useScanPolicy is True. Ignored otherwise. Set the alert
# Threshold and the attack strength of enabled active scans.
# Currently, possible values are:
# Low, Medium and High for alert Threshold
# Low, Medium, High and Insane for attack strength
alertThreshold = 'Medium'
attackStrength = 'Low'



#################################
### END OF CONFIGURATION AREA ###
#################################





zap = ZAPv2(proxies=localProxy, apikey=apiKey)

# Start the ZAP session
core = zap.core
if isNewSession:
    pprint('Create ZAP session: ' + sessionName + ' -> ' +
            core.new_session(name=sessionName, overwrite=True))
else:
    pprint('Load ZAP session: ' + sessionName + ' -> ' +
            core.load_session(name=sessionName))

# Configura gli URL esclusi dallo scan
print('Add Global Exclude URL regular expressions:')
for regex in globalExcludeUrl:
    pprint(regex + ' ->' + core.exclude_from_proxy(regex=regex))


# Enable all passive scanners (it's possible to do a more specific policy by
# setting needed scan ID: Use zap.pscan.scanners() to list all passive scanner
# IDs, then use zap.scan.enable_scanners(ids) to enable what you want
pprint('Enable all passive scanners -> ' +
        zap.pscan.enable_all_scanners())

ascan = zap.ascan
# Define if a new scan policy is used
if useScanPolicy:
    ascan.remove_scan_policy(scanpolicyname=scanPolicyName)
    pprint('Add scan policy ' + scanPolicyName + ' -> ' +
            ascan.add_scan_policy(scanpolicyname=scanPolicyName))
    for policyId in range(0, 5):
        # Set alert Threshold for all scans
        ascan.set_policy_alert_threshold(id=policyId,
                                         alertthreshold=alertThreshold,
                                         scanpolicyname=scanPolicyName)
        # Set attack strength for all scans
        ascan.set_policy_attack_strength(id=policyId,
                                         attackstrength=attackStrength,
                                         scanpolicyname=scanPolicyName)
    if isWhiteListPolicy:
        # Disable all active scanners in order to enable only what you need
        pprint('Disable all scanners -> ' +
                ascan.disable_all_scanners(scanpolicyname=scanPolicyName))
        # Enable some active scanners
        pprint('Enable given scan IDs -> ' +
                ascan.enable_scanners(ids=ascanIds,
                                      scanpolicyname=scanPolicyName))
    else:
        # Enable all active scanners
        pprint('Enable all scanners -> ' +
                ascan.enable_all_scanners(scanpolicyname=scanPolicyName))
        # Disable some active scanners
        pprint('Disable given scan IDs -> ' +
                ascan.disable_scanners(ids=ascanIds,
                                       scanpolicyname=scanPolicyName))
else:
    print('No custom policy used for scan')
    scanPolicyName = None

# Open URL inside ZAP
for targetURL in target:
    pprint('Access target URL ' + targetURL)
    core.access_url(url=targetURL, followredirects=True)
    # Give the sites tree a chance to get updated
    time.sleep(2)

    # Launch Spider, Ajax Spider (if useAjaxSpider is set to true) and
    # Active scans, with a context and users or not
    forcedUser = zap.forcedUser
    spider = zap.spider
    ajax = zap.ajaxSpider
    scanId = 0
    print('Starting Scans on target: ' + targetURL)


    # Spider the target and recursively scan every site node found
    scanId = spider.scan(url=targetURL, maxchildren=None, recurse=True,
            contextname=None, subtreeonly=None)
    print('Scan ID equals ' + scanId)
    # Give the Spider a chance to start
    time.sleep(2)
    while (int(spider.status(scanId)) < 100):
        print('Spider progress ' + spider.status(scanId) + '%')
        time.sleep(2)
    print('Spider scan completed')

    if useAjaxSpider:
    # Ajax Spider the target URL
        pprint('Start Ajax Spider -> ' + ajax.scan(url=targetURL, inscope=None))
        # Give the Ajax spider a chance to start
        time.sleep(10)
        while (ajax.status != 'stopped'):
            print('Ajax Spider is ' + ajax.status)
            time.sleep(5)
        print('Ajax Spider scan completed')

    # Launch Active scan with the configured policy on the target url and
    # recursively scan every site node
    scanId = zap.ascan.scan(url=targetURL, recurse=True, inscopeonly=None,
                             scanpolicyname=scanPolicyName, method=None, postdata=True)
    print('Start Active scan. Scan ID equals ' + scanId)
    while (int(ascan.status(scanId)) < 100):
         print('Active Scan progress: ' + ascan.status(scanId) + '%')
         time.sleep(5)
    print('Active Scan completed')

        # Give the passive scanner a chance to finish
    time.sleep(5)

# If you want to retrieve alerts:
## pprint(zap.core.alerts(baseurl=target, start=None, count=None))

# To retrieve ZAP report in XML or HTML format
## print('XML report')
## core.xmlreport()
#print('HTML report:')
#pprint(core.htmlreport())
out = open('report.html','w')

out.write(core.htmlreport())
out.close()

if shutdownOnceFinished:
    # Shutdown ZAP once finished
    pprint('Shutdown ZAP -> ' + core.shutdown())