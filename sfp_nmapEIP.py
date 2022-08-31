# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_nmapEIP
# Purpose:      Modulo para realizar un escaneo de puertos.
#
# Author:      David Cacho Saiz <d.cacho_6@hotmail.com>
#
# Created:     31/08/2022
# Copyright:   (c) David Cacho Saiz 2022
# Licence:     GPL
# -------------------------------------------------------------------------------


from spiderfoot import SpiderFootEvent, SpiderFootPlugin
import subprocess

class sfp_nmapEIP(SpiderFootPlugin):

    meta = {
        'name': "nmapEIP",
        'summary': "Realiza un escaneo de puertos",
        'flags': [""],
        'useCases': [""],
        'categories': ["Passive DNS"]
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]

    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "IP_ADDRESS"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["TCP_PORT_OPEN"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:
            data = None

            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")

            ########################
            # Insert here the code #
            ########################
            
            openPorts=[]
            cont = 0
            for port in range (65536):
            	data = subprocess.run('timeout 1 bash -c "</dev/tcp/'+eventData+'/'+str(port)+'" ' + eventData, shell=True, text=True, capture_output=True)
            	data = str(data)
            	correct = 'CompletedProcess(args=\'timeout 1 bash -c "</dev/tcp/'+eventData+'/'+str(port)+'" ' +eventData+'\', returncode=0, stdout=\'\', stderr=\'\')'
            	if data == correct:
            		openPorts.append(cont)
            	cont = cont + 1
            	
            if not openPorts:
                self.sf.error("Unable to perform <ACTION MODULE> on " + eventData)
                return
        except Exception as e:
            self.sf.error("Unable to perform the <ACTION MODULE> on " + eventData + ": " + str(e))
            return

        #typ = "DOMAIN_NAME"
        #data = "newdomaintest.com"

        for x in openPorts:
        	evt = SpiderFootEvent("TCP_PORT_OPEN", str(x), self.__name__, event)
        	self.notifyListeners(evt)

# End of sfp_new_module class
