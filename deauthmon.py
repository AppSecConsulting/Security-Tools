#!/usr/bin/python
#
# Author: Tim Jensen
# Last Modified: 2017-01-06
# Description: Script to monitor for 802.11 wireless deauthentication frames and
#              logs to a file. Requires scapy and airmon-ng.
# Usage: 
#    airmon-ng check kill
#    airmon-ng start <wlan_interface>
#    python deauthmon.py <wlan_monitor_interface>
#
# Copyright AppSec Consulting, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#  Redistributions of source code must retain the above copyright notice,
#  this list of conditions and the following disclaimer.
#
#  Redistributions in binary form must reproduce the above copyright notice,
#  this list of conditions and the following disclaimer in the documentation
#  and/or other materials provided with the distribution.
#
#  Neither the name of AppSec Consulting, Inc., nor the names of its
#  contributors may be used to endorse or promote products derived from this
#  software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import sys
import logging
from scapy.all import *

 
#This can be just the file name or a path such as /tmp/deauthmon.log
logfilename='deauthmon.log' 
ifacevar=sys.argv[1]
logger = logging.getLogger('deauthmon')
hdlr = logging.FileHandler(logfilename)
formatter = logging.Formatter('%(asctime)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.INFO)

def PacketHandler(pkt) :
	if pkt.haslayer(Dot11Deauth):
		tmppacket = pkt.sprintf("AP: [%Dot11.addr2%] CLIENT: [%Dot11.addr1%] Reason: [%Dot11Deauth.reason%]")
		print tmppacket
		logger.info(tmppacket)

sniff(iface=ifacevar,prn=PacketHandler)