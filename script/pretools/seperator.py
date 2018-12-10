#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2017-12-7 by r4mind

import dpkt
import os
import sys
import getopt

import pandas as pd
import scapy.all as scapy

def createBurst(sf):
	cnt, prevts = 0, 0.0
	burstslist = []
	tstamplist = []
	burst = []
	time  = []

	pcap = dpkt.pcap.Reader(sf)

	for ts, buf in pcap:
		if cnt == 0:
			prevts = ts

		# get the time gap
		timegap = ts - prevts
		if timegap >= 1:
			burstslist.append(burst)
			burst = []

		burst.append(buf)
		prevts = ts
		cnt += 1

		tstamplist.append(ts)

	burstslist.append(burst)
	burst = []

	return burstslist, tstamplist


def createFlowFile(burstslist, dstfilepath, nowip):
	flowslist = []
	pkglength = []
	bcnt = 1

	for burst in burstslist:
		# check whether the burstXX exists
		if not os.path.exists(dstfilepath):
			os.makedirs(dstfilepath)

		flowsdict = {}
		# pkginflow = {}
		# incompkg  = {}
		# outcompkg = {}

		for pkt in burst:
			eth = dpkt.ethernet.Ethernet(pkt)

			ip = eth.data
			ipset = set([ip.src, ip.dst])

			# if ipset not in keyset:
			# 	flowsdict[ipset] = []
			# flowsdict[ipset].append(pkt)

			# check whether the ip set exists
			inflag = 0
			for key in flowsdict.keys():
				if set(key) == ipset:
					flowsdict[key].append(pkt)
					# if ip.dst in nowip: #  b'\xc0\xa8\x02\x03':
					# 	pkginflow[key].append(len(ip.data))
					# 	incompkg[key].append(len(ip.data))
					# else:
					# 	pkginflow[key].append(len(ip.data))
					# 	outcompkg[key].append(len(ip.data))

					inflag = 1
					break;

			if inflag == 0:
				iptuple = tuple(ipset)
				flowsdict[iptuple] = []
				# pkginflow[iptuple] = []
				# incompkg[iptuple]  = []
				# outcompkg[iptuple] = []

				flowsdict[iptuple].append(pkt)
				# if ip.dst in nowip: # b'\xc0\xa8\x02\x03':
				# 	pkginflow[iptuple].append(-len(ip.data))
				# 	incompkg[iptuple].append(-len(ip.data))
				# else:
				# 	pkginflow[iptuple].append(len(ip.data))
				# 	outcompkg[iptuple].append(len(ip.data))

		# flowslist.append(flowsdict)
		# pkglength.append(pkginflow)


		fcnt = 1
		for f in flowsdict.values():
			with open(dstfilepath + 'flow_' + str(bcnt) + '_' + str(fcnt) + '.pcap', 'wb+') as df:
				flow = dpkt.pcap.Writer(df)
				for pkt in f:
					flow.writepkt(pkt)
			fcnt += 1

		bcnt += 1


def createFlowPD(burstslist, tstamplist, nowip):
	burst   = []
	flow    = []
	uburst  = []
	length  = []
	inorout = []

	# inburst  = []
	# inflow   = []
	# inlength = []

	# outburst  = []
	# outflow   = []
	# outlength = []

	for bursti in range(len(burstslist)):

		ipsetvali = []
		cnt = 0
		curuburst = 1
		prevflag = 0
		curflag = 0
		for pkt in burstslist[bursti]:
			eth = dpkt.ethernet.Ethernet(pkt)

			ip = eth.data
			ipset = set([ip.src, ip.dst])

			burst.append(bursti + 1)

			inflag = 0
			curtup = ()
			for i in ipsetvali:
				if ipset == i:			
					curtup = tuple(i)
					flow.append(curtup)
					inflag = 1
					break;

			if inflag == 0:
				ipsetvali.append(ipset)
				flow.append(tuple(ipset))

			if ip.dst in nowip: # b'\xc0\xa8\x02\x05'
				length.append(-len(ip.data))
				curflag = 1
				# inburst.append(bursti + 1)
				# if inflag == 0:
				# 	inflow.append(tuple(ipset))
				# else:
				# 	inflow.append(curtup)
				# inlength.append(-len(ip.data))
			else:
				length.append(len(ip.data))
				# inorout.append(0)
				curflag = 0

			inorout.append(curflag)

			if cnt == 0:
				prevflag = curflag

			if prevflag != curflag:
				curuburst += 1
				prevflag = curflag

			uburst.append(curuburst)
			cnt += 1

	flowPD = pd.DataFrame({
		'Burst'  : burst  ,
		'Flow'   : flow   ,
		'UBurst' : uburst ,
		'Inorout': inorout,
		'Length' : length ,
		'TStamp' : tstamplist
	})

	# inflowPD = pd.DataFrame({
	# 	'Burst' : inburst,
	# 	'Flow'  : inflow ,
	# 	'Length': inlength
	# })

	# outflowPD = pd.DataFrame({
	# 	'Burst' : outburst,
	# 	'Flow'  : outflow ,
	# 	'Length': outlength
	# })

	# flows = [flowPD, inflowPD, outflowPD]
	# print(type(flows))

	return flowPD


def geneTCPStream(srcpath, value, phonename, pcapnum):
	# cmd = 'tshark -q -r /tmp/%s -z follow,tcp,ascii,%s' % (pcappath, streamindex)
	# sf = '/tmp/' + srcpath + '.pcap'
	dp = '/tmp/tcpstream/' + str(value) + '/'

	# pkgs = scapy.rdpcap(sf)
	# for p in pkgs:
	# 	print(repr(p['TCP'])) 

	if not os.path.exists(dp):
		os.makedirs(dp)

	si = 0
	while True:
		# os.system("tshark -r %s -w %s -F pcap -z follow,tcp,ascii,%s" % (sf, df + srcpath + '_' + str(si) + '.pcap', str(si)))
		df = dp + phonename + '_app' + str(value) + str(pcapnum) + '_tcps' + str(si) + '.pcap'
		os.system("tshark -r %s -w %s -F pcap -Y 'tcp.stream==%s'" % (srcpath, df, str(si)))

		if os.path.getsize(df) < 50:
			break
		else:
			si += 1






def main(argv):
	srcfilepath = ''
	dstfilepath = ''

	try:
		opts, args = getopt.getopt(argv, 'hs:d:')
	except getopt.GetoptError:
		print('seperator.py -s <srcfilepath> -d <dstdirectory>')
		sys.exit(2)

	if opts == []:
		print('seperator.py -s <srcfilepath> -d <dstdirectory>')
		sys.exit(2)

	for opt, arg in opts:
		if opt == '-h':
			print('seperator.py -s <srcfilepath> -d <dstdirectory>')
			sys.exit()
		elif opt == '-s':
			srcfilepath = arg
		elif opt == '-d':
			dstfilepath = arg

	with open(srcfilepath, mode='rb') as sf:
		bh = createBurst(sf)
		fh = createFlow(bh, dstfilepath)
			

################# TEST ###################
if __name__ == '__main__':
	# main(sys.argv[1:])

	geneTCPStream('meizu_TikTok')

# tcp and !(tcp.analysis.flags && !tcp.analysis.window_update) and !(tcp.flags.reset eq 1) and !(sctp.chunk_type eq ABORT) and ip.addr==192.168.2.2