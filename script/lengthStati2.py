	#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2018-10-31 by r4mind

import pretools.pcapfilter as pf
import pretools.seperator  as sp
import scapy.all           as scapy
import numpy               as np

from classifiers.RFmulti     import RFmul
from classifiers.MetricL     import LMNNforkNN
from classifiers.KNeigh      import KNeigh
from sklearn.metrics         import precision_score, recall_score, accuracy_score, roc_curve, auc
from sklearn.preprocessing   import binarize
from matplotlib          import pyplot as plt
from random              import sample, randint
from itertools           import groupby

import pickle
import appset
import glob
import os
import math
import csv

def geneFlow(srcfile):
	filteredfile = pf.filter('/tmp/' + srcfile + '.pcap')
	with open(filteredfile, mode='rb') as sf:
		bh, _ = sp.createBurst(sf)
	sp.createFlowFile(bh, '/tmp/flow/' + srcfile + '/', [b'\xc0\xa8\x02\x07', b'\xc0\xa8\x02\x05', b'\xc0\xa8\x89\xa4'])


def sepaByPcapLength(srcfile):
	lengthdict = {}
	lengthdict[1] = []
	lengthdict[2] = []
	lengthdict[3] = []
	lengthdict[4] = []
	lengthdict[5] = []

	pcapfiles = glob.glob('/tmp/flow/' + srcfile + '/*.pcap')
	for i in pcapfiles:
		pcapsize = os.path.getsize(i)

		if pcapsize < 1e+4:
			lengthdict[1].append(i)
		elif pcapsize < 1e+5:
			lengthdict[2].append(i)
		elif pcapsize < 1e+6:
			lengthdict[3].append(i)
		elif pcapsize < 1e+7:
			lengthdict[4].append(i)
		else:
			lengthdict[5].append(i)

	return lengthdict


def sepaByPkgLength(lengthdict, values):
	feaarray = []
	yarray = []

	for n, v in lengthdict.items():
		pcapsizeflag = [0, 0, 0, 0, 0]
		pcapsizeflag[n - 1] = 1

		for j in v:
			pkgs = scapy.rdpcap(j)
			pkgcount = len(pkgs)

			length_0_19      = 0
			length_20_39     = 0
			length_40_79     = 0
			length_80_159    = 0
			length_160_319   = 0
			length_320_639   = 0
			length_640_1279  = 0
			length_1280_2559 = 0
			length_2560_5119 = 0
			length_5120_     = 0

			for k in pkgs:
				pkglen = len(k.payload.payload)

				if pkglen < 20:
					length_0_19      += 1
				elif pkglen < 40:
					length_20_39     += 1
				elif pkglen < 80:
					length_40_79     += 1
				elif pkglen < 160:
					length_80_159    += 1
				elif pkglen < 320:
					length_160_319   += 1
				elif pkglen < 640:
					length_320_639   += 1
				elif pkglen < 1280:
					length_640_1279  += 1
				elif pkglen < 2560:
					length_1280_2559 += 1
				elif pkglen < 5120:
					length_2560_5119 += 1
				else:
					length_5120_ += 1

			fealist = [length_0_19 / pkgcount, length_20_39 / pkgcount, length_40_79 / pkgcount, length_80_159 / pkgcount, length_160_319 / pkgcount, length_320_639 / pkgcount, length_640_1279 / pkgcount, length_1280_2559 / pkgcount, length_2560_5119 / pkgcount, length_5120_ / pkgcount]
			fealist.extend(pcapsizeflag)
			feaarray.append(fealist)
			yarray.append(values)

	return feaarray, [values for i in range(len(feaarray))]


def timePkgDisturb(srcfile):
	pcapfiles = glob.glob('/tmp/flow/' + srcfile + '/*.pcap')
	timefea = []
	timeres = []

	for pcap in pcapfiles:
		pcaphandle = scapy.rdpcap(pcap)

		firsttime = pcaphandle[0].time
		gaptimelist = []

		for pkg in pcaphandle:
			gaptime = pkg.time - firsttime
			gaptimelist.append(gaptime)

		pcaptime = gaptimelist[len(gaptimelist) - 1]
		gaptimeflag = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

		for ti in gaptimelist:
			# print(ti)
			for i in range(11)[1:]:
				if ti <= pcaptime * i / 10:
					gaptimeflag[i - 1] += 1
					break

		pkgcount = sum(gaptimeflag)
		gaptimeper = [k / pkgcount for k in gaptimeflag]

		timefea.append(gaptimeper)
		timeres.append(values)

	return timefea, timeres


def classifyStream():
	for i in appset.phonelist:
		print(i)
		pcapfiles = glob.glob("/tmp/" + i + "/*.pcap")
		for pcap in pcapfiles:
			filename = pcap.split('/')[-1].split('_')
			appname  = filename[0]
			pcapnum  = filename[-2]
			print(appname)
			
			sp.geneTCPStream(pcap, appset.apptraindict[appname], i, pcapnum)


def disturbOfPhone(value, picsig):
	if not os.path.exists('/tmp/trainpic/'):
		os.makedirs('/tmp/trainpic/')

	for i in appset.phonelist:
		print(i)
		picsig *= 1000
		for j in range(11):
			list80, list443 = portLengthDisturb(i, value, picsig, random = 200)
			picsig += 10	



def drawHist(data, appnum, phonename, port, picsig):
	print(picsig)
	figure = plt.figure(picsig)

	ax = figure.add_subplot(1,1,1,position=[0.1,0.15,0.8,0.8])

    # ax.set_yticks(range(len(ylabels)))
    # ax.set_yticklabels(ylabels)
	# ax.set_xticks(range(11))
	# ax.set_xticklabels([x * 2 for x in range(11)])

	plt.xlabel("Pkg Length")
	plt.ylabel("per")

	plt.title(phonename + str(appnum) +  ': ' + str(port))
	plt.hist(data, bins = 100, normed = 0)

	plt.savefig('/tmp/trainpic/' + phonename + str(appnum) + '_' + str(port) + '_' + str(picsig) + '.jpg')


############################################################################
###                    Packets Length Disturb Part                       ###
############################################################################

###============= Separated by IP ===============###

def sepaByIP(phonename, value):
	ipdict = {}

	pcapfiles = glob.glob('/tmp/' + phonename + '/' + str(value) + '/*.pcap')

	for p in pcapfiles:
		pcaplength = os.path.getsize(p)

		if pcaplength > 150 and pcaplength < 2e+5:
			pkgs = scapy.rdpcap(p)

			srcip = repr(pkgs[0]['IP'].src).split('.')
			dstip = repr(pkgs[0]['IP'].dst).split('.')

			srckey = srcip[0][1:] + '.' + srcip[1]
			dstkey = dstip[0][1:] + '.' + dstip[1]

			ipkey = ''

			if srckey not in appset.localiplist:
				ipkey = srckey			
			elif dstkey not in appset.localiplist:
				ipkey = dstkey

			if ipkey == '':
				continue

			if ipkey not in ipdict:
				ipdict[ipkey] = [p]
			else:
				ipdict[ipkey].append(p)

	return ipdict


def geneDistubAccIP(ipdict, random = 0):
	list80All  = []
	list443All = []
	portdict = {}
	portfeat = {}

	for ipadd, plist in ipdict.items():
		if len(plist) > random * 3:
			print(ipadd)
			if random != 0:
				pcapfiles = sample(plist, random)

			for p in pcapfiles:
				pcaplength = os.path.getsize(p)
				pkgs = scapy.rdpcap(p)

				sport = pkgs[0]['TCP'].sport
				dport = pkgs[0]['TCP'].dport

				portkey = ''

				if sport < dport:
					portkey = sport
				else:			
					portkey = dport

				if portkey not in portdict:
					portdict[portkey] = []

				portdict[portkey].append((pcaplength, p))		

			if 80 in portdict:
				sum80  = len(portdict[80])
			if 443 in portdict:
				sum443 = len(portdict[443])

			feature80  = {}
			feature443 = {}

			list80  = [0.0 for x in range(80)]
			list443 = [0.0 for x in range(80)]

			if 80 in portdict:
				for f, g in groupby(sorted(portdict[80]), key = lambda x: (x[0] - 1) // 2500):
					tmpg = list(g)
					feature80[f] = len(tmpg)

				for n, m in feature80.items():
					list80[n] = float(m) / float(sum80)

			print(list80)

			if 443 in portdict:
				for f, g in groupby(sorted(portdict[443]), key = lambda x: (x[0] - 1) // 2500):
					tmpg = list(g)
					feature443[f] = len(tmpg)
				for n, m in feature443.items():
					list443[n] = float(m) / float(sum443)

			print(list443)

			list80All.append(list80)
			list443All.append(list443)

	print(list80All, list443All)

	return list80All, list443All



###=============================================###

def writeStateInfo(path):
	# print(path)
	os.system('tshark -r %s -T fields -e ssl.record.content_type -e ssl.handshake.type -Y ssl>"/tmp/report/test1.txt"' % path)

	with open('/tmp/report/test1.txt', 'r') as text:
		flow_state = ''
		for tls in text:
			# print(tls)
			tls = tls.rstrip().split('\t')
			if tls[0] == '':
				continue

			content_type = tls[0].split(',')

			if len(tls) > 1:
				handshake_type = tls[1].split(',')

				handshake_cnt = 0
				for ct in range(len(content_type)):
					if content_type[ct] == '22':
						content_type[ct] += ':' + handshake_type[handshake_cnt]
						handshake_cnt += 1

					if handshake_cnt >= len(handshake_type):
						break

			pkg_state = ','.join(content_type)

			if flow_state == '':
				flow_state = pkg_state
			else:
				flow_state += '-' + pkg_state

		# print(flow_state)

		return flow_state


def geneStateFea(features, flow_state):
	i = ''
	j = ''
	statechain = []
	stateindex = ['20', '21', '22', '22:0', '22:1', '22:2', '22:4', '22:11', '22:12', '22:13', '22:14', '22:15', '22:16', '22:20', '23']

	stateitems = flow_state.split('-')

	for item in stateitems:
		statechain.append(item.split(','))

	for s in range(len(statechain)):
		if s < len(statechain) - 1:
			for i in statechain[s]:
				for j in statechain[s + 1]:
					if i in stateindex and j in stateindex:
						features[stateindex.index(i)][stateindex.index(j)] += 1


def loadStatePath(paths):
	features = np.zeros(shape = [15, 15])
	pathlist = [x[3] for x in paths]
	fea_pro  = [0 for y in range(225)]

	for path in pathlist:
		flow_state = writeStateInfo(path)
		geneStateFea(features, flow_state)

	# print(features)

	cnt = np.sum(features)
	# print(cnt)

	features = list(features.reshape((-1,)))

	if cnt > 0:
		fea_pro = [float(y) / float(cnt) for y in features]
	# print(sum(fea_pro))

	return fea_pro


def DisturbbinSample(phonename, group, value, index):
	portdict = {}
	portpkgdict = {}

	# lengthstand = [1e+2, 3e+2, 4e+2, 6e+2, 1e+3, 5e+3, 1e+4, 2.5e+4, 1e+5, 1e+6]

	# pcapfiles = glob.glob('/tmp/' + phonename + '/' + str(value) + '/*.pcap')
	pcapfiles = []

	# if random != 0:
	# 	pcapfiles = sample(pcapfiles, random)
		# print(len(pcapfiles))

	with open("M_H_tcp_1/" + phonename + "/" + group + "/" + str(value) + "/tcplist" + str(index) + ".txt", "r") as f:
		for line in f:
			pcapfiles.append(line[:-1])

	for p in pcapfiles:
		pcaplength = os.path.getsize(p)
		# print(pcaplength)
		inlength = 0
		otlength = 0

		if 24 < pcaplength < 2 ** 25 - 1:
			# print('in place')
			pkgs = scapy.rdpcap(p)

			# for pkg in pkgs:
			# 	print(repr(pkg))

			portkey = ''

			if 'TCP' in pkgs[0]:
				sport = pkgs[0]['TCP'].sport
				dport = pkgs[0]['TCP'].dport

				if sport < dport:
					portkey = sport
				else:			
					portkey = dport

				if portkey not in portdict:
					portdict[portkey] = []
					pkgin = 0
					pkgot = 0
					portpkgdict[portkey] = [pkgin, pkgot]

				# tmplength = []
				# tmppkgin  = 0
				# tmppkgot = 0
				for pkg in pkgs:
					if 'TCP' in pkg:
						# tmplength.append(pkg['IP'].len)
						if pkg['TCP'].sport == portkey:
							inlength += pkg['IP'].len
							portpkgdict[portkey][0] += 1
						else:
							otlength += pkg['IP'].len
							portpkgdict[portkey][1] += 1

				# print(portpkgdict[portkey])

				# portpkgdict[portkey].extend(tmplength)
				# portpkgdict[portkey][0].extend(tmppkgin)
				# portpkgdict[portkey][1].extend(tmppkgin)
				inavarage = 0
				otavarage = 0

				if portpkgdict[portkey][0] != 0:
					inavarage = inlength // float(portpkgdict[portkey][0])

				if portpkgdict[portkey][1] != 0:
					otavarage = otlength // float(portpkgdict[portkey][1])
				

				portdict[portkey].append((pcaplength, inavarage, otavarage, p))
				

				# print(portdict)

	# if 80 in portdict:
	# 	sum80  = len(portdict[80])
	# if 443 in portdict:
	# 	sum443 = len(portdict[443])S

	feature80  = {}
	feature80pkg = {}

	feature443 = {}
	feature443pkg = {}

	finalfea80 = []
	finalfea443 = []
	# statefea = [0.0 for x in range(225)]

	for i in [1, 2]:

		list80  = [0 for x in range(25)]
		list443 = [0 for x in range(25)]

		# if 80 in portdict:
		# 	# print(sorted(portdict[80]))
		# 	for f, g in groupby(sorted(portdict[80], key = lambda y: y[i]), key = lambda x: int(math.log(x[i] + 1, 2))):
		# 		# print(f, list(g))
		# 		tmpg = list(g)
		# 		# print(f, tmpg)
		# 		# tmplist.append((f, tmpg))
		# 		feature80[f] = len(tmpg)
		# 		# feature802nd[f] = [tup[1] for tup in tmpg]			# feature802nd[f] = list(g)[0]
		# 	sum80 = 0
		# 	for s in feature80.values():
		# 		sum80 += s

		# 	for n, m in feature80.items():
		# 		list80[n] = float(m) / float(sum80)


		# 	# print(sum(list80))
		# 	# print(sum80)
		# 	# print(msum)


		# finalfea80.extend(list80[5:])



		# print(list80)
		if 443 in portdict:
			for f, g in groupby(sorted(portdict[443], key = lambda y: y[i]), key = lambda x:  int(math.log(x[i] + 1, 2))):
				# print(f, list(g))
				tmpg = list(g)
				# print(f, tmpg)
				feature443[f] = len(tmpg)

				# feature4432nd[f] = [tup[1] for tup in tmpg]

			sum443 = 0
			for s in feature443.values():
				sum443 += s

			for n, m in feature443.items():
				list443[n] = float(m) / float(sum443)

			# print(len(list443))



		finalfea443.extend(list443[5:])
		# print(finalfea443)


	# if 443 in portdict:
	# 	# print(sorted(portdict[443]))
	# 	for tup in portdict[443]:
	# 		writeStateInfo(tup[3])

	# 	statefea = loadStatePath(portdict[443])
	# print(list443)

	# finalfea80pkg = []
	# finalfea443pkg = []

	# for i in [0, 1]:

	# 	list80pkg  = [0 for x in range(25)]
	# 	list443pkg = [0 for x in range(25)]

	# 	if 80 in portdict:
	# 		for f, g in groupby(sorted(portpkgdict[80][i]), key = lambda x: int(math.log(x + 1, 2))):
	# 			tmpg = list(g)
	# 			feature80pkg[f] = len(tmpg)

	# 		sum80 = 0
	# 		for s in feature80pkg.values():
	# 			sum80 += s

	# 		for n, m in feature80pkg.items():
	# 			list80pkg[n] = float(m) / float(sum80)

	# 	if 443 in portdict:
	# 		for f, g in groupby(sorted(portpkgdict[443][i]), key = lambda x: int(math.log(x + 1, 2))):
	# 			tmpg = list(g)
	# 			feature443pkg[f] = len(tmpg)

	# 		sum443 = 0
	# 		for s in feature443pkg.values():
	# 			sum443 += s

	# 		for n, m in feature443pkg.items():
	# 			list443pkg[n] = float(m) / float(sum443)

	# 	print(sum(list80pkg))
	# 	print(sum(list443pkg))

	# 	finalfea80pkg.extend(list80pkg[5:])
	# 	finalfea443pkg.extend(list443pkg[5:])

	# return finalfea80pkg, finalfea443pkg #, statefea
	# return finalfea80, finalfea443
	return finalfea443#, statefea
	# return statefea


def portLengthDisturbbin(phonename, value, random = 0):
	portdict = {}
	portpkgdict = {}

	# lengthstand = [1e+2, 3e+2, 4e+2, 6e+2, 1e+3, 5e+3, 1e+4, 2.5e+4, 1e+5, 1e+6]

	pcapfiles = glob.glob('/tmp/' + phonename + '/' + str(value) + '/*.pcap')

	if random != 0:
		pcapfiles = sample(pcapfiles, random)
		# print(len(pcapfiles))

	for p in pcapfiles:
		pcaplength = os.path.getsize(p)
		# print(pcaplength)
		inlength = 0
		otlength = 0

		if 114 < pcaplength < 2 ** 25 - 1:
			# print('in place')
			pkgs = scapy.rdpcap(p)

			# for pkg in pkgs:
			# 	print(repr(pkg))

			portkey = ''

			if 'TCP' in pkgs[0]:
				sport = pkgs[0]['TCP'].sport
				dport = pkgs[0]['TCP'].dport

				if sport < dport:
					portkey = sport
				else:			
					portkey = dport

				if portkey not in portdict:
					portdict[portkey] = []
					portpkgdict[portkey] = []

				tmplength = []
				for pkg in pkgs:
					if 'TCP' in pkg:
						tmplength.append(pkg['IP'].len)
						if pkg['TCP'].sport == portkey:
							inlength += pkg['IP'].len
						else:
							otlength += pkg['IP'].len

				portpkgdict[portkey].extend(tmplength)
				portdict[portkey].append((pcaplength, inlength, otlength, p))
				

				# print(portdict)

	# if 80 in portdict:
	# 	sum80  = len(portdict[80])
	# if 443 in portdict:
	# 	sum443 = len(portdict[443])

	feature80  = {}
	feature80pkg = {}

	feature443 = {}
	feature443pkg = {}

	finalfea80 = []
	finalfea443 = []
	# statefea = [0.0 for x in range(225)]

	for i in [1, 2]:

		list80  = [0 for x in range(25)]
		list443 = [0 for x in range(25)]

		if 80 in portdict:
			# print(sorted(portdict[80]))
			for f, g in groupby(sorted(portdict[80], key = lambda y: y[i]), key = lambda x: int(math.log(x[i] + 1, 2))):
				# print(f, list(g))
				tmpg = list(g)
				# print(f, tmpg)
				# tmplist.append((f, tmpg))
				feature80[f] = len(tmpg)
				# feature802nd[f] = [tup[1] for tup in tmpg]			# feature802nd[f] = list(g)[0]
			sum80 = 0
			for s in feature80.values():
				sum80 += s

			for n, m in feature80.items():
				list80[n] = float(m) / float(sum80)


			print(sum(list80))
			print(sum80)
			print(msum)


		finalfea80.extend(list80[5:])



		# print(list80)
		if 443 in portdict:
			for f, g in groupby(sorted(portdict[443], key = lambda y: y[i]), key = lambda x:  int(math.log(x[i] + 1, 2))):
				# print(f, list(g))
				tmpg = list(g)
				# print(f, tmpg)
				feature443[f] = len(tmpg)

				# feature4432nd[f] = [tup[1] for tup in tmpg]

			sum443 = 0
			for s in feature443.values():
				sum443 += s

			for n, m in feature443.items():
				list443[n] = float(m) / float(sum443)



		finalfea443.extend(list443[5:])


	# if 443 in portdict:
	# 	# print(sorted(portdict[443]))
	# 	for tup in portdict[443]:
	# 		writeStateInfo(tup[3])

	# 	statefea = loadStatePath(portdict[443])
	# print(list443)

	# list80pkg  = [0 for x in range(25)]
	# list443pkg = [0 for x in range(25)]

	# if 80 in portdict:
	# 	for f, g in groupby(sorted(portpkgdict[80]), key = lambda x: int(math.log(x + 1, 2))):
	# 		tmpg = list(g)
	# 		feature80pkg[f] = len(tmpg)

	# 	sum80 = 0
	# 	for s in feature80pkg.values():
	# 		sum80 += s

	# 	for n, m in feature80pkg.items():
	# 		list80pkg[n] = float(m) / float(sum80)

	# if 443 in portdict:
	# 	for f, g in groupby(sorted(portpkgdict[443]), key = lambda x: int(math.log(x + 1, 2))):
	# 		tmpg = list(g)
	# 		feature443pkg[f] = len(tmpg)

	# 	sum443 = 0
	# 	for s in feature443pkg.values():
	# 		sum443 += s

	# 	for n, m in feature443pkg.items():
	# 		list443pkg[n] = float(m) / float(sum443)

	# print(sum(list80pkg))
	# print(sum(list443pkg))

	# return list80pkg[5:], list443pkg[5:] #, statefea
	return finalfea80, finalfea443
	# return statefea



###============= Separated by Port and ===============###
###================= Length Disturb ==================###

def portLengthDisturb(phonename, value, random = 0):
	portdict = {}
	portfeat = {}

	ipsetdict = {}

	# lengthstand = [1e+2, 3e+2, 4e+2, 6e+2, 1e+3, 5e+3, 1e+4, 2.5e+4, 1e+5, 1e+6]

	pcapfiles = glob.glob('/tmp/' + phonename + '/' + str(value) + '/*.pcap')

	if random != 0:
		pcapfiles = sample(pcapfiles, random)
		print(len(pcapfiles))

	for p in pcapfiles:
		pcaplength = os.path.getsize(p)

		if pcaplength > 150 and pcaplength < 2e+5:
			pkgs = scapy.rdpcap(p)

			# for r in pkgs:
			# 	r = TLS(r['TCP'].payload)
			# 	r.show()

			# srcip = repr(pkgs[0]['IP'].src).split('.')
			# dstip = repr(pkgs[0]['IP'].dst).split('.')

			# srckey = srcip[0][1:] + '.' + srcip[1]
			# dstkey = dstip[0][1:] + '.' + dstip[1]

			# ipkey = ''
			# print(srckey)
			# print(dstkey)
			# print(appset.localiplist)
			# if srckey not in appset.localiplist:
			# 	# print('not in')
			# 	ipkey = srckey			
			# elif dstkey not in appset.localiplist:
			# 	# print('in')
			# 	ipkey = dstkey

			# print(ipkey)
			# print(p)
			# print("+++++++++++")

			# if ipkey == '':
			# 	continue

			# if ipkey not in ipsetdict:
			# 	ipsetdict[ipkey] = 1
			# else:
			# 	ipsetdict[ipkey] += 1


			sport = pkgs[0]['TCP'].sport
			dport = pkgs[0]['TCP'].dport

			portkey = ''

			if sport < dport:
				portkey = sport
			else:			
				portkey = dport

			if portkey not in portdict:
				portdict[portkey] = []

			# flag = 0
			# for l in range(len(lengthstand)):
			# 	if pcaplength < lengthstand[l]:
			# 		portdict[portkey][l] += 1
			# 		flag = 1

			# if flag == 0:
			# 	portdict[portkey][-1] += 1

			portdict[portkey].append((pcaplength, p))
			# print(portdict)

	# if 80 in portdict:
	# 	drawHist([x[0] for x in portdict[80]] , value, phonename, 80, picsig * 10 + 1)
	# if 443 in portdict:
	# 	drawHist([x[0] for x in portdict[443]], value, phonename, 443, picsig * 10 + 2)

	# data = sorted(ipsetdict.items(), key = lambda x : x[1], reverse = True)
	# print(data)
	# namelist = [n[0] for n in data]
	# datalist = [n[1] for n in data]
	# rantitle = randint(1000, 5000)
	# fig = plt.figure(rantitle)
	# plt.bar(range(len(namelist)), datalist, tick_label = namelist)
	# plt.xlabel('xlabel', fontsize = 10)
	# plt.xticks(rotation = 90)
	# plt.savefig('/tmp/trainpic/' + str(phonename) + '_' + str(value) + '_' + str(rantitle) + '.jpg')

	if 80 in portdict:
		sum80  = len(portdict[80])
	if 443 in portdict:
		sum443 = len(portdict[443])

	feature80  = {}
	feature802nd = {}

	feature443 = {}
	feature4432nd = {}

	list80  = [0.0 for x in range(80)]
	list443 = [0.0 for x in range(80)]
	statefea = [0.0 for x in range(225)]

	if 80 in portdict:
		# print(sorted(portdict[80]))
		for f, g in groupby(sorted(portdict[80]), key = lambda x: (x[0] - 1) // 2500):
			# print(f, list(g))
			tmpg = list(g)
			# print(tmpg)
			feature80[f] = len(tmpg)
			# feature802nd[f] = [tup[1] for tup in tmpg]			# feature802nd[f] = list(g)[0]

		for n, m in feature80.items():
			list80[n] = float(m) / float(sum80)

	# print(list80)

	if 443 in portdict:
		# print(sorted(portdict[443]))
		for tup in portdict[443]:
			writeStateInfo(tup[1])

		for f, g in groupby(sorted(portdict[443]), key = lambda x: (x[0] - 1) // 2500):
			# print(f, list(g))
			tmpg = list(g)
			feature443[f] = len(tmpg)
			# feature4432nd[f] = [tup[1] for tup in tmpg]
		for n, m in feature443.items():
			list443[n] = float(m) / float(sum443)

		statefea = loadStatePath(portdict[443])
	# print(list443)

	return list80, list443, statefea
	# return feature802nd, feature4432nd

	# if not os.path.exists('/tmp/trainpic/'):
	# 	os.makedirs('/tmp/trainpic/')

	# portcnt = 0
	# for k, v in portdict.items():
	# 	picsig = piccnt * 10 + portcnt

	# 	figure = plt.figure(picsig)

	# 	ax = figure.add_subplot(1,1,1,position=[0.1,0.15,0.8,0.8])

	#     # ax.set_yticks(range(len(ylabels)))
	#     # ax.set_yticklabels(ylabels)
	# 	# ax.set_xticks(range(11))
	# 	# ax.set_xticklabels([x * 2 for x in range(11)])

	# 	plt.xlabel("Pkg Length")
	# 	plt.ylabel("per")

	# 	plt.title(str(piccnt) + ': ' + str(k))
	# 	print(len(v))

	# 	plt.hist(v, bins = 100, normed = 0)

	# 	plt.savefig('/tmp/trainpic/' + str(picsig) + '_' + str(k) + '.jpg')

	# 	portcnt += 1


	# return portfeat



def pkgLengthDisturb(feature2nd):
	fea2nddict = {}

	for k, v in feature2nd.items():
		fea2nd = [0 for x in range(17)]
		# pkgsum = 0

		for add in v:
			pkgs = scapy.rdpcap(add)
			# pkgsum += len(pkgs)

			for p in pkgs:
				# print(repr(p))
				if 'TCP' in p:
					ploadlen = len(p['TCP'].payload)
					print(ploadlen)

					for i in range(17):
						if 2 ** i - 1 <= ploadlen < 2 ** (i + 1) - 1:
							fea2nd[i] += 1
		if sum(fea2nd) != 0:
			fea2ndratio = [float(y) / float(sum(fea2nd)) for y in fea2nd]
			print(fea2nd)
			fea2nddict[k] = fea2ndratio
		else:
			fea2nddict[k] = [0.0 for x in range(17)]

		return fea2nddict


def toCSV(csvdict, csvheader, appnum, csvname, trainlist):
	csvlist = []
	# print(csvheader)
	for train in trainlist:	
		for j in appnum:
			csvitem = []
			for g in csvheader:
				csvitem.append(csvdict[(train[1], g)][j]["tpr"])
				csvitem.append(csvdict[(train[1], g)][j]["fpr"])
			csvlist.append(csvitem)

	with open("csv/" + csvname + ".csv", "w") as f:
		f_csv = csv.writer(f)
		f_csv.writerow(csvheader)
		f_csv.writerows(csvlist)




########################################
##       Machine Learning Model       ##
########################################

def trainModel(X, y, modelname):
	# columnSum = np.sum(X, axis = 0)
	# columnDel = []

	# for i in range(X.shape[1]):
	# 	if columnSum[i] == 0:
	# 		columnDel.append(i)

	# X = np.delete(X, columnDel, axis = 1)

	print(X.shape)
	print(y.shape)

	###============ Random Forest ============###

	rfh = RFmul(X, y)
	rfh.rfStart()
	print(rfh.ascore)
	print(rfh.getPR())
	print("trainset test")
	print(rfh.testByTrainset())

	rfh.saveModel(modelname)

	###=============== KNeigh ================###

	# kneigh = KNeigh(X, y)
	# kneigh.exekNN()

	# kneigh.saveModel(modelname)



def testModel(X, y, modelname, appnum):
	# columnSum = np.sum(X, axis = 0)
	# columnDel = []

	# for i in range(X.shape[1]):
	# 	if columnSum[i] == 0:
	# 		columnDel.append(i)

	# X = np.delete(X, columnDel, axis = 1)

	scoredict = {
		2:  {"tpr" : 0, "fpr" : 0},
		4:  {"tpr" : 0, "fpr" : 0},
		8:  {"tpr" : 0, "fpr" : 0},
		9:  {"tpr" : 0, "fpr" : 0},
		11: {"tpr" : 0, "fpr" : 0},
	}


	with open('pickles/' + modelname + '.pickle', 'rb') as fr:
		new_clf = pickle.load(fr)
		# pro_res = new_clf.predict_proba(filtered_fea_X)
		pre_res = new_clf.predict(X)
		print(pre_res.shape)
		# pro_res = new_clf.predict_proba(X)

		# acu = accuracy_score(y, pre_res)
		precision = precision_score(y, pre_res, average = 'weighted')
		recall = recall_score(y, pre_res, average = 'weighted')

		# maxindex = np.argmax(pro_res, axis = 1)
		# bin_res = np.zeros(pro_res.shape)
		# for i in range(maxindex.shape[0]):
		# 	bin_res[i][maxindex[i]] = 1

		bin_y_tru = np.zeros((y.shape[0], len(appnum)))
		bin_y_pre = np.zeros((y.shape[0], len(appnum)))


		for i in range(y.shape[0]):
			bin_y_tru[i][appnum.index(y[i])] = 1
			bin_y_pre[i][appnum.index(pre_res[i])] = 1

		for j in range(len(appnum)):
			p = np.sum(bin_y_tru[:, j])
			n = bin_y_tru.shape[0] - p

			tp = np.logical_and(bin_y_tru[:, j], bin_y_pre[:, j])
			fp = 0
			for k in range(bin_y_tru.shape[0]):
				if bin_y_tru[k, j] == 0 and bin_y_pre[k, j] == 1:
					fp += 1


			# print(bin_y_tru[:, j])
			# print(bin_y_pre[:, j])

			# print(tp + 0)

			tpr = np.sum(tp + 0) / p
			fpr = fp / n

			scoredict[appnum[j]]["tpr"] = tpr
			scoredict[appnum[j]]["fpr"] = fpr

			print('%s tpr: %s' % (appnum[j], tpr))
			print('%s fpr: %s' % (appnum[j], fpr))

		return scoredict





		# fpr = [0 for x in range(len(appnum))]
		# tpr = [0 for x in range(len(appnum))]
		# roc = [0 for x in range(len(appnum))]

		# for j in range(len(appnum)):
		# 	tmp_fpr, tmp_tpr, _ = roc_curve(bin_y[:, j], pro_res[:, j])
		# 	# fpr[j] = list(tmp_fpr)
		# 	# tpr[j] = list(tmp_tpr)

		# 	plt.figure(j)
		# 	plt.plot(tmp_fpr, tmp_tpr)
		# 	plt.show()


		# print(acu)
		# print(precision, recall)



############################################
############################################



if __name__ == '__main__':
	# train_X = []
	# train_y = []

	# for k, v in appset.apptraindict.items():
	# 	print(k)
	# 	geneFlow(k)

	# 	lengthdict = sepaByPcapLength(k)
	# 	nowX, nowy = sepaByPkgLength(lengthdict, v)

	# 	train_X.extend(nowX)
	# 	train_y.extend(nowy)

	# 	fea, res = timePkgDisturb(k, v)
	# 	train_X.extend(fea)
	# 	train_y.extend(res)

	# trainModel(np.array(train_X), np.array(train_y), 'time_pkg_disturb')
	# trainModel(np.array(train_X), np.array(train_y), 'tcp_num_pkg_disturb')

	# test_X = []
	# test_y = []

	# for k, v in appset.apptestdict.items():
	# 	# geneFlow(k)

	# 	lengthdict = sepaByPcapLength(k)
	# 	nowX, nowy = sepaByPkgLength(lengthdict, v)

	# 	test_X.extend(nowX)
	# 	test_y.extend(nowy)

	# 	# fea, res = timePkgDisturb(k, v)
	# 	# test_X.extend(fea)
	# 	# test_y.extend(res)

	# # testModel(np.array(test_X), np.array(test_y), 'time_pkg_disturb')
	# testModel(np.array(test_X), np.array(test_y), 'tcp_num_pkg_disturb')

	# for k, v in appset.apptraindict.items():
	# 	classifyStream(k, v)


	# testfea80   = []
	# trainfea443 = []
	# testfea443  = []

	# train_values = []
	# test_values  = []


	################################

	trainnum = testnum = 150
	# # # # list2d80  = [[0.0 for y in range(17)] for x in range(100)]
	# # # # list2d443 = [[0.0 for y in range(17)] for x in range(100)]
	phonelist = ["M1"]
	# grouplist = ["A1C1", "A1C2", "A2C1", "A2C2", "B1C1", "B1C2", "B2C1", "B2C2"]
	grouplist = ["A1", "A2", "B1", "B2", "C1", "C2"]
	appnum =  [2, 4, 8, 9, 11]
	# # # picsig = 1
	# datadict = {
	# 	'meizu': [],               
	# 	'honor': [],
	# 	'lenovo': [],
	# 	# 'nexus': []
	# }

	datadict = {

		'H1':{
			'A1' : [],
			'A2' : [], 
			'B1' : [],
			'B2' : []
		},

		'M1':{
			'A1' : [],
			'A2' : [],
			'B1' : [],
			'B2' : []
		},

		'M2':{
			'A1' : [],
			'A2' : [],
			'B1' : [],
			'B2' : []
		}
	}

	# for i in appnum:
	# 	disturbOfPhone(i, picsig)
	# 	picsig += 1
	# for i in phonelist:
	# 	print(i)
		

	# 	for l in grouplist:
	# 		print(l)
	# 		trainfea80   = []
	# 		trainfea443  = []
	# 		train_state  = []
	# 		train_values = []

	# 		for j in appnum:
	# 			print(j)
	# 			for k in range(trainnum):
	# 				# print(k)			
	# 				# list80, list443 = portLengthDisturbbin(i, j, random = 100)
	# 				# statefea = portLengthDisturbbin(i, j, random = 100)
	# 				# statefea = DisturbbinSample(i, j, k)
	# 				# list80, list443 = DisturbbinSample(i, l, j, k)
	# 				list443 = DisturbbinSample(i, l, j, k)

	# 				# print(len(list80))
	# 				# print(len(list443))
	# 				# print(len(statefea))
			
	# 				# ipdict = sepaByIP(i, j)
	# 				# print(ipdict)
	# 				# list80, list443 = geneDistubAccIP(ipdict, random = 100)

	# 				# print(len(statefea))

	# 				# trainfea80.append(list80)
	# 				trainfea443.append(list443)
	# 				# train_state.append(statefea)
	# 				train_values.append(j)

	# 			# trainfea80.extend(list80)
				# trainfea443.extend(list443)
				# train_values.extend([j for x in range(len(list80))])

	# 	# for j in appnum:
	# 	# 	for k in range(trainnum):
	# 	# 		feature802nd, feature4432nd = portLengthDisturb(i, j, random = 200)
	# 	# 		fearatio80  = pkgLengthDisturb(feature802nd)
	# 	# 		print(fearatio80)
	# 	# 		print(type(fearatio80))
	# 	# 		fearatio443 = pkgLengthDisturb(feature4432nd)
	# 	# 		print(fearatio443)
	# 	# 		print(type(fearatio443))

	# 	# 		if fearatio80 is not None:
	# 	# 			for k, v in fearatio80.items():
	# 	# 				list2d80[k] = v

	# 	# 		if fearatio443 is not None:
	# 	# 			for k, v in fearatio443.items():
	# 	# 				list2d443[k] = v

	# 	# 		trainfea80.append(np.array(list2d80).reshape((-1, 1)))
	# 	# 		trainfea443.append(np.array(list2d443).reshape((-1, 1)))
	# 	# 		train_values.append(j)

	# 	# print(np.array(train_state).shape)

	# 	# datadict[i] = [np.array(train_state), np.array(train_values)]

	# 	###=========

	# 	# lengthfea = np.hstack((np.array(trainfea80), np.array(trainfea443)))

	# 	# complxfea = np.hstack((lengthfea, np.array(train_state)))

	# 	# datadict[i] = [complxfea, np.array(train_values)]

	# 	# np.savetxt('feature_bin_log_'+ i + '.txt', complxfea)

	# 	###=========

	# 	# datadict[i] = [np.array(train_state), np.array(train_values)]
	# 	# np.savetxt('feature_sta_final'+ i + '_persame.txt', datadict[i][0])

	# 	###=========

			# datadict[i][l] = [np.array(trainfea443), np.array(train_values)]
			# print(datadict[i][l][0].shape)
			# np.savetxt('M_H_tcp_' + i + l + '_pkg.txt', datadict[i][l][0])

		###=========

			# datadict[i][l] = [np.hstack((np.array(trainfea80), np.array(trainfea443))), np.array(train_values)]
			# print(datadict[i][l][0].shape)
			# np.savetxt('M_H_' + i + l + '.txt', datadict[i][l][0])


		###=========

		# datadict[i] = [np.hstack((np.array(trainfea80), np.array(trainfea443)))[:, :, 0], np.array(train_values)]

		###=========

		# ori_X = np.hstack((np.array(trainfea80), np.array(trainfea443)))
		# ori_y = np.array(train_values)

		# mtl = LMNNforkNN(ori_X, ori_y)
		# new_X = mtl.exeLMNN()

		# datadict[i] = [new_X, ori_y]

		###=========

		# print(i)
		# print(new_X)
		# print(ori_X)

		###===================================================###


	##################################
	##         read fea txt         ##
	##################################

	train_value = np.empty(0)
	# train_value = []
	# for i in appnum:
	# 	for j in range(150):
	# 		train_value.append(i)

	for k in phonelist:
		print(k)
		for l in grouplist:
			train_fea = np.loadtxt('M_H_' + k + l + '_stati_enc.txt')			
			print(l)
			# train_fea = np.hstack((np.loadtxt('feature_pkg_final' + k + '_5.txt'), np.loadtxt('feature_sta_final' + k + '_5.txt')))
			# train_fea = np.hstack((train_fea, np.loadtxt('feature_sess_final' + k + '_same.txt')))
			# datadict[k][l] = [train_fea, np.array(train_value)]
			train_value = np.loadtxt('M_H_' + k + l + '_stati_enc_y.txt')
			for i in range(len(train_value)):
				if np.isnan(train_value[i]):
					train_value[i] = train_value[i - 1]

		# datadict[k] = [np.loadtxt('feature_stati_final' + k + '_5.txt'), train_value]
			datadict[k][l] = [train_fea, train_value]




	##################################
	##        training switch       ##
	##################################


	# trainlist = [
	# 	('meizu', 'honor'),
	# 	('meizu', 'lenovo'),
	# 	# ('meizu', 'nexus'),
	# 	('honor', 'lenovo'),
	# 	# ('honor', 'nexus'),
	# 	# ('nexus', 'lenovo')
	# ]

	trainlist = [
		# ('M1', 'A1'),
		# ('M1', 'A2'),
		# ('M1', 'B1'),
		# ('M1', 'B2')
		# ('H1', 'C1'),
		# ('H1', 'C2')
		
		('H1', 'A1C1'),
		('H1', 'A1C2'),
		('H1', 'B1C1'),
		('H1', 'B1C2'),
		('H1', 'A2C1'),
		('H1', 'A2C2'),
		('H1', 'B2C1'),
		('H1', 'B2C2'),

	]


	doubletrainlist = ["A1","A2", "B1","B2"]


	###################################################
	##################### train 2 #####################
	###################################################


	# for tr in trainlist:
	# 	train_X = np.vstack((datadict[tr[0]][0], datadict[tr[1]][0]))
	# 	train_y = np.hstack((datadict[tr[0]][1], datadict[tr[1]][1]))

	# 	trainModel(train_X, train_y, tr[0] + '_fea_sess_final_same_' + tr[1])

	# for tr in phonelist:
	# 	for g in doubletrainlist:
	# 		train_X = np.vstack((datadict[tr][g][0], datadict[tr]["C2"][0]))
	# 		train_y = np.hstack((datadict[tr][g][1], datadict[tr]["C2"][1]))

	# 		trainModel(train_X, train_y, "M_H_" + tr + g + "C2_enc")


	###################################################
	##################### train 1 #####################
	###################################################

	# for tr in phonelist:
	# 	for g in grouplist:
	# 		# print(len(datadict[tr][g]))
	# 		train_X = datadict[tr][g][0]
	# 		train_y = datadict[tr][g][1]

	# 		trainModel(train_X, train_y, 'M_H_tcp_' + tr + g + '_pkg')


	###################################################
	###################### test 1 #####################
	###################################################

	csvdict = {}
	scoredict = {}
	csvheader = []

	for te in phonelist:
		for g in grouplist:
			print('test:')
			print(te)
			print(g)
			for tup in trainlist:
				print("train:")
				print("M_H_tcp_" + tup[0] + tup[1])
				# print(datadict[te][1].shape)
				# testModel(datadict[te][g][0], datadict[te][g][1], "M_H_" + tup[0] + tup[1], appnum)
				scoredict = testModel(datadict[te][g][0], datadict[te][g][1], "M_H_" + tup[0] + tup[1] + "_enc", appnum)
				csvdict[(tup[1], g)] = scoredict

			csvheader.append(g)

	toCSV(csvdict, csvheader, appnum, "train_H1_test_M1_stati_enc_1", trainlist)


	# for te in appset.phonelist:
	# 	print('test:')
	# 	print(te)
	# 	for tup in appset.phonelist:
	# 		print("train:")
	# 		print(tup + '_fea_pkg_final_persame')
	# 		print(datadict[te][1].shape)
	# 		testModel(datadict[te][0], datadict[te][1], tup + '_fea_pkg_final_persame', appnum)


	###################################################
	###################### test 2 #####################
	###################################################

	# for te in trainlist:
	# 	print('test:')

	# 	tset = appset.phonelist[trainlist.index(te)]
		
	# 	print("trian:")
	# 	print(tset + '_fea_stati_final')

	# 	print(te[0])
	# 	testModel(datadict[te[0]][0], datadict[te[0]][1], tset + '_fea_stati_final', appnum)

	# 	print(te[1])
	# 	testModel(datadict[te[1]][0], datadict[te[1]][1], tset + '_fea_stati_final', appnum)


	####################################



	# for i in appnum:
	# 	for j in range(testnum):
	# 		list80, list443 = portLengthDisturb('test_' + str(i), i * 1000 + j, random = 60)
	# 		testfea80.append(list80)
	# 		testfea443.append(list443)

	# 		test_values.append(i)

	# test_X  = np.hstack((np.array(testfea80), np.array(testfea443)))

	
	# testModel(test_X, np.array(test_values), 'tcpstream_disturb_2tr_nexus_100')




