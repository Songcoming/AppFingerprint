#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2018-10-31 by r4mind

import pretools.pcapfilter as pf
import pretools.seperator  as sp
import scapy.all as scapy
import numpy as np

from classifiers.RFmulti import RFmul
from sklearn.metrics     import precision_score, recall_score, accuracy_score
from matplotlib import pyplot as plt
from random import sample
from itertools import groupby

import pickle
import appset
import glob
import os

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


def portLengthDisturb(value, piccnt, random = 0):
	portdict = {}
	portfeat = {}

	# lengthstand = [1e+2, 3e+2, 4e+2, 6e+2, 1e+3, 5e+3, 1e+4, 2.5e+4, 1e+5, 1e+6]

	pcapfiles = glob.glob('/tmp/tcpstream/' + value + '/*.pcap')

	if random != 0:
		pcapfiles = sample(pcapfiles, random)

	for p in pcapfiles:
		pcaplength = os.path.getsize(p)

		if pcaplength > 150 and pcaplength < 2e+4:
			pkgs = scapy.rdpcap(p)

			# print(len(pkgs[0]['TCP'].payload))

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
	if 80 in portdict:
		sum80  = len(portdict[80])
	if 443 in portdict:
		sum443 = len(portdict[443])

	feature80  = {}
	feature802nd = {}

	feature443 = {}
	feature4432nd = {}

	list80  = [0.0 for x in range(100)]
	list443 = [0.0 for x in range(100)]

	if 80 in portdict:
		for f, g in groupby(sorted(portdict[80]), key = lambda x: (x[0] - 1) // 200):
			# print(f, list(g))
			feature80[f] = len(list(g))
			feature802nd[f] = [tup[1] for tup in list(g)]
		for n, m in feature80.items():
			list80[n] = float(m) / float(sum80)

	print(list80)

	if 443 in portdict:
		for f, g in groupby(sorted(portdict[443]), key = lambda x: (x[0] - 1) // 200):
			feature443[f] = len(list(g))
			feature4432nd[f] = [tup[1] for tup in list(g)]
		for n, m in feature443.items():
			list443[n] = float(m) / float(sum443)

	print(list443)

	return list80, list443

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
	for k, v in feature2nd.items():
		fea2nd = [0 for x in range(17)]
		pkgsum = 0

		for add in v:
			pkgs = scapy.rdpcap(add)
			pkgsum += len(pkgs)

			for p in pkgs:
				ploadlen = len(p['TCP'].payload)

				for i in range(17):
					if ploadlen < 2 ** i:
						fea2nd[i] += 1

		fea2ndratio = [float(y) / float(pkgsum) for y in fea2nd]
		print(fea2ndratio)





def trainModel(X, y, modelname):
	# columnSum = np.sum(X, axis = 0)
	# columnDel = []

	# for i in range(X.shape[1]):
	# 	if columnSum[i] == 0:
	# 		columnDel.append(i)

	# X = np.delete(X, columnDel, axis = 1)

	print(X.shape)
	print(y.shape)

	rfh = RFmul(X, y)
	rfh.rfStart()
	print(rfh.ascore)
	print(rfh.getPR())
	print("trainset test")
	print(rfh.testByTrainset())

	rfh.saveModel(modelname)


def testModel(X, y, modelname):
	# columnSum = np.sum(X, axis = 0)
	# columnDel = []

	# for i in range(X.shape[1]):
	# 	if columnSum[i] == 0:
	# 		columnDel.append(i)

	# X = np.delete(X, columnDel, axis = 1)

	with open('pickles/' + modelname + '.pickle', 'rb') as fr:
		new_clf = pickle.load(fr)
		# pro_res = new_clf.predict_proba(filtered_fea_X)
		pre_res = new_clf.predict(X)

		acu = accuracy_score(y, pre_res)
		precision = precision_score(y, pre_res, average = 'weighted')
		recall = recall_score(y, pre_res, average = 'weighted')

		print(acu)
		print(precision, recall)



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

	# trainfea80  = []
	# testfea80   = []
	# trainfea443 = []
	# testfea443  = []

	# train_values = []
	# test_values  = []

	################################

	# trainnum = testnum = 100
	# appnum =  [2, 4, 7, 8, 9, 10, 11]
	# for i in appnum:
	# 	for j in range(trainnum):
	# 		list80, list443 = portLengthDisturb(str(i), i * 1000 + j, random = 200)
	# 		trainfea80.append(list80)
	# 		trainfea443.append(list443)

	# 		train_values.append(i)

	##################################

	# print(len(trainfea80))
	# print(len(trainfea443))
	# print(len(train_values))

	# train_X = np.hstack((np.array(trainfea80), np.array(trainfea443)))

	# trainModel(train_X, np.array(train_values), 'tcpstream_disturb_2tr_nexus_100')


	# for i in appnum:
	# 	for j in range(testnum):
	# 		list80, list443 = portLengthDisturb('test_' + str(i), i * 1000 + j, random = 60)
	# 		testfea80.append(list80)
	# 		testfea443.append(list443)

	# 		test_values.append(i)

	# test_X  = np.hstack((np.array(testfea80), np.array(testfea443)))

	
	# testModel(test_X, np.array(test_values), 'tcpstream_disturb_2tr_nexus_100')

	classifyStream()



