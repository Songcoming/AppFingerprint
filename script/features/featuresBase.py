#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2018-10-26 by r4mind

import sys
sys.path.append("..")

import glob
import appset
import os
import math

import pretools.pcapfilter as pf
import pretools.seperator  as sp
import scapy_http.http     as HTTP

from features.statistical  import statiFeature
from features.contextual.contextualBase import contBase
from random import shuffle, sample
from itertools import groupby

import pandas as pd
import numpy  as np


class feaBase:
	def __init__(self, nowip):
		self.nowip = nowip
		self.flowpath = '/tmp/flow/'


	def getAPPPath(self, phname, grname, result):
		# self.srcpcap = '/tmp/' + srcpcap + '.pcap'
		self.result = result

		# self.filtedpcap = self.filter()
		self.filtedpcap = "../../../M_H/aff/for/enc/" + phname + grname + "_" + str(result) + "_aff_enc.pcap"

		if os.path.exists(self.filtedpcap):
			self.seperator(self.filtedpcap)


	def getStatisticalFea(self, ai):
		fh = sp.createFlowPD(self.bh, self.th, self.nowip)
		return statiFeature(fh, ai)

		# fh = sp.getStaticalPD(pn, gi, ai, i, self.nowip)
		# return statiFeature(fh, ai)
		

	def getFlowDisFea(self, ai):

		# 2019-12-10 by r4mind

		fh = sp.createFlowPD(self.bh, self.th, self.nowip)
		sf = statiFeature(fh, ai)

		return sf.getFlowProDistribution()


	def getTStampDisFea(self, ai):

		# 2019-12-17 by r4mind

		fh = sp.createFlowPD(self.bh, self.th, self.nowip)
		sf = statiFeature(fh, ai)

		return sf.getFlowTStamp()




	def getContextualFea(self):

		sp.createFlowFile(self.bh, self.flowpath, self.nowip, self.srcpcap)
		pcapfiles = glob.glob(self.flowpath + '/*.pcap')

		httpfealist = self.cbh.generateConFea(pcapfiles)

		print(httpfealist)


	def createCTFhandle(self):
		print("create handle")
		self.cbh = contBase()


	def getFullHTTPInfo(self):
		print("begin to get HTTP info")
		self.cbh.initHeaderInfo(self.filtedpcap)
		self.cbh.getHTTPHeaderInfo()


	def filter(self):
		return pf.filter(self.srcpcap)


	def seperator(self, filtedpcap):
		with open(filtedpcap, mode='rb') as sf:
			self.bh, self.th = sp.createBurst(sf)


##############TEST################
if __name__ == '__main__':

	def sampleFlowDict(flowlist, time, random):

		samlist = []

		for i in range(time):
			samlist.append(sample(flowlist, random))
			shuffle(flowlist)

		return samlist


	def geneFlowDistribution(samitem):
		disdict = {}
		for f, g in groupby(sorted(samitem), key = lambda x : int(x // 0.1)):
			tmpg = list(g)
			print(f, tmpg)
			disdict[f] = len(tmpg)

		return disdict





	feadict = {}
	valdict = {}

	fb = feaBase([b'\xc0\xa8\x02\x0c', b'\xc0\xa8\x02\x0d', b'\xc0\xa8\x02\x09'])

	for pn in appset.phonelist:
		print(pn)	
		flowdict = {2: [], 4: [], 8: [], 9: [], 11: []}	

		for gi in appset.grouplist:
			print(gi)
			# feadict[pn] = np.empty(shape = [0, 54])
			valdict[pn] = np.empty(0)
			for ai in appset.appindex:
				print(ai)				
				# print(i)

				fb.getAPPPath(pn, gi, ai)

				if ai == 92:
					tmpi = 9
				elif ai == 42:
					tmpi = 4
				else:
					tmpi = ai

				flowdict[tmpi].extend(list(fb.getTStampDisFea(tmpi)))

				print(flowdict[tmpi])

		samlist = []
		feaper = {2: [], 4: [], 8: [], 9: [], 11: []}

		for k, v in flowdict.items():
			samlist = sampleFlowDict(v, 10, 120)
			# print(samlist)
			print(k)

			disdict = {}
			for item in samlist:
				fealist = [0.0 for x in range(50)]
				disdict = geneFlowDistribution(item)
				# print(disdict)

				lensum = 0
				for s in disdict.values():
					lensum += s

				# print(lensum)

				for n, m in disdict.items():
					if n < 50:
						fealist[n] = float(m) / float(lensum)

				feaper[k].append(fealist)
				# print(fealist)

		feaperlist = []
		for con in feaper.values():
			feaperlist.extend(con)

		print(np.array(feaperlist).shape)

		np.savetxt("txt/" + pn + "_seg_stati_tstamp.txt", np.array(feaperlist))	





			# 	sfh = fb.getStatisticalFea(tmpi)
			# 	sfh.generateFea()

			# 	testX, testy = sfh.chooseLowwestFlow(5)
			# 	print(testX.shape)
			# 	feadict[pn] = np.vstack((feadict[pn], testX))
			# 	valdict[pn] = np.concatenate((valdict[pn], testy))

			# print(feadict[pn].shape)
			# print(valdict[pn].shape)

			# np.savetxt('../M_H_'+ pn + gi + '_stati_enc.txt', feadict[pn])
			# np.savetxt('../M_H_'+ pn + gi + '_stati_enc_y.txt', valdict[pn])


