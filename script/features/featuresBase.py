#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2018-10-26 by r4mind

import sys
sys.path.append("..")

import glob

import pretools.pcapfilter as pf
import pretools.seperator  as sp
import scapy_http.http     as HTTP

from features.statistical  import statiFeature
from features.contextual.contextualBase import contBase

import pandas as pd
import numpy  as np


class feaBase:
	def __init__(self, nowip):
		self.nowip = nowip
		self.flowpath = '/tmp/flow/'


	def getAPPPath(self, srcpcap, result):
		self.srcpcap = '/tmp/' + srcpcap + '.pcap'
		self.result = result

		self.filtedpcap = self.filter()
		self.seperator(self.filtedpcap)


	def getStatisticalFea(self):
		fh = sp.createFlowPD(self.bh, self.th, self.nowip)
		return statiFeature(fh, self.result)


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
