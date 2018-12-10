 #!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2018-04-06 by r4mind

import sys
sys.path.append("..")

import pretools.pcapfilter as pf
import pretools.seperator  as sp

import pandas as pd
import numpy  as np

class perflowFeature:

	def __init__(self, srcpcap, result):
		self.srcpcap = srcpcap
		self.result  = result

		self.filtedpcap = self.__filter()
		self.tmphandle  = self.__seperator(self.filtedpcap)
		self.pkghandle  = self.tmphandle.groupby(["Burst", "Flow"])

		self.lengthlist = self.pkghandle.count()['Length'].values

		self.X = {}
		self.y = {}

		self.genePerflowFea()


	def __filter(self):
		return pf.filter(self.srcpcap)

	def __seperator(self, filtedpcap):
		with open(filtedpcap, mode='rb') as sf:
			bh = sp.createBurst(sf)
			fh = sp.createFlowPD(bh)
		return fh

	def genePerflowFea(self):
		startpos  = 0
		pkglength = self.tmphandle['Length'].values.tolist()

		for flowlen in self.lengthlist:
			if not (flowlen in self.X.keys()):
				self.X[flowlen] = []
				self.y[flowlen] = []
			tmpslice = pkglength[startpos : startpos + flowlen]
			self.X[flowlen].append(tmpslice)
			self.y[flowlen].append(self.result)

			startpos += flowlen




