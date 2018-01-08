#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2017-12-23 by r4mind

import sys
sys.path.append("..")

import pretools.pcapfilter as pf
import pretools.seperator  as sp

import pandas as pd
import numpy  as np

class statiFeature:

	def __init__(self, srcpcap, result):
		self.srcpcap = srcpcap

		self.filtedpcap      = self.__filter()
		print(self.filtedpcap)
		self.tmphandle  = self.__seperator(self.filtedpcap)

		bins = self.getbiSeries()
		ins  = self.getinSeries()
		outs = self.getoutSeries()

		tmp1   = pd.merge(bins, ins,  left_index = True, right_index = True, how = "left")
		tmp2   = pd.merge(tmp1, outs, left_index = True, right_index = True, how = "left")

		self.X = tmp2.fillna(0).values
		self.y = np.ones((1, self.X.shape[0])) * result

	def getbiSeries(self):
		self.pkghandle  = self.tmphandle.groupby(["Burst", "Flow"])

		X = self.__pkg2sta()
		# y = np.ones((1, self.X.shape[0])) * result
		return X

	def getinSeries(self):
		# self.pkghandle = self.__seperator(self.filtedpcap).groupby(["Burst", "Flow", "Inorout"])
		self.pkghandle = self.tmphandle[self.tmphandle.Inorout == 0].groupby(["Burst", "Flow"])
		X = self.__pkg2sta()

		return X

	def getoutSeries(self):
		# self.pkghandle = self.__seperator(self.filtedpcap).groupby(["Burst", "Flow", "Inorout"])
		self.pkghandle = self.tmphandle[self.tmphandle.Inorout == 1].groupby(["Burst", "Flow"])
		X = self.__pkg2sta()

		return X

		# for i in range(3):
		# 	self.pkghandle = tmphandle[i].groupby(["Burst", "Flow"])
		# 	X = self.__pkg2sta()
		# 	self.X = np.hstack((self.X, X))

		# self.y = np.ones((1, self.X.shape[0])) * result

	def getMean(self):
		return self.pkghandle.mean()

	def getMinimum(self): 
		return self.pkghandle.min()

	def getMaximum(self):
		return self.pkghandle.max()

	def getMAD(self):
		return self.pkghandle.mad()

	def getStandard(self):
		return self.pkghandle.std().fillna(0)

	def getVariance(self):
		return self.pkghandle.var().fillna(0)

	def getSkew(self):
		return self.pkghandle.skew().fillna(0)

	def getKurtosis(self):
		return self.pkghandle.apply(pd.DataFrame.kurt).fillna(0)

	def getPercentiles(self, q):
		return self.pkghandle.quantile(q)

	def getCount(self):
		return self.pkghandle.count()

	def visiBursts(self, filtedpcap, dstpath):
		with open(filtedpcap, mode='rb') as sf:
			bh = sp.createBurst(sf)
			fh = sp.createFlow(bh, dstpath)
		return fh

	def __filter(self):
		return pf.filter(self.srcpcap)

	def __seperator(self, filtedpcap):
		with open(filtedpcap, mode='rb') as sf:
			bh = sp.createBurst(sf)
			fh = sp.createFlowPD(bh)
		return fh

	def __pkg2sta(self):
		X = pd.DataFrame({
			'mean' : self.getMean()['Length'],
			'min'  : self.getMinimum()['Length'],
			'max'  : self.getMaximum()['Length'],
			'mad'  : self.getMAD()['Length'],
			'std'  : self.getStandard()['Length'],
			'var'  : self.getVariance()['Length'],
			'skew' : self.getSkew()['Length'],
			'kurt' : self.getKurtosis()['Length'],
			'p10'  : self.getPercentiles(.1)['Length'],
			'p20'  : self.getPercentiles(.2)['Length'],
			'p30'  : self.getPercentiles(.3)['Length'],
			'p40'  : self.getPercentiles(.4)['Length'],
			'p50'  : self.getPercentiles(.5)['Length'],
			'p60'  : self.getPercentiles(.6)['Length'],
			'p70'  : self.getPercentiles(.7)['Length'],
			'p80'  : self.getPercentiles(.8)['Length'],
			'p90'  : self.getPercentiles(.9)['Length'],
			'count': self.getCount()['Length']
		})

		# y = np.ones((1, self.X.shape[0])) * result
		# print(y.shape)

		return X




