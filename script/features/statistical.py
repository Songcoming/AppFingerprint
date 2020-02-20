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

	def __init__(self, tmphandle, result):		
		self.tmphandle = tmphandle
		self.result = result

		# self.testLowwestF = {}
		self.features = None
		# self.testLowwestF = []


	# def inipcapfile(self, srcpcap, result):
	# 	self.srcpcap = srcpcap
	# 	self.result = result

	# 	self.filtedpcap = self.__filter()
	# 	print(self.filtedpcap)

	# 	self.tmphandle  = self.__seperator(self.filtedpcap, self.nowip)
	# 	# print(self.tmphandle)


	def generateFea(self):
		bins  = self.getbiSeries()
		ins   = self.getinSeries()
		outs  = self.getoutSeries()

		# print(bins.shape)
		# print(ins.shape)
		# print(outs.shape)
		# times = self.gettimeSeries()
 
		tmp1 = pd.merge(bins, ins,   left_index = True, right_index = True, how = "left")		
		tmp2 = pd.merge(tmp1, outs,  left_index = True, right_index = True, how = "left")
		
		# tmp3 = pd.merge(tmp2, times, left_index = True, right_index = True, how = "left")

		# print(tmp3.shape)

		if self.features is None:
			self.features = tmp2
		else:
			self.features = self.features.append(tmp2)

		# self.features = self.features.append(tmp2)

		# print(self.features.shape)
		# print(self.features)

		# ycur = pd.DataFrame(np.ones((tmp3.shape[0], 1)) * self.result, columns = ['yvalue'])
		# print(ycur)
		# if self.yvalue is None:
		# 	self.yvalue = ycur
		# else:
		# 	self.yvalue = self.yvalue.append(ycur)

		# print(self.yvalue.shape)

		self.namelist = self.features.columns.values
		# print(self.namelist)


		# tmp2.drop(['min_y', 'p50_y', 'p30_y', 'p20_y', 'skew', 'count', 'max', 'p90', 
		# 	'p60_x', 'p60_y', 'p70_y', 'p40_y', 'count_y', 'kurt', 'p80', 'kurt_y', 
		# 	'p60', 'kurt_x', 'skew_y', 'p80_y', 'var', 'p50', 'p70_x', 'p10_y', 'mad', 
		# 	'p70', 'mad_x', 'p30', 'std', 'p50_x', 'count_x', 'mean_y', 'p90_x', 'p30_x', 
		# 	'p40', 'p90_y', 'skew_x', 'std_x', 'mad_y', 'p80_x', 'p20', 'var_x', 'p20_x',
		# 	'p10', 'mean_x', 'var_y', 'p10_x', 'min', 'mean'], axis = 1, inplace = True)

		### tmp2.drop(['max', 'min', 'min_y', 'p40', 'p40_y', 'std', 'std_x', 'count', 'count_y'], axis = 1, inplace = True)
		# tmp2.drop(['min_y', 'skew', 'p30_y', 'count', 'p10_y', 'p20_y', 'p40_y', 'p50_y', 
		# 	'p60_y', 'p70_y', 'p80_y', 'p90_y', 'p10', 'p20', 'p30', 'p40', 'p50', 'p60', 
		# 	'p70', 'p80', 'p90', 'count_x', 'count_y', 'max'], axis = 1, inplace = True)
		# print(tmp2)

	def chooseLowwestFlow(self, lowwest):
		tmplist = self.features[self.features['count_x'] >= lowwest]
		# tmplist.drop(['count_x'], axis = 1, inplace = True)
		testX = tmplist.drop(['yvalue', 'yvalue_x', 'yvalue_y'], axis = 1).fillna(0).values
		print(testX.shape)
		testy = tmplist['yvalue'].values

		# print(testX.shape)
		# print(testy.shape)

		return testX, testy

		# self.testLowwestF['testX'] = self.features[self.features['count_x'] >= 34].fillna(0).values
		# # self.testLowwestF['testX'] = self.features.fillna(0).values
		# self.testLowwestF['testy'] = np.ones((1, self.testLowwestF['testX'].shape[0])) * result

		# self.X = tmp2.fillna(0).values
		# self.y = np.ones((1, self.X.shape[0])) * result

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

	def gettimeSeries(self):
		btimehandle = self.tmphandle.groupby(["Burst", "Flow", "UBurst"])
		# itimehandle = self.tmphandle[self.tmphandle.Inorout == 0].groupby(["Burst", "Flow", "UBurst"])
		# otimehandle = self.tmphandle[self.tmphandle.Inorout == 1].groupby(["Burst", "Flow", "UBurst"])

		buburstts = btimehandle.max() - btimehandle.min()
		# iuburstts = itimehandle.max() - itimehandle.min()
		# ouburstts = otimehandle.max() - otimehandle.min()

		flowtime = buburstts["TStamp"].groupby(["Burst", "Flow"]).sum()

		buburstdict = self.gettimeFeatures(buburstts, flowtime, "b")
		iuburstdict = self.gettimeFeatures(iuburstts, flowtime, "i")
		ouburstdict = self.gettimeFeatures(ouburstts, flowtime, "o")

		uburstdict = {}
		uburstdict.update(buburstdict)
		uburstdict.update(iuburstdict)
		uburstdict.update(ouburstdict)

		uburstdict["flowtime"] = flowtime
		uburstdict["yvalue"] = self.result

		return pd.DataFrame(uburstdict)


	def gettimeFeatures(self, uburstts, flowtime, bursttype):
		uburstdict = {}

		uburstdict[bursttype + "ubursttimemean"] = uburstts["TStamp"].groupby(["Burst", "Flow"]).mean()
		uburstdict[bursttype + "ubursttimemax"]  = uburstts["TStamp"].groupby(["Burst", "Flow"]).max()
		uburstdict[bursttype + "ubursttimemin"]  = uburstts["TStamp"].groupby(["Burst", "Flow"]).min()
		uburstdict[bursttype + "ubursttimestd"]  = uburstts["TStamp"].groupby(["Burst", "Flow"]).std().fillna(0)

		uburstdict[bursttype + "uburstlenmean"] = uburstts["Length"].groupby(["Burst", "Flow"]).mean()
		uburstdict[bursttype + "uburstlenmax"]  = uburstts["Length"].groupby(["Burst", "Flow"]).max()
		uburstdict[bursttype + "uburstlenmin"]  = uburstts["Length"].groupby(["Burst", "Flow"]).min()
		uburstdict[bursttype + "uburstlenstd"]  = uburstts["Length"].groupby(["Burst", "Flow"]).std().fillna(0)

		uburstdict[bursttype + "uburstcnt"]  = uburstts["TStamp"].groupby(["Burst", "Flow"]).count()

		uburstdict[bursttype + "uburstpersnd"]  = (uburstdict[bursttype + "uburstcnt"] / flowtime).replace([np.inf, -np.inf], np.nan).fillna(0)
		uburstdict[bursttype + "lenpersnd"] = (self.tmphandle.groupby(["Burst", "Flow"]).sum()["Length"] / flowtime).replace([np.inf, -np.inf], np.nan).fillna(0)

		return uburstdict

	def getFlowProDistribution(self):

		# 2019-12-10 by r4mind

		self.pkghandle = self.tmphandle.groupby(["Burst", "Flow"])

		return np.array(self.getMean()["Length"])


	def getFlowTStamp(self):

		# 2019-12-17 by r4mind
		
		tstamphandle = self.tmphandle.groupby(["Burst", "Flow"])
		flowlengthT = tstamphandle.max() - tstamphandle.min()
		# print(flowlengthT)

		return flowlengthT["TStamp"]


	def getSum(self):
		return self.pkghandle.sum()

	def getMean(self):
		return self.pkghandle.mean()

	def getMinimum(self): 
		return self.pkghandle.min()

	def getMaximum(self):
		return self.pkghandle.max()

	def getMAD(self):
		# print(self.pkghandle.mad())
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
		# print(self.pkghandle.count()['Length'])
		return self.pkghandle.count()

	def getMmm(self):
		return self.pkghandle.apply(lambda x : x.max() - x.min())

	def getSecond(self):
		return self.pkghandle.apply(self.__getNum, num = -2)

	def getThird(self):
		return self.pkghandle.apply(self.__getNum, num = -3)
	
	def getSecs(self):
		return self.pkghandle.apply(self.__getNum, num = 2)

	def getThirds(self):
		return self.pkghandle.apply(self.__getNum, num = 3)

	def getMms(self):
		return self.pkghandle.max()['Length'] - self.pkghandle.apply(self.__getNum, num = -2)

	def getSmm(self):
		return self.pkghandle.apply(self.__getNum, 2) - self.pkghandle.min()['Length']

	def getSmmsm(self):
		return self.pkghandle.apply(self.__getNum, -2) - self.pkghandle.apply(self.__getNum, 2)

	def getMmmedian(self):
		return self.pkghandle.max() - self.pkghandle.median()

	def getMedianmm(self):
		return self.pkghandle.median() - self.pkghandle.min()

	def getMedian(self):
		return self.pkghandle.median()

	def getMaxmper(self, q):
		return self.pkghandle.max()['Length'] - self.pkghandle.quantile(q)['Length']


	def visiBursts(self, filtedpcap, dstpath):
		with open(filtedpcap, mode='rb') as sf:
			bh = sp.createBurst(sf)
			fh = sp.createFlow(bh, dstpath)
		return fh

	def __getNum(self, x, num):
		# print(x['Length'])
		# print(x.max())
		a = sorted(list(set(x['Length'].values.tolist())))
		if len(a) < abs(num):
			# print(0.0)
			return 0.0
		else:
			if num < 0:
				return a[num]
			else:
				return a[num - 1]

	def __pkg2sta(self):
		X = pd.DataFrame({
			'mean'  : self.getMean()['Length']         ,
			'min'   : self.getMinimum()['Length']      ,
			'max'   : self.getMaximum()['Length']      ,
			'mad'   : self.getMAD()['Length']          , 
			'std'   : self.getStandard()['Length']     ,
			'var'   : self.getVariance()['Length']     ,
			'skew'  : self.getSkew()['Length']         ,
			'kurt'  : self.getKurtosis()['Length']     ,
			'p10'   : self.getPercentiles(.1)['Length'],
			'p20'   : self.getPercentiles(.2)['Length'],
			'p30'   : self.getPercentiles(.3)['Length'],
			'p40'   : self.getPercentiles(.4)['Length'],
			'p50'   : self.getPercentiles(.5)['Length'],
			'p60'   : self.getPercentiles(.6)['Length'],
			'p70'   : self.getPercentiles(.7)['Length'],
			'p80'   : self.getPercentiles(.8)['Length'],
			'p90'   : self.getPercentiles(.9)['Length'],
			'count' : self.getCount()['Length']        ,
			# 'mmm'   : self.getMmm()['Length']          ,
			'yvalue': self.result
			# 'second' : self.getSecond(),
			# 'third'  : self.getThird(),
			# 'seconds'  : self.getSecs(),
			# 'thirds'   : self.getThirds(),
			# 'mms'   : self.getMms(),
			# 'smm'   : self.getSmm(),
			# 'smmsm' : self.getSmmsm(),
			# 'median'  : self.getMedian()['Length'],
			# 'mmmed'   : self.getMmmedian()['Length'],
			# 'medmm'   : self.getMedianmm,
			# 'mm1': self.getMaxmper(.1),
			# 'mm2': self.getMaxmper(.2),
			# 'mm3': self.getMaxmper(.3),
			# 'mm4': self.getMaxmper(.4),
			# 'mm5': self.getMaxmper(.5),
			# 'mm6': self.getMaxmper(.6),
			# 'mm7': self.getMaxmper(.7),
			# 'mm8': self.getMaxmper(.8),
			# 'mm9': self.getMaxmper(.9),
		})

		# y = np.ones((1, self.X.shape[0])) * result
		# print(y.shape)
		# print(X)

		return X




