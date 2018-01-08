#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2017-12-26 by r4mind

import appset
import numpy  as np

from features.statistical  import statiFeature
from classifiers.SVCmulti  import SVCmul

from sklearn.preprocessing import MinMaxScaler

def appdata2fea():
	fea_X = np.empty(shape = [0, 54])
	fea_y = np.empty(shape = [1, 0 ])

	for k, v in appset.appdict.items():
		sf = statiFeature('/tmp/' + k + '.pcap', v)
		print(sf.X.shape)
		fea_X = np.vstack((fea_X, sf.X))
		fea_y = np.hstack((fea_y, sf.y))

	return fea_X, fea_y

def scaleFeature(features):
	scaler = MinMaxScaler()
	return scaler.fit_transform(features)

if __name__ == '__main__':
	fea_X, fea_y = appdata2fea()
	print(fea_X.shape)
	print(fea_y.shape)

	s_fea_X = scaleFeature(fea_X)
	svc_mul = SVCmul(s_fea_X, fea_y[0])
	svc_mul.svmStart()

