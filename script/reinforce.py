#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2018-07-11 by r4mind

import appset
import pickle

from sklearn.ensemble         import RandomForestClassifier
from sklearn.metrics          import classification_report,  accuracy_score
from sklearn.model_selection  import train_test_split
from sklearn.preprocessing    import MinMaxScaler
from sklearn.metrics          import accuracy_score

from classifiers.plotEstimate import plotE
from features.statistical     import statiFeature

import numpy as np
import matplotlib.pyplot as plt

def imdata():
	fea_X = np.empty(shape = [0, 9])
	fea_y = np.empty(shape = [1, 0])

	for k, v in appset.appdict.items():
		sf = statiFeature('/tmp/' + k + '.pcap', v, b'\xc0\xa8\x02\x03')

		fea_X = np.vstack((fea_X, sf.testLowwestF['testX']))
		fea_y = np.hstack((fea_y, sf.testLowwestF['testy']))

	s_fea_X = scaleFeature(fea_X)
	p_train_X, p_test_X, p_train_y, p_test_y = train_test_split(s_fea_X, fea_y[0], test_size = 0.5, random_state = 7)

	r_train_X = p_test_X
	r_train_y = createReinTrainSet(p_train_X, p_train_y, p_test_X, p_test_y)

	createReinClassifier(r_train_X, r_train_y)


def createReinTrainSet(p_train_X, p_train_y, p_test_X, p_test_y):
	clf = RandomForestClassifier()
	clf.fit(p_train_X, p_train_y)

	pre_res = clf.predict(p_test_X)
	cmpresult = (pre_res == p_test_y)

	return p_test_y * cmpresult


def createReinClassifier(r_train_X, r_train_y):
	r_ntrain_X, r_test_X, r_ntrain_y, r_test_y = train_test_split(r_train_X, r_train_y, test_size = 0.2, random_state = 77)

	rfc = RandomForestClassifier()
	rfc.fit(r_ntrain_X, r_ntrain_y)

	with open("reinforceSS.pickle", "wb") as fw:
			pickle.dump(rfc, fw)

	# pre_res = rfc.predict(r_test_X)
	# pro_res = rfc.predict_proba(r_test_X)

	# result = (pre_res == r_test_y) & (pre_res != 0)

	# print(np.sum(result) / np.sum(pre_res != 0))

	# pe = plotE(pro_res, r_test_y)
	# pe.plotThreshold_perform()


def scaleFeature(features):
	scaler = MinMaxScaler()
	return scaler.fit_transform(features)

if __name__ == '__main__':
	imdata()