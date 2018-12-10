#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2018-04-12 by r4mind

from sklearn.ensemble        import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics         import classification_report,  accuracy_score
from sklearn import svm

from classifiers.plotEstimate import plotE

import numpy as np

class PFRFmul:
	def __init__(self, X, y):
		self.X = X
		self.y = y

	def pfrfStart(self):
		clfDict = {}
		test_X_dict = {}
		test_y_dict = {}

		pro_res_list = np.empty(shape = [0, 4])
		test_y_list  = np.empty(shape = [1, 0])

		for length, feature in self.X.items():
			feature = np.array(feature)
			value   = np.array(self.y[length])

			print(feature)
			print(value)

			train_X, test_X, train_y, test_y = train_test_split(feature, value, test_size = 0.2, random_state = 0)
			clf = RandomForestClassifier()
			# clf = svm.SVC()

			if feature.shape[0] >= 2:
				clf.fit(train_X, train_y)

				test_X_dict[length] = test_X
				test_y_dict[length] = test_y
			else:
				clf.fit(feature, value)

				test_X_dict[length] = feature
				test_y_dict[length] = value

			clfDict[length] = clf

		for length, feature in test_X_dict.items():
			# pre_res = clfDict[length].predict(feature)
			pro_res = clfDict[length].predict_proba(feature)

			if pro_res.shape[1] == 4:
				pro_res_list = np.vstack((pro_res_list, pro_res))
				test_y_list  = np.hstack((test_y_list , test_y_dict[length].reshape(1, -1)))

		pe = plotE(pro_res_list, test_y_list[0])
		pe.plotThreshold_perform()

			