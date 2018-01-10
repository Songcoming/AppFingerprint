#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2018-01-08 by r4mind

from sklearn.ensemble        import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics         import classification_report,  accuracy_score

from classifiers.plotEstimate import plotE

class RFmul:
	def __init__(self, X, y):
		self.X = X
		self.y = y

	def rfStart(self):
		train_X, test_X, train_y, test_y = train_test_split(self.X, self.y, test_size = 0.2, random_state = 0)
		clf = RandomForestClassifier(oob_score = True, random_state = 0)
		clf.fit(train_X, train_y)

		pre_res = clf.predict(test_X)
		pro_res = clf.predict_proba(test_X)

		print(classification_report(test_y, pre_res))
		print(accuracy_score(test_y, pre_res))

		pe = plotE(pro_res, test_y)
		pe.plotThreshold_perform()

