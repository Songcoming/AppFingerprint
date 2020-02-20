#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2020-01-21 by r4mind

from sklearn.ensemble import AdaBoostClassifier
from sklearn.model_selection   import train_test_split
from sklearn.metrics           import classification_report,  accuracy_score
from sklearn.metrics           import precision_score, recall_score

import pickle

class AdaBoost:
	def __init__(self, X, y):
		self.X = X
		self.y = y

	def adaStart(self):
		train_X, test_X, train_y, test_y = train_test_split(self.X, self.y, test_size = 0.1, random_state = 1)
		self.train_X = train_X
		self.train_y = train_y

		self.clf = AdaBoostClassifier()

		self.clf.fit(train_X, train_y)
		self.test_y = test_y

		pro_res = self.clf.predict_proba(test_X)
		self.pre_res = self.clf.predict(test_X)

		self.ascore = accuracy_score(test_y, self.pre_res)

	def getPR(self):
		precision = precision_score(self.test_y, self.pre_res, average = 'weighted')
		recall = recall_score(self.test_y, self.pre_res, average = 'weighted')

		return precision, recall

	def saveModel(self, modelname):
		with open("pickles/adaboost/" + modelname + ".pickle", "wb") as fw:
			pickle.dump(self.clf, fw)

	def testByTrainset(self):
		self.trainset_pre_res = self.clf.predict(self.train_X)
		trainset_ascore  = accuracy_score(self.train_y, self.trainset_pre_res)

		return trainset_ascore