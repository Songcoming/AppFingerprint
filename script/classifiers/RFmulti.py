#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2018-01-08 by r4mind

from sklearn.ensemble          import RandomForestClassifier
from sklearn.model_selection   import train_test_split
from sklearn.metrics           import classification_report,  accuracy_score
from sklearn.feature_selection import SelectFromModel
from sklearn.decomposition     import PCA
from sklearn.metrics           import precision_score, recall_score

from classifiers.plotEstimate import plotE

import numpy as np
import matplotlib.pyplot as plt

import pickle

class RFmul:
	def __init__(self, X, y):
		self.X = X
		self.y = y

	def rfStart(self):

		# print(self.X, self.y)

		train_X, test_X, train_y, test_y = train_test_split(self.X, self.y, test_size = 0.2, random_state = 1)
		self.train_X = train_X
		self.train_y = train_y
		# clf = RandomForestClassifier(min_samples_leaf = 6, min_samples_split = 15, max_depth = 10, oob_score = True, random_state = 0)

		self.clf = RandomForestClassifier()

		self.clf.fit(train_X, train_y)

		# save model
		# with open("pickles/hw3finmodel.pickle", "wb") as fw:
		# 	pickle.dump(self.clf, fw)

		self.test_y = test_y

		pro_res = self.clf.predict_proba(test_X)
		self.pre_res = self.clf.predict(test_X)

		self.ascore = accuracy_score(test_y, self.pre_res)

		# self.precision = precision_score(test_y, pre_res, average = 'weighted')
		# self.recall = recall_score(test_y, pre_res, average = 'weighted')

		# print(ascore)
		# print(pre_res)

		# pe = plotE(pro_res, test_y)
		# pe.plotThreshold_perform()
		
		# return ascore

	def getPR(self):
		precision = precision_score(self.test_y, self.pre_res, average = 'weighted')
		recall = recall_score(self.test_y, self.pre_res, average = 'weighted')

		return precision, recall

	def saveModel(self, modelname):
		with open("pickles/" + modelname + ".pickle", "wb") as fw:
			pickle.dump(self.clf, fw)

	def testByTrainset(self):
		self.trainset_pre_res = self.clf.predict(self.train_X)
		trainset_ascore  = accuracy_score(self.train_y, self.trainset_pre_res)

		return trainset_ascore








