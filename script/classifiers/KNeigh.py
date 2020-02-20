#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2019-03-19 by r4mind

from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics   import accuracy_score

import pickle

class KNeigh:
	def __init__(self, X, y):
		self.X = X
		self.y = y

	def exekNN(self):
		self.neigh = KNeighborsClassifier(n_neighbors = 3)
		self.neigh.fit(self.X, self.y)

	def getPrediction(self, test_X, test_y):
		pre_y = self.neigh.predict(test_X)
		ascore = accuracy_score(test_y, pre_y)

		print(ascore)
		return ascore

	def saveModel(self, modelname):
		with open("pickles/" + modelname + ".pickle", "wb") as fw:
			pickle.dump(self.neigh, fw)