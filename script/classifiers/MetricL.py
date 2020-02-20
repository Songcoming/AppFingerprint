#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2019-03-06 by r4mind

from metric_learn      import LMNN
from sklearn.neighbors import KNeighborsClassifier


class LMNNforkNN:
	def __init__(self, X, y):
		self.X = X
		self.y = y


	def exeLMNN(self, knum = 5):
		lmnn = LMNN(k = knum)
		X_new = lmnn.fit_transform(self.X, self.y)

		return X_new


		

