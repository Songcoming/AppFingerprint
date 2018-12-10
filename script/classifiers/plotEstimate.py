#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2018-01-09 by r4mind

import matplotlib.pyplot as plt
import numpy as np

from sklearn.preprocessing   import label_binarize, binarize
from sklearn.metrics         import accuracy_score, precision_score, recall_score

class plotE:
	def __init__(self, pro_res, test_y):
		self.pro_res = pro_res
		self.test_y  = test_y

	def plotThreshold_perform(self):
		thresholdlist = np.array([x / 10 for x in range(10)])
		accuracylist  = np.zeros((10,))
		precisionlist = np.zeros((10,))
		recalllist    = np.zeros((10,))
		perunclaslist = np.zeros((10,))

		for i in range(10):
			result2d = binarize(self.pro_res, thresholdlist[i])
			# print(result2d)
			result1d, unclassified = self.__bin2one(result2d)
			print(result1d)
			# print(self.test_y)

			nozero_result1d, nozero_test_y = self.__filterZeros(result1d)
			print(nozero_result1d, nozero_test_y)

			accuracylist[i]  = accuracy_score(nozero_test_y, nozero_result1d)
			precisionlist[i] = precision_score(nozero_test_y, nozero_result1d, average=None)[1:].mean()
			recalllist[i]    = recall_score(nozero_test_y, nozero_result1d, average=None)[1:].mean()
			perunclaslist[i] = 1 - unclassified

		# print("p")
		# print(precisionlist)
		# print("r")
		# print(recalllist)
		# print("a")
		# print(accuracylist)

		plt.figure(3)
		lw = 2

		plt.plot(thresholdlist, accuracylist , lw=lw, label='accuracy')
		plt.plot(thresholdlist, precisionlist, lw=lw, label='precision')
		plt.plot(thresholdlist, recalllist   , lw=lw, label='recall')
		plt.plot(thresholdlist, perunclaslist, lw=lw, label='per of classified')

		plt.xlim([0.0, 0.95])
		plt.ylim([0.0, 1.05])
		plt.xlabel('Threshold')
		plt.ylabel('Classifier Performance')
		plt.legend(loc="lower right")
		plt.show()


	def __bin2one(self, result2d):
		result1d = []
		unclassified = 0
		row = 0

		for i in result2d:
			if sum(i) == 1:
				# added for reinforce test
				if i.shape[0] == 5 and i[0] == 1:
					result1d.append(0.0)
				else:
					for j in range(i.shape[0]):
						if i[j] == 1:
							# add for reinforce test
							if i.shape[0] == 5:
								result1d.append(j)
							else:
								result1d.append(j + 1)
							break
			elif sum(i) > 1:
				comparedict = {}

				for j in range(i.shape[0]):
					if i[j] == 1:
						comparedict[j] = self.pro_res[row][j]
				if i.shape[0] == 5:
					result1d.append(max(comparedict, key = comparedict.get)) 
				else:
					result1d.append(max(comparedict, key = comparedict.get) + 1)
			else:
				result1d.append(0.0)
				unclassified += 1

			row += 1

		return np.array(result1d), unclassified / len(result1d)


	def __filterZeros(self, result1d):
		nozero_result1d = []
		nozero_test_y = []

		for r in range(result1d.shape[0]):
			if result1d[r] != 0:
				nozero_result1d.append(result1d[r])
				nozero_test_y.append(self.test_y[r])

		return np.array(nozero_result1d), np.array(nozero_test_y)



