#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2017-12-26 by r4mind

from sklearn import svm
from sklearn.decomposition   import PCA
from sklearn.model_selection import KFold, cross_val_score, cross_val_predict, train_test_split
from sklearn.preprocessing   import label_binarize, binarize
from sklearn.feature_selection import RFE
# from sklearn.multiclass      import OneVsRestClassifier   
from sklearn.metrics         import classification_report,  accuracy_score, roc_curve, auc, precision_score, recall_score

from classifiers.plotEstimate import plotE

import numpy as np
import matplotlib.pyplot as plt

class SVCmul:
	def __init__(self, X, y, namelist):
		self.X = X
		self.y = y
		self.namelist = namelist

	def svmStart(self):
		# train_X = self.X[:-100]
		# train_y = self.y[:-100]
		# test_X  = self.X[-100:]
		# test_y  = self.y[-100:]

		train_X, test_X, train_y, test_y = train_test_split(self.X, self.y, test_size = 0.2, random_state = 0)

		clf = svm.SVC(decision_function_shape='ovo', C = 3500, kernel='rbf', probability = True)
		rfe = RFE(estimator = clf, n_features_to_select = 57, step = 1)

		rfe.fit(train_X, train_y)

		rank = rfe.ranking_

		fea = np.arange(57)

		width = 0.5
		plt.bar(range(len(rank)), rank, width = width)

		plt.ylim([0.0, 1.75])

		plt.xlabel("feature")
		plt.ylabel("rank")

		plt.xticks(fea, self.namelist, fontsize = 5, rotation = 45)

		plt.show()
		# score_y = clf.fit(train_X, train_y)

		# pre_res = clf.predict(test_X)
		# pro_res = clf.predict_proba(test_X)

		# fpr = dict()
		# tpr = dict()
		# roc_auc = dict()
		# th = dict()

		# for i in range(n_classes):
		# 	fpr[i], tpr[i], th[i] = roc_curve(test_y_bin[:, i], pro_res[:, i])
		# 	roc_auc[i] = auc(fpr[i], tpr[i])

		# fpr["micro"], tpr["micro"], _ = roc_curve(test_y_bin.ravel(), pro_res.ravel())
		# roc_auc["micro"] = auc(fpr["micro"], tpr["micro"])

		# plt.figure(1)
		# lw = 2
		# for j in range(n_classes):
		# 	plt.plot(fpr[j], tpr[j],
		# 	         lw=lw, label='ROC curve (area = %0.2f)' % roc_auc[j])
		# plt.plot([0, 1], [0, 1], color='navy', lw=lw, linestyle='--')
		# plt.xlim([0.0, 1.0])
		# plt.ylim([0.0, 1.05])
		# plt.xlabel('False Positive Rate')
		# plt.ylabel('True Positive Rate')
		# plt.title('Receiver operating characteristic example')
		# plt.legend(loc="lower right")
		# plt.show()

		# plt.figure(2)
		# for k in range(n_classes):
		# 	plt.plot(th[k], tpr[k], lw=lw, label='tpr %s' % str(k))
		# plt.xlim([0.0, 1.0])
		# plt.ylim([0.0, 1.05])
		# plt.xlabel('th')
		# plt.ylabel('True Positive Rate')
		# plt.legend(loc="lower right")
		# plt.show()

		# pe = plotE(pro_res, test_y)
		# pe.plotThreshold_perform()

		# print(pro_res)

		# print(classification_report(test_y, pre_res))
		# print(accuracy_score(test_y, pre_res))


	# def getThresholdedData(self, threshold, pro_res):
	# 	result2d = np.zeros(pro_res.shape)

	# 	for row in range(pro_res.shape[0]):
	# 		for col in range(pro_res.shape[1]):
	# 			if pro_res[row][col] < threshold:
	# 				result2d[row][col] = 0
	# 			else:
	# 				result2d[row][col] = 1

	# 	return result2d


	# def __bin2one(self, result2d, pro_res):
	# 	result1d = []
	# 	unclassified = 0
	# 	row = 0

	# 	for i in result2d:
	# 		if sum(i) == 1:
	# 			for j in range(i.shape[0]):
	# 				if i[j] == 1:
	# 					result1d.append(j + 1)
	# 					break
	# 		elif sum(i) > 1:
	# 			comparedict = {}

	# 			for j in range(i.shape[0]):
	# 				if i[j] == 1:
	# 					comparedict[j] = pro_res[row][j]

	# 			result1d.append(max(comparedict, key = comparedict.get) + 1)
	# 		else:
	# 			result1d.append(0.0)
	# 			unclassified += 1

	# 		row += 1

	# 	return np.array(result1d), unclassified / len(result1d)


	# def __filterZeros(self, result1d, test_y):
	# 	nozero_result1d = []
	# 	nozero_test_y = []

	# 	for r in range(result1d.shape[0]):
	# 		if result1d[r] != 0:
	# 			nozero_result1d.append(result1d[r])
	# 			nozero_test_y.append(test_y[r])

	# 	return np.array(nozero_result1d), np.array(nozero_test_y)


	# def plotEstimate(self, pro_res, test_y):
	# 	thresholdlist = np.array([x / 10 for x in range(10)])
	# 	accuracylist  = np.zeros((10,))
	# 	precisionlist = np.zeros((10,))
	# 	recalllist    = np.zeros((10,))
	# 	perunclaslist = np.zeros((10,))

	# 	for i in range(10):
	# 		result2d = binarize(pro_res, thresholdlist[i])
	# 		print(result2d)
	# 		result1d, unclassified = self.__bin2one(result2d, pro_res)
	# 		print(result1d)
	# 		print(test_y)

	# 		nozero_result1d, nozero_test_y = self.__filterZeros(result1d, test_y)

	# 		accuracylist[i]  = accuracy_score(nozero_test_y, nozero_result1d)
	# 		precisionlist[i] = precision_score(nozero_test_y, nozero_result1d, average=None)[1:].mean()
	# 		recalllist[i]    = recall_score(nozero_test_y, nozero_result1d, average=None)[1:].mean()
	# 		perunclaslist[i] = 1 - unclassified

	# 	# print("p")
	# 	# print(precisionlist)
	# 	# print("r")
	# 	# print(recalllist)
	# 	# print("a")
	# 	# print(accuracylist)

	# 	plt.figure(3)
	# 	lw = 2

	# 	plt.plot(thresholdlist, accuracylist , lw=lw, label='accuracy')
	# 	plt.plot(thresholdlist, precisionlist, lw=lw, label='precision')
	# 	plt.plot(thresholdlist, recalllist   , lw=lw, label='recall')
	# 	plt.plot(thresholdlist, perunclaslist, lw=lw, label='per of classified')

	# 	plt.xlim([0.0, 0.95])
	# 	plt.ylim([0.0, 1.05])
	# 	plt.xlabel('Threshold')
	# 	plt.ylabel('Classifier Performance')
	# 	plt.legend(loc="lower right")
	# 	plt.show()


