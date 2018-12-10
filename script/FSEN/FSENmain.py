#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2018-09-12 by r4mind

from sklearn.preprocessing import MinMaxScaler

import numpy as np
from FSEN.HeuristicSearch import HSearch

from decimal import Decimal

class FSEN():

	def __init__(self, X, y, classifier, top, *FSname):
		self.X = X
		self.y = y
		self.top  = top

		self.classifier = classifier
		self.FSname = FSname

		self.filterdict = {}
		self.selectedF  = {}
		self.selectedA  = {}

		self.score = []
		self.pre   = []
		self.rec   = []
		self.index = []

		print("in FSEN")


		self.estiFeaSelecCorr()
		# saccuracy = self.sortAccuracy(accuracy)
		# # print(self.y)
		# hsh = HSearch(self.cmbSubset(saccuracy), self.y)
		# self.scores, self.subset = hsh.HSstart()

		# # print(self.subset.shape[1])
		# print(self.scores)


	def estiFeaSelecCorr(self):
		'''
		estimate the features selection performence

		Returns:
		-------
		FSaccuracy : dict
			the classify accuracy of each feature selection method
		'''

		filterdict = {}

		for n in self.FSname:
			if n == 'FCBF':
				# import FCBF
				pass

			elif n == 'info_gain':
				# import infoGain
				from sklearn.feature_selection import mutual_info_classif
				iglist = mutual_info_classif(self.X, self.y)

				# print('info_gain: ')
				# print(iglist.shape)
			
				self.filterdict[n] = np.argsort(iglist)[::-1]

			elif n == 'gain_ratio':
				# import gainRatio
				pass

			elif n == 'chi_square':
				# import chiSquare
				from sklearn.feature_selection import chi2
				X_formed = MinMaxScaler().fit_transform(self.X)
				chi2list = chi2(X_formed, self.y)

				# print('chi_square')
				# print(chi2list[0].shape)

				self.filterdict[n] = np.argsort(chi2list[0])[::-1]

			elif n == 'ReliefF':
				# import ReliefF
				pass

			elif n == 'f_classif':
				# import f_classif
				from sklearn.feature_selection import f_classif

				fcflist = f_classif(self.X, self.y)

				# print('f_classif: ')
				# print(fcflist[0].shape)

				self.filterdict[n] = np.argsort(fcflist[0])[::-1]
			
			elif n == 'var_thresh':
				# import var_thresh
				from sklearn.feature_selection import VarianceThreshold

				varray = VarianceThreshold()
				varray.fit_transform(self.X, self.y)
				varlist = varray.variances_

				# print('var_thresh: ')
				# print(varlist.shape)
				self.filterdict[n] = np.argsort(varlist)[::-1]

			elif n == 'pearson_corr':
				corlist = []

				for i in range(self.X.shape[1]):
					# print(self.X[:, i])
					cor = np.corrcoef(self.X[:, i], self.y)[0, 1]
					corlist.append(cor)

				corlist = np.abs([0 if np.isnan(i) else i for i in corlist])

				# print("pearson_corr:")
				# print(corlist.shape)

				self.filterdict[n] = np.argsort(corlist)[::-1]

			else:
				print(n + ": Unknown feature selection method.")

		# print(self.filterdict)


	def selectBestScore(self, best, flownum):

		for k, v in self.filterdict.items():
			# print(k)
			sortedindex = v[:best]

			X_new = np.empty(shape = [self.X.shape[0], 0])
			for i in sortedindex:
				X_new = np.hstack((X_new, self.X[:, i].reshape((self.X.shape[0], -1))))

			# print(X_new.shape)

			handle = self.classifier(X_new, self.y)
			handle.rfStart()

			X_new = np.vstack((sortedindex, X_new))
			# print(X_new)

			self.selectedA[k] = handle.ascore
			self.selectedF[k] = X_new

		accuracy = sorted(self.selectedA.items(), key = lambda x : x[1])[-self.top :]
		print(accuracy)

		# subfeatures = self.cmbSubset(accuracy)
		subfeatures = self.cmbSubsetUnion(accuracy)

		scorelist = []
		indexlist = []
		modellist = []
		prelist   = []
		reclist   = []

		if subfeatures.shape[1] != 0:
			for i in range(5):

				# hsh = HSearch(subfeatures, self.y)
				hsh = HSearch(subfeatures, self.y)
				scores, subset, index = hsh.HSstart()

				precision, recall = hsh.getFroPR()

				# scores, subset = hsh.RFEstart()
				scorelist.append(scores)
				indexlist.append(index)
				modellist.append(hsh)
				prelist.append(precision)
				reclist.append(recall)	
				# self.scores, self.subset = hsh.RFEstart()
		else:
			zerolist = [i * 0.0 for i in range(5)]
			scorelist.append(zerolist)
			prelist.append(zerolist)
			reclist.append(zerolist)

		self.score = scorelist
		self.pre = prelist
		self.rec = reclist

		maxindex = scorelist.index(max(scorelist))
		self.index = indexlist[maxindex]
		modellist[maxindex].saveFroModel('honor_meizu_nexus_flow' + str(flownum) + '_fea' + str(best))

		print(self.index)

		

	def cmbSubset(self, sortedaccuracy):
		'''
		combine the top n subsets

		Parameters:
		-----------
		sortedaccuracy : dict
			the sorted accuracy numbers

		Returns:
		--------
		cmbsubset : ndarray
			the best subset
		'''

		# new_array = []
		new_array = np.empty(shape = [self.X.shape[0], 0])

		for k in sortedaccuracy:
			new_array = np.hstack((new_array, self.selectedF[k[0]]))

		# print(new_array.shape)
		# cmbsubset = np.unique(new_array, axis = 1)
		# print(cmbsubset.shape)

		feanum = {}

		for i in range(new_array.shape[1]):
			flag = 0
			for j in feanum.keys():
				if (new_array[:, i] == new_array[:, j]).all():
					feanum[j] += 1
					flag = 1

			if flag == 0:
				feanum[i] = 1

		cmbsubset = np.empty(shape = [self.X.shape[0], 0])
		for k, v in feanum.items():
			if v == self.top:
				cmbsubset = np.hstack((cmbsubset, new_array[:, k].reshape((self.X.shape[0], -1))))

		return cmbsubset



	def cmbSubsetUnion(self, sortedaccuracy):
		'''
		combine the top n subsets

		Parameters:
		-----------
		sortedaccuracy : dict
			the sorted accuracy numbers

		Returns:
		--------
		cmbsubset : ndarray
			the best subset
		'''

		# new_array = []
		new_array = np.empty(shape = [self.X.shape[0] + 1, 0])

		for k in sortedaccuracy:
			new_array = np.hstack((new_array, self.selectedF[k[0]]))

		cmbsubset = np.unique(new_array, axis = 1)
		print(cmbsubset.shape)

		return cmbsubset



