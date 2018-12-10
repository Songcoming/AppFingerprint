#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2017-12-26 by r4mind

import appset
import hwtest

import numpy  as np
import matplotlib.pyplot as plt
from matplotlib import cm
from matplotlib import axes

from features.featuresBase import feaBase

from classifiers.SVCmulti  import SVCmul
from classifiers.RFmulti   import RFmul
from classifiers.PFRFmul   import PFRFmul

from FSEN.FSENmain import FSEN

from sklearn.preprocessing import MinMaxScaler

def appdata2fea():
	fea_X = np.empty(shape = [0, 9])
	fea_y = np.empty(shape = [1, 0])

	for k, v in appset.appdict.items():
		sf = statiFeature('/tmp/' + k + '.pcap', v)

		fea_X = np.vstack((fea_X, sf.X))
		fea_y = np.hstack((fea_y, sf.y))

	return fea_X, fea_y, sf.namelist


def scaleFeature(features):
	scaler = MinMaxScaler()
	return scaler.fit_transform(features)


def startSVCMul(s_fea_X, fea_y, namelist):
	svc_mul = SVCmul(s_fea_X, fea_y[0], namelist)
	svc_mul.svmStart()

def startRFMul(s_fea_X, fea_y):
	rf_mul = RFmul(s_fea_X, fea_y[0])
	return rf_mul.rfStart()


def startPFRFmul(fea_X, fea_y):
	pf_rf_mul = PFRFmul(fea_X, fea_y)
	pf_rf_mul.pfrfStart()


def mergeFlowFea(fealist):
	basefea_X = fealist[0].X
	basefea_y = fealist[0].y

	for fea in fealist[1:]:
		for length, items in fea.X.items():
			if not (length in basefea_X.keys()):
				basefea_X[length] = []
				basefea_y[length] = []
			basefea_X[length] += items
			basefea_y[length] += fea.y[length]

	return basefea_X, basefea_y

def testLowwestFlow(flowindexlist, feaindexlist = []):
	# lowestflow = np.array(range(13)[1:])
	ascorelist = []
	prelist = []
	reclist = []
	indexlist = []

	fb = feaBase([b'\xc0\xa8\x02\x07', b'\xc0\xa8\x02\x05', b'\xc0\xa8\x89\xa4'])

	fb.createCTFhandle()

	for k, v in appset.apptraindict.items():
		fb.getAPPPath(k , v)

		# sf = fb.getStatisticalFea()
		# sf.generateFea()

		fb.getFullHTTPInfo()

	fb.getContextualFea()

	for i in flowindexlist:	
		# fea_X = np.empty(shape = [0, 91])
		# fea_y = np.empty(shape = [1, 0])

		fea_X, fea_y = sf.chooseLowwestFlow(i)
		
		best2accuracy = {}
		predict = {}
		recdict = {}
		indexdict = {}

		s_fea_X = scaleFeature(fea_X)
		# ascorelist[i] = startRFMul(s_fea_X, fea_y)

		# ylist.append(fea_y.tolist())
		# print(ylist)

		fsen = FSEN(fea_X, fea_y, RFmul, 3, 'info_gain', 'f_classif', 'pearson_corr', 'chi_square', 'var_thresh')

		for j in feaindexlist:

			fsen.selectBestScore(j, i)	

			# if j in best2accuracy:
			# 	if best2accuracy[j] < fsen.scores:
			# 		best2accuracy[j] = fsen.scores
			# else:
			best2accuracy[j] = sum(fsen.score) / float(len(fsen.score))
			predict[j] = sum(fsen.pre) / float(len(fsen.pre))
			recdict[j] = sum(fsen.rec) / float(len(fsen.rec))
			indexdict[j] = fsen.index

			print('score')
			print(best2accuracy)
			print('pre')
			print(predict)
			print('rec')
			print(recdict)
			print('index')
			print(indexdict)

		ascorelist.append(list(best2accuracy.values()))
		prelist.append(list(predict.values()))
		reclist.append(list(recdict.values()))
		indexlist.append(list(indexdict.values()))

		print('score')
		print(ascorelist)
		print('pre')
		print(prelist)
		print('rec')
		print(reclist)
		print('index')
		print(indexlist)

	maxlist = []
	for k in ascorelist:
		maxlist.append(max(k))

	print(max(maxlist))

	return getMaxIndex(ascorelist, indexlist)

	# plt.figure(7)

	# plt.scatter([x * 5 for x in range(13)[1:]], [x * 5 for x in range(11)[1:]], c = ascorelist, marker = ",")
	# plt.colorbar()

	# plt.xlim([0.0, 60.0])
	# plt.ylim([0.0, 60.0])
	# plt.xlabel('lowwest length of one flow')
	# plt.ylabel('the amount of delivered features')

	# plt.show()

	# drawHeatmap(ascorelist, [x * 5 for x in range(9)[1:]], [x * 5 for x in range(13)[1:]])
	# drawHeatmap(prelist, [x * 5 for x in range(9)[1:]], [x * 5 for x in range(13)[1:]])
	# drawHeatmap(reclist, [x * 5 for x in range(9)[1:]], [x * 5 for x in range(13)[1:]])


def getMaxIndex(ascorelist, indexlist):
	ascorearray = np.array(ascorelist)
	maxindex = np.unravel_index(ascorearray.argmax(), ascorearray.shape)
	print(maxindex)
	print(indexlist)

	maxfeaindex = indexlist[maxindex[0]][maxindex[1]]
	
	return maxindex, maxfeaindex



def drawHeatmap(data, xlabels, ylabels):
    #cmap=cm.Blues    
    cmap = cm.get_cmap('rainbow',1000)
    figure = plt.figure(facecolor='w')

    ax = figure.add_subplot(1,1,1,position=[0.1,0.15,0.8,0.8])

    ax.set_yticks(range(len(ylabels)))
    ax.set_yticklabels(ylabels)
    ax.set_xticks(range(len(xlabels)))
    ax.set_xticklabels(xlabels)

    vmax = data[0][0]
    vmin = data[0][0]

    for i in data:
        for j in i:
            if j > vmax:
                vmax = j
            if j < vmin:
                vmin = j

    map = ax.imshow(data,interpolation='nearest',cmap=cmap,aspect='auto',vmin=vmin,vmax=vmax)
    cb = plt.colorbar(mappable=map,cax=None,ax=None,shrink=0.5)
    plt.show()
		

def getBestAccuracy():
	fea_X = np.empty(shape = [0, 9])
	fea_y = np.empty(shape = [1, 0])

	bestAccuracy = 0.0

	for k, v in appset.appdict.items():
		sf = statiFeature('/tmp/' + k + '_HW_3.pcap', v, b'\xc0\xa8\x02\x05')

		fea_X = np.vstack((fea_X, sf.testLowwestF['testX']))
		fea_y = np.hstack((fea_y, sf.testLowwestF['testy']))



	s_fea_X = scaleFeature(fea_X)
	bestAccuracy = startRFMul(s_fea_X, fea_y)

def FSENtest():
	fea_X = np.empty(shape = [0, 57])
	fea_y = np.empty(shape = [1, 0])

	best2accuracy = {}

	for k, v in appset.appdict.items():
		sf = statiFeature('/tmp/' + k + '_HW_3.pcap', v, b'\xc0\xa8\x02\x05')

		fea_X = np.vstack((fea_X, sf.testLowwestF['testX']))
		fea_y = np.hstack((fea_y, sf.testLowwestF['testy']))

	for i in range(58)[1:]:
		fsen = FSEN(fea_X, fea_y[0], RFmul, 2, i, 'info_gain', 'f_classif', 'var_thresh')
		if i in best2accuracy:
			if best2accuracy[i] < fsen.scores:
				best2accuracy[i] = fsen.scores
		else:
			best2accuracy[i] = fsen.scores

	print(best2accuracy)
	plt.figure(5)
	plt.plot(range(58)[1:], list(best2accuracy.values()), lw = 2)

	plt.xlim([0.0, 60.0])
	plt.ylim([0.0, 1.05])
	plt.xlabel('the number of features')
	plt.ylabel('Accuracy')

	plt.show()

def openstatistical():
	fea_X, fea_y, namelist = appdata2fea()

	s_fea_X = scaleFeature(fea_X)

	# startSVCMul(s_fea_X, fea_y, namelist)
	startRFMul(s_fea_X, fea_y, namelist)


def openperflow():
	modeldict = {}
	scoresum  = 0

	flowfealist = [perflowFeature('/tmp/' + k + '.pcap', v) for k, v in appset.appdict.items()]
	flowfea_X, flowfea_y = mergeFlowFea(flowfealist)


	# for length, items in flowfea_X.items():
	# 	# print(length, items)
	# 	# print(flowfea_y[length])
	# 	print(np.array(items))
	# 	print(np.array(flowfea_y[length]))
	# 	modeldict[length], score = startRFMul(np.array(items), np.array(flowfea_y[length]), 0)
	# 	scoresum += score

	# print(scoresum / len(flowfea_X))

	startPFRFmul(flowfea_X, flowfea_y)





if __name__ == '__main__':
	flowindexlist = [x * 5 for x in range(13)[6:]]
	feaindexlist  = [x * 5 for x in range(11)[6:]]
	# openstatistical()
	# openperflow()
	maxindex, maxfeaindex = testLowwestFlow(flowindexlist, feaindexlist)
	# getBestAccuracy()
	# FSENtest()
	print(maxindex, maxfeaindex)

	hwtest.hwtest(maxindex, maxfeaindex, flowindexlist, feaindexlist)


