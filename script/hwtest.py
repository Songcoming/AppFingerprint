 #!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2018-07-05 by r4mind

import pickle
import appset

from sklearn.ensemble       import RandomForestClassifier
from sklearn.preprocessing  import MinMaxScaler
from sklearn.metrics        import precision_score, recall_score, accuracy_score

from classifiers.plotEstimate import plotE
from features.statistical     import statiFeature

import numpy as np
import matplotlib.pyplot as plt

def hwtest(maxindex, maxfeaindex, flowindexlist, feaindexlist):
	# fea_X = np.empty(shape = [0, 91])
	# fea_y = np.empty(shape = [1, 0])

	sf = statiFeature([b'\xc0\xa8\x89\x1d'])

	for k, v in appset.apptestdict.items():
		sf.inipcapfile('/tmp/mi6s/' + k + '_mi_6.pcap', v)
		sf.generateFea()

	fea_X, fea_y = sf.chooseLowwestFlow(maxindex[0])
	filtered_fea_X = fea_X[:, np.array([int(x) for x in list(maxfeaindex)])]
	# s_fea_X = scaleFeature(fea_X)

	print(filtered_fea_X.shape)

	# reslist = []
	# seclist = []
		
	with open('pickles/honor_meizu_nexus_flow' + str(flowindexlist[maxindex[0]]) + '_fea' + str(feaindexlist[maxindex[1]]) + '.pickle', 'rb') as fr:
		new_clf = pickle.load(fr)
		pro_res = new_clf.predict_proba(filtered_fea_X)
		pre_res = new_clf.predict(filtered_fea_X)

		test_y = fea_y

		acu = accuracy_score(test_y, pre_res)
			
	# seclist.append(acu)

	# reslist.append(seclist)

	print(acu)
	precision = precision_score(test_y, pre_res, average = 'weighted')
	recall = recall_score(test_y, pre_res, average = 'weighted')
	print(precision, recall)
	# drawHeatmap(reslist, [x * 5 for x in range(9)[5:]], [x * 5 for x in range(14)[9:]])

				# pe = plotE(pro_res, test_y)
				# pe.plotThreshold_perform()


def scaleFeature(features):
	scaler = MinMaxScaler()
	return scaler.fit_transform(features)


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

if __name__ == '__main__':
	hwtest((3, 0), [3.0, 32.0, 44.0, 53.0, 25.0, 26.0, 82.0, 21.0, 8.0, 22.0, 59.0, 69.0, 12.0, 14.0, 11.0, 34.0, 37.0, 15.0, 42.0])