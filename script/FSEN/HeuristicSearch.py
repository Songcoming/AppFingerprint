#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from sklearn.feature_selection import SelectKBest
from classifiers.RFmulti import RFmul
from sklearn.preprocessing import MinMaxScaler

import numpy as np

class HSearch():
    def __init__(self, FSubset, y):
        self.BFSubset = FSubset #全组合原特征集
        self.Fin2Subset = None #全组合结果特征子集

        self.GFSubset = FSubset #启发式搜索原特征集（不变）
        self.FSubset = FSubset #启发式搜索原特征集（最后为空）
        self.ZSubset = None #启发式搜索中间计算特征子集
        self.FinSubset = None #启发式搜索结果特征子集

        self.RFEset = FSubset #RFE原特征集
        self.RFESubset = FSubset #RFE中间计算特征子集
        self.Fin3Subset = None #RFE结果特征子集

        self.y = y

    def JudgeValue(self,X): #判据值（随机森林算法准确率）
        fea_X = X
        fea_y = self.y
        scaler = MinMaxScaler()
        s_fea_X = scaler.fit_transform(fea_X)
        rf_mul = RFmul(s_fea_X, fea_y)
        rf_mul.rfStart()

        # print(rf_mul.precision)
        # print(rf_mul.recall)

        return rf_mul.ascore

    def RFEstart(self): #RFE
        JudgePro = self.JudgeValue(self.RFEset)
        while self.RFEset.shape[1] > 1:
            index = 0
            Cindex = -1
            Judge = 0.0
            Juindex = 0.0

            while index < self.RFEset.shape[1] - 1:
                self.RFESubset = self.RFEset
                self.RFESubset = np.delete(self.RFESubset, index, axis=1)
                Juindex = self.JudgeValue(self.RFESubset)
                if Juindex > Judge:
                    Judge = Juindex
                    Cindex = index
                index += 1
            if Cindex >= 0:
                self.RFEset = np.delete(self.RFEset, Cindex, axis=1)
            if Judge > JudgePro:
                JudgePro = Judge
                self.Fin3Subset = self.RFEset
            #print(Judge)
        return JudgePro, self.Fin3Subset

    def HSstart(self): #启发式搜索
        JudgePro = 0.0
        ColNumList = []
        FinSubColList = []
        #SignArr = np.arange(self.GFSubset.shape[1])
        #print(SignArr.shape)
        #print(self.FSubset.shape)
        #self.FSubset = np.vstack((SignArr,self.GFSubset))
        #print(self.FSubset.shape)
        while self.FSubset.shape[1] > 0:
            index = 0
            Colnum = 0
            Judge = 0.0
            JIndex = 0.0
            Fcol = self.FSubset[:,index]
            Fcol = Fcol.reshape(-1,1)
            while index < self.FSubset.shape[1]:
                col = self.FSubset[:,index]
                col = col.reshape(-1, 1)
                X = self.ZSubset
                #print(col.shape)
                if X is None:
                    X = col
                else:
                    X = np.hstack((X, col))
                X = np.delete(X, 0, axis=0)
                JIndex = self.JudgeValue(X)
                if JIndex > Judge:
                    Judge = JIndex
                    Fcol = col
                    Colnum = index
                index += 1
            #print(JudgePro)
            # print(Judge)
            if self.ZSubset is None:
                self.ZSubset = Fcol
            else:
                self.ZSubset = np.hstack((self.ZSubset, Fcol))
            self.FSubset = np.delete(self.FSubset, Colnum, axis=1)
            ColNumList.append(Fcol[0][0])
            if Judge > JudgePro:
                self.FinSubset = self.ZSubset

                JudgePro = Judge
        self.FinSubset = np.delete(self.FinSubset, 0, axis=0)
        FinSubColList = ColNumList[:self.FinSubset.shape[1]]
        return JudgePro, self.FinSubset, FinSubColList #返回最终准确率，最终特征子集，最终特征列表

    def FulCom(self): #特征全组合
        n = self.BFSubset.shape[1]
        Cn = 2 ** n - 1
        index = 1
        Judge = 0.0
        while index <= Cn:
            Nstr = list(str(bin(index))[2:])
            Nstr.reverse()
            CIndex = 0
            X = None
            for itnu in Nstr:
                if itnu == "1":
                    col = self.BFSubset[:, CIndex]
                    col = col.reshape(-1, 1)
                    if X is None:
                        X = col
                    else:
                        X = np.hstack((X, col))
                CIndex += 1
            JIndex = self.JudgeValue(X)
            #print(JIndex)
            if JIndex > Judge:
                Judge = JIndex
                self.Fin2Subset = X
            index += 1

        return Judge, self.Fin2Subset #返回最终准确率，最终特征子集

    def getFroPR(self):
        self.handle = RFmul(self.FinSubset, self.y)
        self.handle.rfStart()
        precision, recall = self.handle.getPR()

        return precision, recall

    def saveFroModel(self, modelName):
        self.handle.saveModel(modelName)





