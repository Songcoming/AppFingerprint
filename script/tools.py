import numpy             as np
import matplotlib.pyplot as plt
import scapy.all         as scapy
from matplotlib import cm
from matplotlib import axes
from random import shuffle, sample
from itertools import groupby
import appset
import glob
import os
import math
import scipy.stats


def drawHeatmap(data,xlabels,ylabels):
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


def mulexam(lists):
    firstaxis = []
    for i in lists:
        secondaxis = []
        for j in i:
            secondaxis.append(sum(j) / float(len(j)))

        firstaxis.append(secondaxis)
    print(firstaxis)
    print("max")
    maxlist = []
    for k in firstaxis:
        maxlist.append(max(k))

    print(max(maxlist))


def drawHist(data, appnum, phonename, port, picsig):
    figure = plt.figure(picsig)

    ax = figure.add_subplot(1,1,1,position=[0.1,0.15,0.8,0.8])

    # ax.set_yticks(range(len(ylabels)))
    # ax.set_yticklabels(ylabels)
    # ax.set_xticks(range(11))
    # ax.set_xticklabels([x * 2 for x in range(11)])

    plt.xlabel("dis")
    plt.ylabel("port")

    plt.hist(data, bins = 100, normed = 0)


def drawBar(data):
    figure = plt.figure()
    index = range(50)
    label = [str(x + 100) for x in range(26)[1:]]
    label.extend([str(y + 200) for y in range(26)[1:]])

    plt.xticks(index, label, rotation = 90)

    p2 = plt.bar(index, data, color="#87CEFA")

    plt.show()


def samplePcapsC(phonename, groupname, value, index, random):
    pcapfiles = glob.glob('../../M_H/tcp/' + phonename + '/' + groupname + '/' + str(value) + '/*.pcap')
    pcapC1 = glob.glob('../../M_H/tcp/' + phonename + '/C1/' + str(value) + '/*.pcap')
    pcapC2 = glob.glob('../../M_H/tcp/' + phonename + '/C2/' + str(value) + '/*.pcap')

    shuffle(pcapfiles)
    shuffle(pcapC1)
    shuffle(pcapC2)

    pcaplist = sample(pcapfiles, random)
    pcaplistC1 = sample(pcapC1, random)
    pcaplistC2 = sample(pcapC2, random)

    with open("M_H_1/" + phonename + "/" + groupname + 'C1/' + str(value) + "/plist" + str(index) + ".txt", "w+") as f:
        for line in pcaplist:
            f.write(line)
            f.write("\n")
        for line in pcaplistC1:
            f.write(line)
            f.write("\n")

    with open("M_H_1/" + phonename + "/" + groupname + 'C2/' + str(value) + "/plist" + str(index) + ".txt", "w+") as g:
        for line in pcaplist:
            g.write(line)
            g.write("\n")
        for line in pcaplistC2:
            g.write(line)
            g.write("\n")

    # np.savetxt("pcapaddr/" + ph


def samplePcaps(phonename, groupname, value, index, random):
    pcapfiles = glob.glob('../../M_H/tcp/' + phonename + '/' + groupname + '/' + str(value) + '/*.pcap')

    shuffle(pcapfiles)
    pcaplist = sample(pcapfiles, random)

    with open("M_H_2/" + phonename + "/" + groupname + '/' + str(value) + "/plist" + str(index) + ".txt", "w+") as f:
        for line in pcaplist:
            f.write(line)
            f.write("\n")

    # np.savetxt("pcapaddr/" + phonename + "/" + str(value) + "/plist" + str(index) + ".txt", np.array(pcaplist))

def sampleTCPPcapsC(phonename, groupname, value, times, random):
    pcapfiles = glob.glob('../../M_H/tcp/' + phonename + '/' + groupname + '/' + str(value) + '/*.pcap')
    pcapC1 = glob.glob('../../M_H/tcp/' + phonename + '/C1/' + str(value) + '/*.pcap')
    pcapC2 = glob.glob('../../M_H/tcp/' + phonename + '/C2/' + str(value) + '/*.pcap')

    tcpfiles = []
    c1files = []
    c2files = []

    for p in pcapfiles:
        pcaplength = os.path.getsize(p)

        if 114 < pcaplength < 2 ** 25 - 1:
            # print('in place')
            pkgs = scapy.rdpcap(p)

            # for pkg in pkgs:
            #   print(repr(pkg))

            portkey = ''

            if 'TCP' in pkgs[0]:
                sport = pkgs[0]['TCP'].sport
                dport = pkgs[0]['TCP'].dport

                if sport < dport:
                    portkey = sport
                else:           
                    portkey = dport

                if portkey == 443:
                    tcpfiles.append(p)

    for p in pcapC1:
        pcaplength = os.path.getsize(p)

        if 114 < pcaplength < 2 ** 25 - 1:
            # print('in place')
            pkgs = scapy.rdpcap(p)

            # for pkg in pkgs:
            #   print(repr(pkg))

            portkey = ''

            if 'TCP' in pkgs[0]:
                sport = pkgs[0]['TCP'].sport
                dport = pkgs[0]['TCP'].dport

                if sport < dport:
                    portkey = sport
                else:           
                    portkey = dport

                if portkey == 443:
                    c1files.append(p)

    for p in pcapC2:
        pcaplength = os.path.getsize(p)

        if 114 < pcaplength < 2 ** 25 - 1:
            # print('in place')
            pkgs = scapy.rdpcap(p)

            # for pkg in pkgs:
            #   print(repr(pkg))

            portkey = ''

            if 'TCP' in pkgs[0]:
                sport = pkgs[0]['TCP'].sport
                dport = pkgs[0]['TCP'].dport

                if sport < dport:
                    portkey = sport
                else:           
                    portkey = dport

                if portkey == 443:
                    c2files.append(p)

    # print(len(tcpfiles))

    for index in range(times):
        tcplist = sample(tcpfiles, random)
        c1list  = sample(tcpfiles, random)

        with open("M_H_tcp_1/" + phonename + "/" + groupname + 'C1/' + str(value) + "/tcplist" + str(index) + ".txt", "w+") as f:
            for line in tcplist:
                f.write(line)
                f.write("\n")

            for line in c1list:
                f.write(line)
                f.write("\n")

        shuffle(tcpfiles)
        shuffle(c1list)


    for index in range(times):
        tcplist = sample(tcpfiles, random)
        c2list  = sample(tcpfiles, random)

        with open("M_H_tcp_1/" + phonename + "/" + groupname + 'C2/' + str(value) + "/tcplist" + str(index) + ".txt", "w+") as f:
            for line in tcplist:
                f.write(line)
                f.write("\n")

            for line in c1list:
                f.write(line)
                f.write("\n")

        shuffle(tcpfiles)
        shuffle(c2list)


def sampleTCPPcaps(phonename, groupname, value, times, random):
    pcapfiles = glob.glob('../../M_H/tcp/' + phonename + '/' + groupname + '/' + str(value) + '/*.pcap')
    tcpfiles = []

    for p in pcapfiles:
        pcaplength = os.path.getsize(p)

        if 114 < pcaplength < 2 ** 25 - 1:
            # print('in place')
            pkgs = scapy.rdpcap(p)

            # for pkg in pkgs:
            #   print(repr(pkg))

            portkey = ''

            if 'TCP' in pkgs[0]:
                sport = pkgs[0]['TCP'].sport
                dport = pkgs[0]['TCP'].dport

                if sport < dport:
                    portkey = sport
                else:           
                    portkey = dport

                if portkey == 443:
                    tcpfiles.append(p)

    print(len(tcpfiles))

    for index in range(times):
        tcplist = sample(tcpfiles, random)

        with open("M_H_tcp_2/" + phonename + "/" + groupname + '/' + str(value) + "/tcplist" + str(index) + ".txt", "w+") as f:
            for line in tcplist:
                f.write(line)
                f.write("\n")

        shuffle(tcpfiles)



def sampleTCPseg(phonename, groupname, value, times, random):
    pcapfiles = glob.glob('../../M_H/tcp/' + phonename + '/' + groupname + '/' + str(value) + '/*.pcap')
    tcpfiles = []

    for p in pcapfiles:
        pcaplength = os.path.getsize(p)

        if 114 < pcaplength < 2 ** 25 - 1:
            # print('in place')
            pkgs = scapy.rdpcap(p)

            # for pkg in pkgs:
            #   print(repr(pkg))

            portkey = ''

            if 'TCP' in pkgs[0]:
                sport = pkgs[0]['TCP'].sport
                dport = pkgs[0]['TCP'].dport

                if sport < dport:
                    portkey = sport
                else:           
                    portkey = dport

                if portkey == 443:
                    tcpfiles.append(p)

    print(len(tcpfiles))

    for index in range(times):
        tcplist = sample(tcpfiles, random)

        with open("seg_test/" + phonename + "/" + str(value) + "/tcplist" + str(index) + ".txt", "a") as f:
            for line in tcplist:
                f.write(line)
                f.write("\n")

        shuffle(tcpfiles)

def segDistribution(phonename, value, index):
    tcpsegfiles = []
    feadistri = {}
    feapro = [0.0 for y in range(25)]

    with open("seg_test/" + phonename + "/" + str(value) + "/tcplist" + str(index) + ".txt", "r") as f:
        for line in f:
            tcpsegfiles.append(line[:-1])

    tcpseglength = []
    for pcap in tcpsegfiles:
        tcpseglength.append(os.path.getsize(pcap))

    # print(tcpseglength)

    for f, g in groupby(sorted(tcpseglength), key = lambda x: int(math.log(x + 1, 2))):
        tmpg = list(g)
        # print(f, len(tmpg))
        feadistri[f] = len(tmpg)

        lensum = 0
        for s in feadistri.values():
            lensum += s

        for n, m in feadistri.items():
            if n < 25:
                feapro[n] = float(m) / float(lensum)

    return feapro


def segPkgDistribution(phonename, value, index):
    tcpsegfiles = []
    feadistri = {}
    feapro = [0.0 for y in range(50)]

    with open("seg_test/" + phonename + "/" + str(value) + "/tcplist" + str(index) + ".txt", "r") as f:
        for line in f:
            tcpsegfiles.append(line[:-1])

    tcpseglength = []
    for pcap in tcpsegfiles:
        pkgs = scapy.rdpcap(pcap)
        # pkglensum = 0
        flowtimelength = pkgs[-1].time - pkgs[0].time
        # for pkg in pkgs:
        #     print(pkg.time)
        # print(flowtimelength)
        tcpseglength.append(flowtimelength)

    # print(len(pkgs))

    for f, g in groupby(sorted(tcpseglength), key = lambda x: int(x // 0.1)):
        tmpg = list(g)
        print(f, len(tmpg))
        feadistri[f] = len(tmpg)

        lensum = 0
        for s in feadistri.values():
            lensum += s

        for n, m in feadistri.items():
            if n < 50:
                feapro[n] = float(m) / float(lensum)

    return feapro





if __name__ == '__main__':

    appnum =  [2, 4, 8, 9, 11]
    phonelist = ["M2", "H1"]
    grouplist = ["A1", "A2", "B1", "B2"]

    #======== formal segmentation ======#

    for i in phonelist:
        print(i)
        for g in grouplist:
            print(g)
            for j in appnum:
                print(j)
                # for k in range(150):
                #     samplePcapsC(i, g, j, k, 30)
                sampleTCPPcaps(i, g, j, 150, 60)

    #========= compare segmentation ======#

    # for i in phonelist:
    #     print(i)
    #     for j in appnum:
    #         for g in grouplist:
    #             print(g, j)
    #             sampleTCPseg(i, g, j, 10, 20)

    #========= compare distribution computation ======#

    # for i in phonelist:
    #     feapro = []
    #     print(i)
    #     for j in appnum:
    #         print(j)
    #         for k in range(10):
    #             feapro.append(segPkgDistribution(i, j, k))

    #     print(np.array(feapro).shape)
    #     np.savetxt("features/txt/" + i + "_seg_tcpsess_tstamp.txt", np.array(feapro)) 

    #======== entropy computation =====#

    # resultlist = []
    # resultavar = []
    # eps = 0.000001

    # segfea1 = np.loadtxt("features/txt/M1_seg_stati_tstamp.txt")
    # segfea2 = np.loadtxt("features/txt/H1_seg_stati_tstamp.txt")

    # for i in range(50):
    #     # print(segfea1[i].shape)
    #     KL = 0.0
    #     for j in range(25):
    #         KL += (segfea1[i][j] + eps) * np.log((segfea1[i][j] + eps) / (segfea2[i][j] + eps))

    #     resultlist.append(KL)

    # for k in range(5):
    #     slip = resultlist[k * 10 : k * 10 + 9]
    #     avar = sum(slip) / 10.0

    #     resultavar.append(avar)

    # print("M1, H1, stati_tstamp")

    # print(resultavar)









