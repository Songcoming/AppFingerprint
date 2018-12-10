#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2018-10-29 by r4mind
import scapy.all as scapy
import os

def compareData():
	filterdpath = pcapFilter("/tmp/wechat_Nexus_6P.pcap")
	wechat = scapy.rdpcap(filterdpath)

	pcaplist = []
	
	for p in wechat:
		pcaplist.append(p)
		print(repr(p.payload.payload))
		print(len(p))
		with open("/tmp/wechat_Nexus_6P.txt", 'wb+') as th:
			th.write(bytes(p.payload.payload))
	
	print(sorted(pcaplist))


def pcapFilter(sf):
	index =  sf[: : -1].index('/')
	dp    =  sf[: -index]
	fn    =  sf[-index: ].split('.')
	df    =  dp + fn[0] + "_aff." + fn[-1]

	# cmd_filter = "'tcp && !(tcp.port == 80) && !(tcp.analysis.flags && !tcp.analysis.window_update)'"

	# 2018-03-20 by r4mind
	cmd_filter = "'(tcp || http) && !(tcp.analysis.flags && !tcp.analysis.window_update)'"
	# end
	os.system("tshark -r %s -w %s -F pcap -Y %s" % (sf, df, cmd_filter))

	return df



if __name__ == '__main__':
	compareData()