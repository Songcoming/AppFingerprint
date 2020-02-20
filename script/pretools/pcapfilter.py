#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2017-12-14 by r4mind

import os
import getopt
import sys

def filter(sf):
	index =  sf[: : -1].index('/')
	dp    =  sf[: -index]
	fn    =  sf[-index: ].split('.')
	df    =  dp + fn[0] + "_aff." + fn[-1]

	cmd_filter = "'tcp && !(tcp.port == 80) && !(tcp.analysis.flags && !tcp.analysis.window_update)'"

	# 2018-03-20 by r4mind
	# cmd_filter = "'(tcp || http) && !(tcp.analysis.flags && !tcp.analysis.window_update)'"
	# end

	dfn = "../../../M_H/aff/for/enc/" + fn[0] + "_enc." + fn[-1]

	# cmd_filter = "'ip.host == 192.168.2.13 && (tcp || http) && !(tcp.analysis.flags && !tcp.analysis.window_update)'"
	os.system("tshark -r %s -w %s -F pcap -Y %s" % (sf, dfn, cmd_filter))

	return df

def main(argv): 
	srcfilepath = ''

	try:
		opts, args = getopt.getopt(argv, 'hs:')
	except getopt.GetoptError:
		print("filter.py -s <srcfilepath>")
		sys.exit(2)

	if opts == []:
		print("filter.py -s <srcfilepath>")
		sys.exit(2)

	for opt, arg in opts:
		if opt == '-h':
			print('filter.py -s <srcfilepath>')
			sys.exit()
		elif opt == '-s':
			srcfilepath = arg
			filter(srcfilepath)

if __name__ == '__main__':
	main(sys.argv[1:])