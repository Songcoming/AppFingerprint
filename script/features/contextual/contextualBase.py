#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2018-10-27 by r4mind

from scapy.all import *
from features.contextual.HTTP_SEND import sumhttp

import scapy_http.http as HTTP

class contBase():

	def __init__(self):
		self.useragent = []
		self.server = []
		self.contenttype = []
		self.connection = []
		self.acceptlanguage = []
		self.acceptencoding = []
		self.option = []


	def initHeaderInfo(self, filtedpcap):
		print("begin to init head info")
		self.filtedpcap = filtedpcap


	def generateConFea(self, pcapfiles):

		print(set(self.useragent))
		print(set(self.option))

		self.useragent = list(set(self.useragent))
		self.server = list(set(self.server))
		self.contenttype = list(set(self.contenttype))
		self.connection = list(set(self.connection))
		self.acceptlanguage = list(set(self.acceptlanguage))
		self.acceptencoding = list(set(self.acceptencoding))
		self.option = list(set(self.option))

		httpfealist = []

		for fp in pcapfiles:
			fphandle = rdpcap(fp)
			httpfea  = sumhttp(fphandle, self.useragent, self.server, self.connection, 
				self.option, self.contenttype)
			httpfealist.append(httpfea)

		return httpfealist


	def getHTTPHeaderInfo(self):
		pcapfiles = rdpcap(self.filtedpcap)

		useragent = []
		server = []
		contenttype = []
		connection = []
		acceptlanguage = []
		acceptencoding = []
		option = []

		for pcap in pcapfiles:
			if HTTP.HTTPRequest in pcap:
				header = pcap[HTTP.HTTPRequest].fields
				if 'User-Agent' in header:
					useragent.append(header['User-Agent'].decode("utf-8"))
				if 'Content-Type' in header:
					contenttype.append(header['Content-Type'].decode("utf-8"))
				if 'Accept-Language' in header:
					acceptlanguage.append(header['Accept-Language'].decode("utf-8"))
				if 'connection' in header:
					connection.append(header['connection'].decode("utf-8"))
				if 'Accept-Encoding' in header:
					acceptencoding.append(header['Accept-Encoding'].decode("utf-8"))

			elif HTTP.HTTPResponse in pcap:
				header = pcap[HTTP.HTTPResponse].fields
				if 'Server' in header:
					server.append(header['Server'].decode("utf-8"))
				if 'Content-Type' in header:
					contenttype.append(header['Content-Type'].decode("utf-8"))
				if 'X-Frame-Options' in header:
					option.append(header['X-Frame-Options'].decode("utf-8"))



		self.useragent.extend(useragent)
		self.server.extend(server)
		self.connection.extend(connection)
		self.contenttype.extend(contenttype)
		self.acceptlanguage.extend(acceptlanguage)
		self.acceptencoding.extend(acceptencoding)
		self.option.extend(option)

		print(set(self.useragent))
		print(set(self.server))
		print(set(self.connection))
		print(set(self.contenttype))
		print(set(self.acceptencoding))
		print(set(self.acceptlanguage))
		print(set(self.option))