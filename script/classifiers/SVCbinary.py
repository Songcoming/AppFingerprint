#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# 2017-12-25 by r4mind

import sys
sys.path.append("..")

from features.statistical import statiFeature

sf = statiFeature('/tmp/toutiao.pcap', 1)
print(sf.X)
print(sf.X.shape)
