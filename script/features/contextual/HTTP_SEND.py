from scapy.all import *
from sklearn.metrics import adjusted_rand_score
import scapy_http.http as HTTP
import numpy as np
import glob as g
from sklearn.externals import joblib
from sklearn.metrics import classification_report
from sklearn.linear_model import LogisticRegressionCV,LinearRegression,LogisticRegression
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt

# sum_content=['text/html','font','httpd','audio','text', 'application', 'text/html; charset=iso-8859-1', 
#             'text/html; charset=us-ascii', 'text/html; charset=utf-8', 'text/html; charset=ISO-8859-1', 
#             'text/html; charset=UTF-8', 'image', 'text/css', 'text/javascript', 'text/javascript; charset=UTF-8', 
#             'text/html; charset=utf-8; charset=utf-8', 'text/plain; charset=UTF-8', 'text/plain', 'text/plain; charset=utf-8', 
#             'text/javascript; charset=utf-8', 'text/xml; charset=utf-8', 'octet-stream', 'text/xml', 'text/html;charset=utf-8', 
#             'text/plain;charset=UTF-8', 'text/html; charset=gbk', 'text/javascript;charset=UTF-8', 'multipart', 
#             'text/plain;charset=ISO-8859-1', 'text/xml; charset=GB2312', 'text/javascript; charset=GBK', 'text/html; charset=GBK', 
#             'text/octet', 'text/html;charset=UTF-8', 'video']
language_dic=['en-bz', 'en-au', 'en-jm', 'en-ie', 'en-nz', 'en-tt', 'zh', 'zh-HK', 'en-us', '*', 'zh-CN', 'zh-cn', 'en', 'en-ca',
             'en-za', 'en-gb', 'zh-TW', 'en-US', 'de']
# connection=['keep-alive','keep-Alive','Keep-alive','Keep-Alive','close','Close']
# User_Agent=['', 'Post', 'sogou_ime', 'macrotest', 'Microsoft-WNS/6.3', 'java_installer', 
# 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/536.36 (KHTML, like Gecko) Chrome/42.0.2357.81 Safari/536.36', 
# 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/538.37 (KHTML, like Gecko) Chrome/44.0.2457.82 Safari/538.37', 
# 'SOGOU_POPUP_NEWS', 'urlRequest', 
# 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 
# 'SogouIme', 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.3; WOW64; Trident/7.0; LCJB;  QIHU 360SE)', 
# 'Mazilla/4.0', 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/539.41 (KHTML, like Gecko) Chrome/44.0.2458.85 Safari/539.41', 
# 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.143 Safari/537.36', 
# 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0) Gecko/20100101 Firefox/15.0', 
# 'Mozilla/5.0 (Windows NT 6.1;WOW64) AppleWebKit/537.37 (KHTML, like Gecko) Chrome/41.0.2273.88 Safari/537.37 OPR/29.0.1751.48', 
# 'JSONParser /1.0', 'Medunja Solodunnja 6.0.0', 'Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 5.1; Trident/5.0)', 
# 'Microsoft BITS/7.5', 'Mozilla/5.0', 
# 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; WOW64; Trident/7.0; .NET4.0E; .NET4.0C; .NET CLR 3.5.30729; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.3)', 
# 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; WOW64; Trident/7.0; .NET4.0E; .NET4.0C; .NET CLR 3.5.30729; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.3)', 
# 'NSIS_Inetc (Mozilla)', 'Mazilla/5.0', 
# 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36', 
# 'Firefox', 'Mozilla/4.0 (compatible; MSIE 8.0; Trident/4.0; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.0.04506.590; .NET CLR 3.0.04506.648; .NET CLR 3.5.21022; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)', 
# 'NSISDL/1.2 (Mozilla)', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; InfoPath.3)', 
# 'Updates downloader', 'SogouIME_newspopup', 
# 'Mozilla/5.0 (Windows NT 6.1;WOW64) AppleWebKit/537.35 (KHTML, like Gecko) Chrome/41.0.2272.88 Safari/537.35 OPR/28.0.1750.47', 
# 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko', 'AdvancedDownloadManager', 
# 'Microsoft Office Protocol Discovery', 'Microsoft-CryptoAPI/6.3', 
# 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.142 Safari/535.19', 
# 'Wget/1.11.4', 'Mozilla/4.0', 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)', 
# 'Google Update/1.3.25.0;winhttp;cup', 'Google Update/1.3.25.0;winhttp', 'Microsoft-CryptoAPI/6.1', 
# 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36', 
# 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.157 Safari/537.36', 
# 'Babylon', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E; ms-office; MSOffice 14)', 
# 'Mozilla/5.0 (Windows NT 6.1; rv:35.0) Gecko/20100101 Firefox/35.0', 'User-Agent', 
# 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1;Miser Report)', '2608cw-2', 'SogouIMEMiniSetup_imepopup', 
# 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.38 (KHTML, like Gecko) Chrome/45.0.2456.99 Safari/537.38', 
# 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2; WOW64; Trident/7.0; .NET4.0E; .NET4.0C; .NET CLR 3.5.30729; .NET CLR 2.0.50727; .NET CLR 3.0.30729; InfoPath.3; LCJB)', 
# 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)', 
# 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)', 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)', 
# 'Mozilla/5.0 (Windows NT 6.1; rv:34.0) Gecko/20100101 Firefox/34.0', 
# 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.99 Safari/537.36', 
# 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:5.0) Gecko/20100101 Firefox/5.0', 'Microsoft NCSI', 'Microsoft-WebDAV-MiniRedir/6.1.7601',
# 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.2) QQBrowser/6.0', 'AutoIt', 'SOGOU_POPUP', 'Microsoft Office Existence Discovery', 
# 'Post_Multipart', 'VersionDwl', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1) QQBrowser/6.0', 
# 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36', 
# 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.3; WOW64; Trident/7.0; LCJB)', 'SOGOU_UPDATER', 
# 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:39.0) Gecko/20100101 Firefox/39.0', 
# 'SearchProtect;3.1.5.104;Microsoft Windows 7 Enterprise;SP4E3F8059-9F3C-4A00-BAD1-5DEEA1045D8B', 'SogouPSI', 
# 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1)', 
# 'Mozilla/5.0 (Windows; Windows NT 7.1; en; rv:1.9.6.8) Gecko/20120122 Firefox/9.1.2', 
# 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36 QIHU 360EE', 
# 'Python-urllib/3.5', 'Wget/1.17.1 (linux-gnu)', 'Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)', 
# 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko', 'WinHttpClient', 'HD Player', 'Mazilla', 
# 'Microsoft Office/14.0 (Windows NT 6.1; Microsoft Word 14.0.4760; Pro)', 'IPM', 
# 'Mozilla/5.0 (Windows NT 6.1; rv:62.0) Gecko/20100101 Firefox/62.0', 'SogouIMEMiniSetup_RandSkin', 
# 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:2.0b8pre) Gecko/20101114 Firefox/4.0b8pre', 
# 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)', 'LogEvents', 
# 'Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; LCJB; rv:11.0) like Gecko', 'Opera', 'PC-WIN7', 
# 'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)', 'download manager', 
# 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)', 
# 'Debian APT-HTTP/1.3 (1.2.15)']
# server_=['', 'ECS (hhp/9AA5)', 'NWS_SPMid', 'ECS (fcn/4192)', 'openresty/1.11.2.5', 'ECS (pox/A5AC)', 'ECS (hhp/9AF0)', 
# 'nginx/d05e780ec0680fc74f35670fdff17c3a919ee4d3 U2FsdGVkX18RJLtniCdwoY1AsWsyVieIB8O7Ns38NaY=', 'ECS (ams/49B8)', 'Tengine', 
# 'Google Frontend', 'ngx_openresty/1.4.3.6', 'ECS (pox/A5B0)', 'Apache/2.4.18 (FreeBSD) PHP/5.5.32', 'WS-web-server', 'ECS (lcy/1D4C)', 
# 'QZHTTP-2.37.1', 'ECS (dca/24CF)', 'Tengine/2.2.2', 'ECS (ams/4991)', 'ECS (dca/24D3)', 'ECS (fcn/40D4)', 'Tengine/2.1.3_400', 
# 'ECS (hhp/9AE0)', 'X2_Platform', 'SCSImageServer', 'KSYUN ELB 1.0.0', 'ws-httpd', 'Apache/2.2.14 (Fedora)', 'sffe', 'ECS (lga/1395)', 
# 'Kestrel', 'ECS (lcy/1D41)', 'HRS/1.4.2', 'ImgHttp3.0.0', 'Apache/2.2.15 (CentOS)', 'ECS (dca/2490)', 'ECS (pox/A5C7)', 
# 'Microsoft-IIS/8.0', 'httpserver', 'QRATOR', 'Apache/2.4.10 (Debian)', 'ECS (via/F340)', 'ECS (pox/A5B8)', 'ECS (hhp/9AA0)', 
# 'YouTube Frontend Proxy', 'ECS (pox/A5C4)', 'elb', 'cloudflare', 'ECS (hhp/9AC1)', 'ECS (dca/24CE)', 'ECS (hhp/9ADD)', 
# 'Apache/2.2.3 (Oracle)', 'ECS (hhp/9A9B)', 'ECS (ord/26C1)', 'httpsf2', 'QWS', 'ECS (lcy/1D2D)', 'cpsrvd', 'Golfe2', 
# 'Mikrotik HttpProxy', 'nginx/1.10.2', 'ECS (ams/49C6)', 'ECS (hhp/9AC2)', 'nginx/1.10.1', 'ECS (dca/24FA)', 'ECS (dca/246E)', 
# 'nginx/1.12.1', 'ECS (lcy/1D2B)', 'ECS (lcy/1D45)', 'mws', 'ECS (via/F344)', 'Microsoft-IIS/7.0', 'ECS (hhp/9AB5)', 
# 'Omniture DC/2.0.0', 'ECS (ams/49F2)', 'nginx/1.11.6', 'Adtech Adserver', 'ECAcc (lha/8D2A)', 'nginx/1.10.3', 'ECS (lcy/1D3F)', 
# 'nginx/1.0.15', 'CLOUD ELB 1.0.0', 'ECS (lcy/1D31)', 'ECS (lcy/1D1D)', 'openresty/1.9.15.1', 'nginx/1.2.6', 'ECS (lcy/1D59)', 
# 'CloudStorage', 'ECS (via/F346)', 'ECS (hhp/9A97)', 'ECS (hhp/9A9F)', 'marco/2.6', 'ECS (lcy/1D2E)', 'ECS (hhp/9AA2)', 'CDN_NWS', 
# 'ECS (pox/A5DA)', 'ECS (dca/2472)', 'downloads', 'ECS (hhp/9A89)', 'ECS (fcn/41A4)', 'ECS (hhp/9A8F)', 'AmazonS3', 
# 'nginx/1.14.0 (Ubuntu)', 'ECS (lcy/1D40)', 'Windows-Azure-Blob/1.0 Microsoft-HTTPAPI/2.0', 'ECS (ska/F718)', 'ECS (hhp/9AB2)', 
# 'JSP3/2.0.14', 'ECS (fcn/4190)', 'ECS (lcy/1D43)', 'cloudflare-nginx', 'ECS (fcn/40D8)', 
# 'Apache/2.4.12 (Unix) OpenSSL/1.0.1e-fips mod_bwlimited/1.4 PHP/5.4.39', 'ECS (lcy/1D64)', 'nws_ocmid_hy', 'AkamaiGHost', 
# 'nginx/1.13.12', 'BWS/1.0', 'ECS (fcn/40FE)', 'openresty/1.13.6.2', 'mafe', 'openresty', 'Microsoft-IIS/6.0', 'nginx/1.6.2', 
# 'ECS (lcy/1D4E)', 'ECS (lcy/1D51)', 'ClientMapServer', 'HTTP Load Balancer/1.0', 'ECAcc (hkc/BDD1)', 'ECS (dca/2494)', 
# 'ECS (hhp/9AB0)', 'Microsoft-IIS/10.0', 'nginx/1.5.7', 'ECS (lcy/1D5A)', 'ECS (pox/A5D7)', 'ECS (dfw/5624)', 'ECS (lcy/1D42)', 
# 'ECS (lcy/1D52)', 'Apache-Coyote/1.1', 'Microsoft-IIS/7.5', 'ECS (hhp/9AB8)', 'ECS (fcn/41A9)', 'Apache4Miaozhen 2.2.4', 
# 'ECS (hhp/9AB4)', 'lighttpd', 'ECS (pox/A5AE)', 
# 'nginx/d05e780ec0680fc74f35670fdff17c3a919ee4d3 U2FsdGVkX19BkmKKBCA4W7PCuTNWpdhKibM0m5cXp0o=', 'ocsp_responder', 'ECS (via/F33F)', 
# 'ECS (dca/53FA)', 'ECAcc (lha/8C8F)', 'Apache/2.2.31 (CentOS)', 'ECS (hhp/9ACB)', 'ECS (via/F339)', 'ECS (fcn/40DA)', 
# 'ECS (dca/5325)', 'cafe', 'ECS (hhp/9AA3)', 'Apache', 'ECS (hhp/9ABD)', 'Nginx', 'ECS (hhp/9AA4)', 'ECS (hhp/9A92)', 'ECS (dca/24A4)', 
# 'ECS (hhp/9AD9)', 'ESF', 'ECS (via/F33E)', 'nginx/1.0.11', 'ECS (hhp/9AD0)', 'ECS (lcy/1D6E)', 'NWS_TCloud_S2', 'ECS (ams/D034)', 
# 'nginx/0.6.39', 'ECS (lcy/1D24)', 'ECS (hhp/9ACF)', 'ECS (hhp/9AC0)', 'ECS (dca/2495)', 'ECS (fcn/41A7)', 
# 'Apache/2.4.6 (CentOS) PHP/5.6.33', 'nginx/1.8.1', 'ECS (lcy/1D2A)', 'ECS (dca/53F7)', 'ECS (hhp/9AB1)', 'nginx/1.10.3 (Ubuntu)', 
# 'ECS (hhp/9AA9)', 'ECS (hhp/9ABA)', 'nws_supermid_hy', 'JDWS/1.0.0', 'ECS (lcy/1D21)', 'ECS (fcn/41D7)', 'ECS (waw/17D4)', 
# 'nginx/1.11.5', 'Oracle-Application-Server-11g', 'ECS (fcn/40AD)', 'nginx/1.9.15', 'ECS (dca/24DA)', 'Apache/2.4.18 (Ubuntu)', 
# 'ECS (ams/D051)', 'ECS (fcn/40FB)', 'ECS (waw/17BA)', 'ECS (hhp/9A9A)', 'Boa/0.93.15', 'Microsoft-IIS/8.5', 'ECS (hhp/9A95)', 
# 'Apache/2.4.34 (Unix)', 'JRun Web Server', 'ECS (lga/1392)', 'SWS', 'nginx/1.6.3', 'ECS (lcy/1D6F)', 'ECS (fcn/4186)', 
# 'ECS (pox/A5DF)', '3Gdown_DK', 'ECS (via/F342)', 'Apache/2.4.6 (CentOS) mpm-itk/2.4.7-04 OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16', 
# 'GFW', 'ECS (hhp/9A96)', 'ECS (hhp/9AD8)', 'ECS (dca/5327)', 'ECS (lcy/1D6D)', 'ECS (lcy/1D1B)', 'ECS (hhp/9AC8)', 'AMO-cookiemap/1.1', 
# 'ECS (lcy/1D73)', 'ECS (ams/49A4)', 'ECS (fcn/40FD)', 'Apache/2.4.25 (Debian)', 'ECS (dfw/F4AB)', 'Microsoft-HTTPAPI/2.0', 'NWS_CDN_P1', 
# 'BigIP', 'ECS (hhp/9A88)', 'ECS (dca/24D7)', 'nginx/1.13.4', 'nginx/1.9.14', 'ECS (fcn/41AA)', 'DynDNS-CheckIP/1.0.1', 'ECS (waw/17A4)', 
# 'ECS (hhp/9AA1)', 'DnionOS/1.11.2.4_2_13', 'ECS (lga/138C)', 'QZHTTP-2.38.18', '0W/0.8c', 'ECS (lcy/1D56)', 'ECS (dca/5324)', 
# 'Apache 1.0/SinkSoft', 'netease-nginx', 'ECS (fcn/40E5)', 'ECS (lcy/1D2F)', 'NWS_TCloud_S1', 'nginx/1.8.0', 'Apache/2', 'Play', 
# 'ECS (pox/A5DB)', 'DynDNS-CheckIP/1.0', 'ECS (hhp/9A87)', 'Oracle-HTTP-Server', 'ECS (lcy/1D50)', 'ECS (lcy/1D54)', 'ECS (via/F349)', 
# 'ECAcc (frc/8E98)', 'nginx/1.4.6 (Ubuntu)', 'ECS (sgb/C6CA)', 'NWS_Oversea_Domestic_Mid', 'Tencent Login Server/2.0.0', 
# 'nginx/d05e780ec0680fc74f35670fdff17c3a919ee4d3 U2FsdGVkX19HE6CYeAcK/+GWkLeGzM/4hIv7qdH0wlE=', 'nginx/1.14.0', 'apache', 
# 'QZHTTP-2.38.17', 'ECS (lcy/1D28)', 'ECS (hhp/9ABC)', 'Apache/2.4.7 (Ubuntu)', 'NWS_SP', 'NginX', 'nginx/1.0.12', 'ECS (lcy/1D32)', 
# 'ECS (fcn/418D)', 'Varnish', 'ECS (lcy/1D53)', 'nginx', 'ECS (fcn/40E9)', 'ECS (sto/DB56)', 'stgw/1.3.6.2_1.13.5', 'ECS (ska/F70C)', 
# 'ECS (lcy/1D3C)', 'DPS/1.4.16', 'ECS (ord/4CFD)', 'ECS (hhp/9AC9)', 'X2S_Platform', 'ECS (hhp/9AAF)', 'ECS (lcy/1D38)', 
# 'ECS (lga/1384)', 'ECS (ams/49B7)', 'nginx/1.4.1', 'Cdn Cache Server V2.0', 'ECS (hhp/9ACA)', 'ECS (pox/A5AA)', 'LiteSpeed', 
# 'XTServer', 'ECS (ams/D1E9)', 'ECS (lcy/1D34)', 'ECS (lcy/1D4B)', 'ECS (hhp/9A93)', 'tws', 'ECS (lcy/1D62)', 'nginx/1.1.19', 
# 'NetDNA-cache/2.2', 'yunjiasu-nginx', 'nginx/1.4.7', 'Apache/2.2.22 (Debian)', 'ECS (lcy/1D44)', 'ECS (dca/2469)', 
# '*******/*.**.*.*', 'ECS (lcy/1D47)', 'ECS (lcy/1D74)', 'ECS (lcy/1D4F)', 'nginx/1.12.2']
Accept_encoding=['compress', 'gzip','deflate','identity','*']
# options=['DENY',"SAMEORIGIN",'ALLOW-FROM']

def sumhttp(flow, User_Agent, server_, connection, options, sum_content):
    sum_http=[]
    content_typelist = np.zeros((1, len(sum_content)))
    code=0
    contentbytes = 0
    feature_ord = np.zeros((1, len(language_dic)))
    location = 0
    Last_Modified = 0
    connectionlist = np.zeros((1, len(connection)))
    Set_Cookie = 0
    Expires = 0
    serverlist = np.zeros((1, len(server_)))
    accept_encoding = np.zeros((1, len(Accept_encoding)))
    User_Agentlist = np.zeros((1, len(User_Agent)))
    option=[0,0,0]
    transfer=0

    contentTlist = []
    serverList = []
    userAlist = []

    for pcap in flow:

        # content_typelist = np.zeros((1, 32))
        # feature_ord = np.zeros((1, 19))
        # connectionlist = np.zeros((1, 6))
        # serverlist = np.zeros((1, 318))
        # accept_encoding = np.zeros((1, 5))
        # User_Agentlist = np.zeros((1, 102))
        
        # code=0
        # in_bytes, out_bytes = 0, 0
        # location = 0
        # Last_Modified = 0
        # Set_Cookie = 0
        # Expires = 0
        # option=[0,0,0]
        # transfer=0


        if HTTP.HTTPRequest in pcap:
            http_header = pcap[HTTP.HTTPRequest].fields
            if 'Content-Type' in http_header: # ÅÐ¶ÏContent-Type
                content_type = http_header['Content-Type'].decode("utf-8")
                if content_type in sum_content:
                    i = sum_content.index(content_type)
                    content_typelist[0][i] = 1
                # else:
                #     content_type =  (content_type.split('/'))[0]
                #     content_typelist[0][sum_content.index(content_type)]=1
            if 'Content-Length' in http_header: # ½ø³ö×Ö½ÚÊý
                # if pcap.sport == 80:
                #     in_bytes += int(http_header['Content-Length'].decode("utf-8"))
                # else:
                #     out_bytes += int(http_header['Content-Length'].decode("utf-8"))
                contentbytes += int(http_header['Content-Length'].decode("utf-8"))
            if 'Accept-Language' in http_header:
                accept_language = http_header['Accept-Language'].decode("utf-8")
                accept_language = accept_language.split(',')
                for i in accept_language:
                    if len(i) <= 5:
                        feature_ord[0][language_dic.index(i)] = 1
                    else:
                        i = i.split(';')[0]
                        feature_ord[0][language_dic.index(i)] = 1
            if 'connection' in http_header:
                connectionlist[0][connection.index(http_header['connection'].decode("utf-8"))] = 1
            if 'Accept-Encoding' in http_header:
                encoding=http_header['Accept-Encoding'].decode("utf-8")
                encoding=encoding.split(',')
                for i in encoding:
                    i=i.strip()
                    if len(i)<=8:
                        if i[0]=='*':
                             index = Accept_encoding.index("*")
                             accept_encoding[0][index] = 1
                        else:
                            index = Accept_encoding.index(i)
                            accept_encoding[0][index] = 1
                    else:
                        i=i.split(';')[0].strip()
                        index = Accept_encoding.index(i)
                        accept_encoding[0][index] = 1
            if 'User-Agent' in http_header:
                userAlist.append(http_header['User-Agent'].decode("utf-8"))
                index = User_Agent.index(http_header['User-Agent'].decode("utf-8"))
                User_Agentlist[0][index] = 1
        elif HTTP.HTTPResponse in pcap:
            http_header = pcap[HTTP.HTTPResponse].fields
            if 'Content-Type' in http_header:
                content_type = http_header['Content-Type'].decode("utf-8")
                if content_type in sum_content:
                    i = sum_content.index(content_type)
                    content_typelist[0][i] = 1
                # else:
                #     content_type = (content_type.split('/'))[0]
                #     index=sum_content.index(content_type)
                #     content_typelist[0][index] = 1
            if 'Status-Line' in http_header:
                code=int(( (http_header['Status-Line'].decode("utf-8")).split())[1])
            if 'Content-Length' in http_header:
                # if pcap.sport == 80 :
                #     in_bytes += int(http_header['Content-Length'].decode("utf-8"))
                # else:
                #     out_bytes +=int(http_header['Content-Length'].decode("utf-8"))
                contentbytes += int(http_header['Content-Length'].decode("utf-8"))
            if 'Location' in http_header:
                location = 1
            if 'Last_Modified' in http_header:
                Last_Modified = 1
            if 'Set-Cookie' in http_header:
                Set_Cookie = 1
            if 'Expires' in http_header:
                Expires = 1
            if 'Server' in http_header:
                serverList.append(http_header['Server'].decode("utf-8"))
                index=server_.index(http_header['Server'].decode("utf-8"))
                serverlist[0][index]=1
            if "X-Frame-Options" in http_header:
                index=options.index(http_header["X-Frame-Options"].decode("utf-8"))
                option[index]=1
            if  "Transfer-Encoding" in http_header:
                transfer=1

        else:
            continue

    content_typelist1=content_typelist.flatten().tolist()

    content_typelist1.append(code)
    content_typelist1.append(contentbytes)
    feature_ord1=feature_ord.flatten().tolist()
    content_typelist1.extend(feature_ord1)
    content_typelist1.append(location)
    content_typelist1.append(Last_Modified)
    connectionlist1=connectionlist.flatten().tolist()
    content_typelist1.extend(connectionlist1)
    content_typelist1.append(Set_Cookie)
    content_typelist1.append(Expires)
    serverlist1=serverlist.flatten().tolist()
    content_typelist1.extend(serverlist1)
    accept_encoding1= accept_encoding.flatten().tolist()
    content_typelist1.extend(accept_encoding1)
    User_Agentlist1=User_Agentlist.flatten().tolist()
    content_typelist1.extend(User_Agentlist1)
    content_typelist1.extend(option)
    content_typelist1.append(transfer)
    return content_typelist1

if __name__ == "__main__":
    good_pcap_files=g.glob('G:\\pcap\\http\\good_2000train\\*.pcap')
    element=[]
    y=[]


    for good_pcap in good_pcap_files:
         good_pcap=rdpcap(good_pcap)
         every_good=sumhttp(good_pcap)
         if every_good:
            element.append(every_good)

            y.append(0)



    malware_pcap_files = g.glob('G:\\pcap\\http\\malware_2000train\\*.pcap')
    for malware_pcap in malware_pcap_files:
        malware_pcap = rdpcap(malware_pcap)
        every_malware = sumhttp(malware_pcap)
        # i=0
        if every_malware:
           element.append(every_malware)
           y.append(1)
    # file = open('http_list1.txt', 'w')
    # for i in range(len(element)):
    #     for j in range(len(element[i])):
    #         if j==len(element[i])-1:
    #             file.write(str(element[i][j])+'\n')
    #         else:
    #             file.write(str(element[i][j])+' ')


    # file.close()
        # if every_malware==None and i==1:
        #      i=i+1
             # print(malware_pcap)
             # break
             # element.append(every_malware)
             # y.append(1)

    X_train, X_test, Y_train, Y_test = train_test_split(element, y, test_size=0.1, random_state=0)
    lr = LogisticRegressionCV(multi_class="ovr", fit_intercept=True, Cs=np.logspace(-2, 2, 10), cv=2, penalty="l1",
                               solver='liblinear', tol=0.01)
    re = lr.fit(X_train, Y_train)
    R = re.predict(X_test)
    joblib.dump(re, 'http3')
    print(classification_report(y_true=Y_test, y_pred=R))
#     fig, ax = plt.subplots(figsize=(8, 5), dpi=80)
#     selsection=["lbfgs",'sag','liblinear']
#     score=[]
#     l=[1,2,3,4,5]
#     for m in  selsection:
#          for i in l:
#             lr = LogisticRegressionCV(multi_class="ovr", fit_intercept=True, Cs=np.logspace(-2, 2, 20), cv=2, penalty="l2",solver=m, tol=0.01)
#             re = lr.fit(X_train, Y_train)
#             score.append(re.score( X_test,Y_test))
#     ax.plot(l , df["sale"] , linestyle = "--" , linewidth = 2 , color = (222/255,89/255,155/255))
# #ÏßÌõÀàÐÍÎª¡°--¡±£¬ÏßÌõ¿í¶ÈÎª2£¬ÏßÌõÑÕÉ«ÎªRGB£¨222,89,155£©
# ax.set(xlabel = "date" , ylabel = "sale" , title = "plot")
# plt.show()

    # X,labels_true=X_test,Y_test
    # nums=range(1,10)
    # fig=plt.figure()
    # ax=fig.add_subplot(1,1,1)
    # linkages=["lbfgs",'sag','liblinear']
    # markers="+o*"
    # for i,linkage in enumerate(linkages):
    #     ARIs=[]
    #     for num in nums:
    #         clst=LogisticRegressionCV(multi_class="ovr", fit_intercept=True, Cs=np.logspace(-2, 2, 20), cv=2, penalty="l2",solver=linkage, tol=0.01)
    #         clst=clst.fit(X_train, Y_train)
    #         predicted_labels=clst.predict(X_test)
    #         ARIs.append(adjusted_rand_score(labels_true, predicted_labels))
    #     ax.plot(nums,ARIs,marker=markers[i],label="linkage:%s"%linkage)
    #
    # ax.set_xlabel("num")
    # ax.set_ylabel("ARI")
    # ax.legend(loc="best")
    # fig.suptitle("LogisticRe")
    # plt.show()

    # ARIs=[]
    # for i in nums:
    #     clst=LogisticRegressionCV(multi_class="ovr", fit_intercept=True, Cs=np.logspace(-2, 2, 20), cv=2, penalty="l1",solver='liblinear', tol=0.01)
    #     clst=clst.fit(X_train, Y_train)
    #     predicted_labels=clst.predict(X_test)
    #     ARIs.append(adjusted_rand_score(labels_true, predicted_labels))
    # ax.plot(nums,ARIs)
    # plt.show()
    # print(classification_report(y_true=Y_test, y_pred=predicted_labels))
if __name__ == "__main__":
    malware_pcap_files=g.glob('G:\\pcap\\http\\malware_test\\*.pcap')
    element=[]
    y=[]

#
    for malware_pcap in malware_pcap_files:
         malware_pcap=rdpcap(malware_pcap)
         every_malware=sumhttp(malware_pcap)
         if every_malware:
            element.append(every_malware)

            y.append(1)
    good_pcap_files = g.glob('G:\\pcap\\http\\good_test\\*.pcap')

    for good_pcap in good_pcap_files:
        good_pcap = rdpcap(good_pcap)
        every_good = sumhttp(good_pcap)
        if every_good:
            element.append(every_good)

            y.append(0)

    predict=re.predict(element)
    print(classification_report(y_true=y, y_pred=predict))