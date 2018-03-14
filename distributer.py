#!/usr/bin/python
# -*- coding: UTF-8 -*-

import time
from celery import Celery
from config import conf_redis_backend,conf_redis_broker
import urllib
import urllib2
import hashlib
from fingerprints import *

distributer=Celery('distributer',broker=conf_redis_backend,backend=conf_redis_backend)

@distributer.task
def scan(url,cmsjobs):
    "TODO"
    res=[]
    for cms in cmsjobs:
        currentMark={"type":cms["name"],"credential":0}
        for u in cms["urls"]:
            currentu=url+'/'+u["addr"]
            try:
                response=urllib2.urlopen(currentu).read()
                m=hashlib.md5()
                m.update(response)
                if m.hexdigest()==u["md5"]:
                    currentMark["credential"]+=u["fullMark"]
                else:
                    currentMark["credential"]+=u["existMark"]
            except urllib2.URLError, e:
                continue
        res.append(currentMark)
    res.sort(key=lambda x:int(x["credential"]),reverse=True)
    return res[0]








