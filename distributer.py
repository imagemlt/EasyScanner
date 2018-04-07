#!/usr/bin/python
# -*- coding: UTF-8 -*-

import time
from celery import Celery
from config import conf_redis_backend,conf_redis_broker
import urllib
import urllib2
import hashlib
from fingerprints import *
import random
import json
import time

agents=json.loads(open('user_agent.json').read())

distributer=Celery('distributer',broker=conf_redis_backend,backend=conf_redis_backend)

@distributer.task
def scan(url,cmsjobs,user_agent="random",timeout=10,proxy_settings=None,interval=None):
    "TODO"
    global agents
    if(proxy_settings is not None):
        proxy=urllib2.ProxyHandler(proxy_settings)
        opener=urllib2.build_opener(proxy)
        urllib2.install_opener(opener)
    res=[]
    for cms in cmsjobs:
        currentMark={"type":cms["name"],"credential":0}
        for u in cms["urls"]:
            if interval is not None:
                time.sleep(interval)
            currentu=url+'/'+u["addr"]
            try:
                req=urllib2.Request(currentu)
                if user_agent!="random":
                    req.add_header('User-Agent',user_agent)
                else:
                    randpos=random.randint(0,len(agents)-1)
                    req.add_header('User-Agent',agents[randpos].encode('utf-8'))
                response=urllib2.urlopen(req,timeout=timeout).read()
                m=hashlib.md5()
                m.update(response)
                if m.hexdigest()==u["md5"].lower():
                    currentMark["credential"]+=u["fullMark"]
                else:
                    currentMark["credential"]+=u["existMark"]
            except Exception,e:
                print e.message
                continue
        for c in cms["content"]:
            currentu = url + '/' + c["addr"]
            try:
                req = urllib2.Request(currentu)
                if user_agent != "random":
                    req.add_header('User-Agent', user_agent)
                else:
                    randpos = random.randint(0, len(agents) - 1)
                    req.add_header('User-Agent', agents[randpos])
                response = urllib2.urlopen(req, timeout=timeout).read()
                if c["data"] in response:
                    currentMark["credential"] += c["Mark"]*3
            except:
                continue
        res.append(currentMark)
    res.sort(key=lambda x:int(x["credential"]),reverse=True)
    return res[0]








