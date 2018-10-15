#!/usr/bin/python
# -*- coding: UTF-8 -*-

import time
from celery import Celery

from config import conf_redis_backend,conf_redis_broker,conf_redis_db_storage
import urllib
import socket
import urllib2
import hashlib
from fingerprints import *
import re
import random
import json
import time
import redis
from gevent import monkey

agents=json.loads(open('user_agent.json').read())

distributer=Celery('distributer',broker=conf_redis_backend,backend=conf_redis_backend)

@distributer.task
def scan(url,cmsname,user_agent="random",timeout=10,proxy_settings=None,interval=None,confirm=False):
        "TODO"
        global agents
        if(proxy_settings is not None):
            proxy=urllib2.ProxyHandler(proxy_settings)
            opener=urllib2.build_opener(proxy)
            urllib2.install_opener(opener)
        res=[]
        errorcount=0
        jobs=0

        session=redis.StrictRedis.from_url(conf_redis_db_storage)
        cmslist=[]

    #for cmsname in cmsjobs:
        while True:
            try:
                cms = json.loads(session.hget('cmslist',cmsname))#session.query(FingerPrints).filter(FingerPrints.cms==cmsname).all()
                break
            except Exception,e:
                print "[-]ERR:",e
                continue
        #cms={'name':cmsname,'urls':[],'content':[]}
        #for fingerprint in fingerprints:
        #    if(fingerprint.type=="hash"):
        #        cms['urls'].append({'fullMark':fingerprint.full_mark,'existMark':fingerprint.exist_mark,'md5':fingerprint.pattern,'addr':fingerprint.addr,'id':fingerprint.id})
        #    elif (fingerprint.type=='content'):
        #        cms['content'].append({'addr':fingerprint.addr,'data':fingerprint.pattern,'Mark':fingerprint.full_mark/3,'id':fingerprint.id})
        #cmslist.append(cms)


        #cms={'name':cmsnames,'urls':[],'content':[]}
        confirmed=False
        currentMark={"type":cms["name"],"credential":0,'fids':[]}
        visited_url=[]
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
                    currentMark['fids'].append({'id':u['id'],'level':2})

                    if(confirm):
                        currentMark['cid']=u['id']
                        currentMark['confirm']=True
                        confirmed=True
                        break
                elif u['addr'] not in visited_url:
                    currentMark["credential"]+=u["existMark"]
                    visited_url.append(u["addr"])
                    currentMark['fids'].append({'id':u['id'],'level':1})
            except socket.error,sockerr:
                print sockerr
                continue
            except urllib2.URLError,e:
                print e.message
                #print e.reason 
                continue
        if confirm and confirmed:
            print 'confirmed'
            return currentMark
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
                if re.search(c['data'],response):
                    currentMark["credential"] += c["Mark"]*3
                    currentMark['fids'].append({'id':c['id'],'level':2})
            except socket.error, sockerr:
                print sockerr
                continue
            except urllib2.URLError,e:
                print e.message
                #print e.reason
                continue
        #res.append(currentMark)

        currentMark['confirm']=confirmed
        return currentMark


#if __name__=='__main__':
#    from fingerprints import cmstypes
#    import sys
#    print scan(sys.argv[1],cmstypes[:10])





















