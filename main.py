#!/usr/bin/python
# -*- coding: UTF-8 -*-

from optparse import OptionParser
from distributer import scan
from celery.task.control import revoke
from fingerprints import *
from bs4 import BeautifulSoup
import time
import json
import random
import requests


instructParser=OptionParser()
instructParser.add_option("-u",action="store",dest="url")
instructParser.add_option("-v",action="store_false",dest="verbose")
instructParser.add_option("--user-agent",action="store",dest="ua",default="random")
instructParser.add_option("-t",action="store",dest="interval",default=0)
instructParser.add_option("-p",action="store",dest="proxy")
instructParser.add_option("--timeout",action="store",dest="timeout",default=10)

def list_of_groups(init_list, childern_list_len):
    list_of_groups = zip(*(iter(init_list),) *childern_list_len)
    end_list = [list(i) for i in list_of_groups]
    count = len(init_list) % childern_list_len
    end_list.append(init_list[-count:]) if count !=0 else end_list
    return end_list


def main():
    options,args=instructParser.parse_args()
    if(not options.url):
        instructParser.print_help()
        return
    print "[+]fetching cotent"
    try:
        frontreqeust=requests.get(options.url,timeout=10)
    except Exception,e:
        print "[-]error accessing your url",e
        return 0
    headers=frontreqeust.headers
    content=frontreqeust.content
    anlyse=BeautifulSoup(content,"lxml")
    print "[+]the url you want to scan:"+options.url
    proxylist=[]
    if(options.proxy):
        try:
            proxylist=json.loads(open(options.proxy))
        except IOError,e:
            print "[-]proxy file error!"
            return
    cmslist=list_of_groups(cmstypes,5)
    applist=[]
    for cms in cmslist:
        proxy=None
        if len(proxylist)>0:
            proxy=proxylist[random.randint(0,len(proxylist)-1)]
        applist.append(scan.delay(options.url,cms,user_agent=options.ua,timeout=options.timeout,proxy_settings=proxy,interval=options.interval))
    result=[]
    while len(applist):
        for x in applist:
            try:
                if(x.ready()):
                    result.append(x.get())
                    applist.remove(x)
                    print "[+]finished a task"
            except KeyboardInterrupt:
                print "[-]user exited"
                for x in applist:
                    revoke(x.id,Terminate=True)
                print "[-]all tasks revoked"
                return 0
            except Exception,e:
                print "an error accured:"+e.message
                continue
    result.sort(key=lambda x:int(x["credential"]),reverse=True)
    try:
        print "[+]request headers:"
        print headers
        print "[+]URL title:"+anlyse.title.text
    except Exception,e:
        print "[-]print basic info err:",e
    print "[+]the url you scanned is most probably "+result[0]["type"].decode('unicode-escape')
    print "\t[+]top five probably answers:"
    for m in result[:5]:
        print "\t\t[+]"+m["type"].decode('unicode-escape')+",credential:"+str(m["credential"])

if __name__=="__main__":
    main()
