#!/usr/bin/python
# -*- coding: UTF-8 -*-

from optparse import OptionParser
from distributer import scan
from celery.task.control import revoke
from fingerprints import *
from bs4 import BeautifulSoup
from config import *
import time
import json
import random
import requests
import sys
import os
from termcolor import colored, cprint
import redis

instructParser=OptionParser()
instructParser.add_option("-u",action="store",dest="url",help="url of the website")
instructParser.add_option("-v",action="store_false",dest="verbose",help="verbose mode")
instructParser.add_option("--user-agent",action="store",dest="ua",default="random",help="set the useragent, random for arbitrary")
instructParser.add_option("-t",action="store",dest="interval",default=0,type="float",help="delay time of each request")
instructParser.add_option("-p",action="store",dest="proxy",help="proxy list file to user")
instructParser.add_option("--timeout",action="store",dest="timeout",default=10,type='float',help="max waiting time of each request")
instructParser.add_option("-d",action="store_true",dest="debug",help="debug mode")
instructParser.add_option("--fast",action="store_true",dest="fast",help="fast confirm mode")
instructParser.add_option("--refresh",action="store_true",dest="refresh",help="refresh storage in redis")

def list_of_groups(init_list, childern_list_len):
    list_of_groups = zip(*(iter(init_list),) *childern_list_len)
    end_list = [list(i) for i in list_of_groups]
    count = len(init_list) % childern_list_len
    end_list.append(init_list[-count:]) if count !=0 else end_list
    return end_list


def refresh_redis():
    redisClient = redis.StrictRedis.from_url(conf_redis_db_storage)
    session = DBSession()
    print "[+]temp database not build yet,building temp database"
    cmslist = {}
    fingerprints = session.query(FingerPrints).all()
    for fp in fingerprints:
        if not cmslist.has_key(fp.cms):
            cmslist[fp.cms] = {'name': fp.cms, 'urls': [], 'content': []}
        if (fp.type == 'hash'):
            cmslist[fp.cms]['urls'].append({
                'fullMark': fp.full_mark,
                'existMark': fp.exist_mark,
                'md5': fp.pattern,
                'addr': fp.addr,
                'id': fp.id
            })
        elif (fp.type == 'content'):
            cmslist[fp.cms]['content'].append({
                'addr': fp.addr,
                'data': fp.pattern,
                'Mark': fp.full_mark,
                'id': fp.id
            })
    out_to_redis = {}
    for k in cmslist:
        out_to_redis[k] = json.dumps(cmslist[k])
    redisClient.hmset('cmslist', out_to_redis)
    session.close()

def main():
    options,args=instructParser.parse_args()

    if options.refresh:
        refresh_redis()
    if(not options.url):
        instructParser.print_help()
        return

    session = DBSession()
    redisClient=redis.StrictRedis.from_url(conf_redis_db_storage)
    temp=redisClient.hgetall('cmslist')
    if not options.refresh and not temp:
        refresh_redis()

    cms_in_db = session.query(FingerPrints.cms).distinct().all()

    cmstypes = [x.cms for x in cms_in_db]
    print colored('[+]avilable cmstypes: {}'.format(len(cmstypes)), 'cyan')
    print colored("[+]fetching content",'green')
    try:
        frontreqeust=requests.get(options.url,timeout=10)
    except Exception,e:
        print colored("[-]error accessing your url {}".format((e)),'red',attrs=['bold']),
        return 0
    headers=frontreqeust.headers
    content=frontreqeust.content
    anlyse=BeautifulSoup(content,"lxml")
    print colored("[+]the url you want to scan:"+options.url,'green')
    proxylist=[]
    if(options.proxy):
        try:
            proxylist=json.loads(open(options.proxy))
        except IOError,e:
            print colored("[-]proxy file error!",'red',attrs=['red'])
            return
    #cmslist=list_of_groups(cmstypes,5)
    applist=[]
    for cms in cmstypes:
        proxy=None
        if len(proxylist)>0:
            proxy=proxylist[random.randint(0,len(proxylist)-1)]
        applist.append(scan.delay(options.url,cms,user_agent=options.ua,timeout=options.timeout,proxy_settings=proxy,interval=options.interval,confirm=options.fast))
    result=[]
    strarrs = ['/', '|', '\\']
    total=len(applist)
    confirmed=False
    while len(applist):
        for x in applist:
            if confirmed:
                for x in applist:
                    revoke(x.id, Terminate=True)
                applist=[]
                break
            try:
                if(x.ready()):
                    current_result=x.get()
                    result.append(current_result)
                    #print current_result
                    if(options.fast and current_result['confirm']):
                        confirmed=True
                        #result.append(current_result)
                        break
                    #result.append(current_result)
                    applist.remove(x)
                    row,col=os.popen('stty size','r').read().split()
                    col=int(col)
                    progress="[+]finished: {}/{}[".format(total-len(applist),total)

                    progress+='#'*int((col-len(progress)-1)*(float((total-len(applist)))/total))
                    progress+='.'*(col-len(progress)-1)+']\r'
                    sys.stdout.write(colored(progress,'green'))
                    sys.stdout.flush()
                    #print "[+]finished %d tasks"% len(result)
            except KeyboardInterrupt:
                print colored("[-]user exited",'red')
                for x in applist:
                    revoke(x.id,Terminate=True)
                print colored("[-]all tasks revoked",'red')
                return 0
            #except Exception,e:
            #    print "an error accured:"+e.message
            #    exit(1)
    result.sort(key=lambda x:int(x["credential"]),reverse=True)
    print
    try:
        if(options.debug):
            print colored("[+]request headers:",'cyan')
            print colored("{}".format(headers),"cyan")
            print colored("[+]URL title:"+anlyse.title.text,'cyan')
    except Exception,e:
        print colored("[-]print basic info err: {}".format(e),'red',attrs=['bold'])
    if options.fast and confirmed:
        print colored("[+]the url you scanned is most probably "+current_result["type"].decode('unicode-escape'),'yellow',attrs=['bold','blink'])
        if(options.debug):
            print colored("[+]confirm fingerprint:",'cyan')
            fingerprint=session.query(FingerPrints).filter(FingerPrints.id==current_result['cid']).first()
            if fingerprint:
                print colored('\t- url:{},pattern:{}'.format(fingerprint.addr,fingerprint.pattern),'cyan')
        return
    if options.fast:
        print colored("[-]not hit evidence",'red')
    print colored("[+]the url you scanned is most probably "+result[0]["type"].decode('unicode-escape'),'yellow',attrs=['bold','blink'])
    if(options.debug):
        print colored("[+]matched fingerprints:",'cyan')
        for match in result[0]['fids']:
            fingerprint=session.query(FingerPrints).filter(FingerPrints.id==match['id']).first()
            if fingerprint:
                print colored('\t- url:{},pattern:{},level:{}'.format(fingerprint.addr,fingerprint.pattern,match['level']),'cyan')
    print colored("[+]top five probably answers:",'cyan')
    for m in result[:5]:
        print colored("\t[+]"+m["type"].decode('unicode-escape')+",credential:"+str(m["credential"]),'cyan')

if __name__=="__main__":
    main()
