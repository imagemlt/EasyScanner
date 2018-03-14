#!/usr/bin/python
# -*- coding: UTF-8 -*-

from optparse import OptionParser
from distributer import scan
from fingerprints import *
import time


instructParser=OptionParser()
instructParser.add_option("-u",action="store",dest="url")
instructParser.add_option("-v",action="store_false",dest="verbose")

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
    print "[+]the url you want to scan:"+options.url
    cmslist=list_of_groups(cmstypes,5)
    applist=[]
    for cms in cmslist:
        applist.append(scan.delay(options.url,cms))
    result=[]
    while len(applist):
        for x in applist:
            if(x.ready()):
                result.append(x.get())
                applist.remove(x)
                print "[+]finished a task"
    result.sort(key=lambda x:int(x["credential"]),reverse=True)
    print "the url you scanned is most probably "+result[0]["type"]

if __name__=="__main__":
    main()