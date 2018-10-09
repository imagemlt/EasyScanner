#!/usr/bin/env python
# -*- coding: utf-8 -*- 
# File Name: testjoin.py
# Author: Image
# mail: malingtao1019@163.com
# Blog:http://blog.imagemlt.xyz
# Created Time: 2018年10月07日 星期日 21时57分58秒
import json
from __init__ import cmstypes



res={}

diguo={}

for per in cmstypes:
    key=per['name'].strip().lower()
    if 'diguocms' in key:
        diguo=per
        break
for per in cmstypes:
    key=per['name'].strip().lower()
    if 'diguocms' in key:
        continue
    if 'empirecms' in key:
        res[key]=per
        res[key]['content']+=diguo['content']
        res[key]['urls']+=diguo['urls']
        continue
    if not res.has_key(key):
        res[key]={'name':key,'content':[],'urls':[],'scripts':[]}
    res[key]['content']+=per['content']
    res[key]['urls']+=per['urls']
    res[key]['scripts']+=per['scripts']


output=[res[t] for t in res]

result=json.dumps(output)
f=open('fin.json','w')
f.write(result)
f.close()
