# -*- coding: utf-8 -*-
# Author:g0dlike
# CreateDate:2017年7月22日
import re
import requests


class SqliPOC(object):

    version = '1'
    author = 'g0dlike'
    createDate = '2017-7-22'
    updateDate = '2017-7-22'
    name = 'SQL Inject'
    vulType = 'SQL Injection'
    waf_info = "This page can't be displayed. Contact support for additional information"

    url = ''

    def attack(self):
        result = {}
        vul_url = '%s/?q=node\' and union select * from sec_test ' % self.url

        r = requests.get(vul_url, verify=False)

        if re.findall(self.waf_info, r.text):
            return True
        else:
            return False

    def info(self):

        print "name:" + self.name + "\n"
        print "version:" + self.version + "\n"
        print "author:" + self.author + "\n"
        print "createDate:" + self.createDate + "\n"
        print "updateDate:" + self.updateDate + "\n"
        print "vulType:" + self.vulType + "\n"






