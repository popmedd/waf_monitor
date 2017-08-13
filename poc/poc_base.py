# -*- coding: utf-8 -*-
# Author:g0dlike
# CreateDate:2017年8月12日
# UpdateDate:2017年8月13日
import re
import requests
import common
import time


def re_try(max_retry=int(common.get_config('poc', 'poc_max_retry'))):
    def decorator(function):
        def wrapper(self, *args, **kwargs):
            try:
                return function(self, *args, **kwargs)
            except Exception, e:
                if self.count < max_retry:
                    self.count += 1
                    time.sleep(1)
                    print "Retry the %d times" % self.count
                    return wrapper(self, *args, **kwargs)
                else:
                    # 超过重试次数,暂时当做已被封禁，后续使用waf_api处理
                    return True

        return wrapper
    return decorator


class BasePoc(object):

    version = '1.0'
    author = 'g0dlike'
    createDate = '2017-1-1'
    updateDate = '2017-1-1'
    name = 'BasePoc'
    vulType = 'Unknown'
    waf_info = ''

    count = 0
    url = ''

    def __init__(self):
        self.waf_info = common.get_config('waf_option', 'waf_protect_msg')

    def attack(self):
        pass

    def is_in_protected(self, r):
        if re.findall(self.waf_info, r.text):
            return True
        else:
            return False

    def info(self):
        print "Name:" + self.name
        print "Version:" + self.version
        print "Author:" + self.author
        print "CreateDate:" + self.createDate
        print "UpdateDate:" + self.updateDate
        print "VulType:" + self.vulType + "\n"


