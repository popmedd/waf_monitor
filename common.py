# -*- coding:utf-8 -*-
# Author:g0dlike
# Create:2017年8月7日

import os
import ConfigParser
import sys


# 读取配置
def get_config(section, option):

    conf_file = os.path.join(sys.path[0], 'waf_monitor.conf')
    cp = ConfigParser.SafeConfigParser()
    cp.read(filenames=conf_file)
    config_value = cp.get(section=section, option=option)

    return config_value