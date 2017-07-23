# -*- coding: utf-8 -*-
# Author:g0dlike
# Create:2017年7月21日

import requests
import os
import sys
import time
import json
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from masscan import masscan
import ConfigParser


def is_web_service(ip, port, web_type):

    if web_type == 'ssl':
        url = 'https://' + ip + ':' + port + '/'
        print url
        try:
            r = requests.get(url=url, verify=False, timeout=5)
        except requests.RequestException as e:
            print url + "\n"
            print e
            return False
    else:
        try:
            url = 'http://' + ip + ':' + port + '/'
            print url
            r = requests.get(url=url, verify=False, timeout=5)
        except requests.RequestException as e:
            print url + "\n"
            print e
            return False
    return True


def get_alive_web_service(ip_seg):
    output_dir = os.path.join(sys.path[0], 'masscan_output')
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    output_file = os.path.join(output_dir, time.strftime("%Y%m%d%H%m%S"))
    res = masscan.run(ip_seg=ip_seg, output_file=output_file)

    for x in range(len(res)-1, -1, -1):
        ip, port, web_type = res[x]
        check_result = is_web_service(ip=ip, port=port, web_type=web_type)
        if check_result is False:
            del res[x]

    return res

'''
waf_session_id = login_waf("192.200.0.87", "8083", "admin", "Crc_waf7")
sites_list = get_all_site("192.200.0.87", "8083", waf_session_id)

if r'DMZ' not in sites_list:
    print "Error: DMZ not in sites"
    exit()

server_group_list = get_all_server_group("192.200.0.87", "8083", waf_session_id, "DMZ")
'''


def get_config(section, option):

    conf_file = os.path.join(sys.path[0], 'waf_monitor.conf')
    cp = ConfigParser.SafeConfigParser()
    cp.read(filenames=conf_file)
    config_value = cp.get(section=section, option=option)

    return config_value

if __name__ == '__main__':

    ip_seg_list = json.loads(get_config('basic', 'ip_seg'))['ip_seg']

    for ip_seg in ip_seg_list:
        web_res = get_alive_web_service(ip_seg)

        from poc import poc_xss

        check_result = []
        for x in web_res:
            ip, port, web_type = x
            tmp_check = {}
            if web_type == 'http':
                url = "http://" + ip + ":" + port
            elif web_type == 'ssl':
                url = "https://" + ip + ":" + port

            check_xss = poc_xss.XssPOC()
            check_xss.url = url
            check_xss_result = check_xss.attack()

            if check_xss_result is True:
                print ip + '---' + port + '---' + web_type + '---' + 'protected'
            else:
                print ip + '---' + port + '---' + web_type + '---' + 'not in protected'









#######################################################################################
#  总体步骤
#  1、寻找并确认所有开着的互联网Web端口
#  2、排除检查的例外端口（路由器或网关的Web端口）
#  3、寻找映射关系列表，找到互联网端口对应的DMZ主机IP和端口（时间较长，操作前置）
#  4、寻找WAF防护范围内的所有IP和端口，以及相关的ServerGroupName、ServiceName
#  5、对比映射关系表和WAF防护表，查看并记录不在防护范围内的Web端口
#  6、对所有互联网Web端口发起Poc检查
#  7、查找对应日志是否存在，对不存在的进行记录
#  8、对所有防护缺失的站点进行告警
#######################################################################################



