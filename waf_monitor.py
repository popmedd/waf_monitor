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
import importlib

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

    masscan_max_rate = get_config('masscan', 'max_rate')
    masscan_port_range = get_config('masscan', 'port_range')
    res = masscan.run(ip_seg=ip_seg, output_file=output_file, rate=masscan_max_rate, port_range=masscan_port_range)

    for x in range(len(res)-1, -1, -1):
        ip, port, web_type = res[x]
        check_result = is_web_service(ip=ip, port=port, web_type=web_type)
        if check_result is False:
            del res[x]

    return res


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

        check_result = []
        for x in web_res:
            ip, port, web_type = x
            if web_type == 'http':
                url = "http://" + ip + ":" + port
            elif web_type == 'ssl':
                url = "https://" + ip + ":" + port

            poc_list = json.loads(get_config('poc', 'poc_msg'))

            tmp_check = {'ip': ip, 'port': port, 'web_type': web_type}
            for _poc in poc_list:
                poc_name = _poc['poc_name']
                class_name = _poc['class_name']

                try:
                    poc_mod = importlib.import_module('poc.'+poc_name)
                    poc_class = getattr(poc_mod, class_name)
                    poc_obj = poc_class()
                    poc_obj.url = url
                    poc_result = poc_obj.attack()
                    tmp_check[poc_class] = poc_result
                except Exception as e:
                    print e

                print ip + '---' + port + '---' + web_type + '---' + poc_name + '---' + poc_result

            check_result.append(tmp_check)










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



