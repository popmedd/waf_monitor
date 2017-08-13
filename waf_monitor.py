# -*- coding: utf-8 -*-
# Author:g0dlike
# Create:2017年7月21日

import requests
import os
import sys
import time
import json
#from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
#requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from masscan import masscan
from my_nmap import my_nmap
import ConfigParser
import importlib
import logging
import logging.config
from common import get_config


# 通过发起Web请求请求确认是否是Web服务
def is_web_service(ip, port, web_type):

    if web_type == 'ssl':
        url = 'https://' + ip + ':' + port + '/'
        try:
            r = requests.get(url=url, verify=False, timeout=5)
            logger.info(json.dumps({'url': url, 'ip': ip, 'port': port, 'web_type': web_type}))
        except requests.RequestException as e:
            logger.debug(json.dumps({'url': url, 'except_msg': str(e)}))
            return False
    else:
        url = 'http://' + ip + ':' + port + '/'
        try:
            r = requests.get(url=url, verify=False, timeout=5)
            logger.info(json.dumps({'url': url, 'ip': ip, 'port': port, 'web_type': web_type}))
        except requests.RequestException as e:
            logger.debug(json.dumps({'url': url, 'except_msg': str(e)}))
            return False
    return True


# 获取存活的Web服务信息
def get_alive_web_service(ip_seg):

    engine_type = get_config('basic', 'engine')

    if engine_type == 'masscan':
        res = masscan_engine(ip_seg=ip_seg)
    elif engine_type == 'nmap':
        res = nmap_engine(ip_seg=ip_seg)

    # 将scan结果进行复查，筛除错误
    for x in range(len(res)-1, -1, -1):
        ip, port, web_type = res[x]
        check_result = is_web_service(ip=ip, port=port, web_type=web_type)
        if check_result is False:
            del res[x]

    return res


def nmap_engine(ip_seg):
    # 获取nmap输出路径
    output_dir = os.path.join(sys.path[0], 'nmap_output')
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    # 获取nmap输出文件名
    output_file = os.path.join(output_dir, time.strftime("%Y%m%d%H%m%S"))
    # 读取配置中nmap的参数并调用masscan
    nmap_max_rate = get_config('scan', 'max_rate')
    nmap_port_range = get_config('scan', 'port_range')
    res = my_nmap.run(ip_seg=ip_seg, output_file=output_file, rate=nmap_max_rate, port_range=nmap_port_range)

    return res

def masscan_engine(ip_seg):

    # 获取masscan输出路径
    output_dir = os.path.join(sys.path[0], 'masscan_output')
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)
    # 获取masscan输出文件名
    output_file = os.path.join(output_dir, time.strftime("%Y%m%d%H%m%S"))
    # 读取配置中masscan的参数并调用masscan
    masscan_max_rate = get_config('scan', 'max_rate')
    masscan_port_range = get_config('scan', 'port_range')
    res = masscan.run(ip_seg=ip_seg, output_file=output_file, rate=masscan_max_rate, port_range=masscan_port_range)

    return res


if __name__ == '__main__':

    # 配置logging过滤器
    logging.config.fileConfig('logging.conf')
    logger = logging.getLogger('waf_monitor')

    ip_seg_list = json.loads(get_config('basic', 'ip_seg'))['ip_seg']

    logger.debug('Action: start to find alive web port')

    # 开始执行检查
    for ip_seg in ip_seg_list:

        # Web端口获取
        web_res = get_alive_web_service(ip_seg)

        # poc执行检验waf功能
        logger.debug('Action: start to check waf protect function')
        check_result = []
        for x in web_res:

            # 随机时间间隔
            # 验证器，对于Connect Error的使用WAF API进行确认

            ip, port, web_type = x

            if web_type == 'http':
                url = "http://" + ip + ":" + port
            elif web_type == 'ssl':
                url = "https://" + ip + ":" + port

            logger.debug('Action: start to check for url\"' + url + '\"')

            # 调用poc
            poc_list = json.loads(get_config('poc', 'poc_msg'))
            tmp_check = {'ip': ip, 'port': port, 'web_type': web_type}
            for _poc in poc_list:
                poc_name = _poc['poc_name']
                class_name = _poc['class_name']

                # 动态载入poc模块和poc类
                try:
                    poc_mod = importlib.import_module('poc.'+poc_name)
                    poc_class = getattr(poc_mod, class_name)
                    poc_obj = poc_class()
                    poc_obj.url = url
                    poc_result = poc_obj.attack()
                    tmp_check[poc_class] = poc_result
                except Exception as e:
                    logger.debug('Error:' + str(e))

                if poc_result == True:
                    logger.info(json.dumps({'ip': ip, 'port': port, 'web_type': web_type, 'poc_name': poc_name, 'poc_result': str(poc_result)}))
                elif poc_result == False:
                    logger.error(json.dumps({'ip': ip, 'port': port, 'web_type': web_type, 'poc_name': poc_name, 'poc_result': str(poc_result)}))

            check_result.append(tmp_check)

        logger.debug('Result:' + str(check_result))









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



