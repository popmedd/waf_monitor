# -*- coding:utf-8 -*-
# Author:g0dlike
# Create:2017年8月7日

import os
import shutil
import platform
import logging
from common import get_config
from xml.dom.minidom import parse
import xml.dom.minidom


def run(ip_seg, output_file, rate=500, port_range='1-65535'):

    logger = logging.getLogger('waf_monitor')

    # 对于已存在的文件进行剪切和备份
    if os.path.isfile(output_file):
        print "Warning:Output File already exist"
        shutil.move(output_file, output_file+".bak")

    # 对输入参数进行处理
    ip_seg = str(ip_seg).translate(None, ';|&')
    rate = str(int(rate))

    # 获取当前操作系统类型，选择合适的nmap程序并整合及执行命令
    path = get_config('scan', 'nmap_path')
    sys_type = platform.system()
    if sys_type == 'Windows':
        logging.error('Error: Use nmap in Windows')
        exit()
    elif sys_type == 'Linux':
        pass
    else:
        pass

    scan_command = str.format("%s -p%s %s --script=banner -oX %s --max-rate %s -version-all"%(path, port_range, ip_seg, output_file, rate))

    logger.debug('Action:' + scan_command)
    os.system(scan_command)

    # 调用xml分析功能
    res = _parse_xml(output_file=output_file)

    logger = logging.getLogger('waf_monitor')
    logger.debug("Action: masscan.py return" + str(res))

    return res


def _parse_xml(output_file):
    parse_list = []
    dom_tree = parse(output_file)
    collection = dom_tree.documentElement

    hosts = collection.getElementsByTagName('host')

    for host in hosts:
        ip = ''
        port = ''
        web_type = ''

        addresses = host.getElementsByTagName('address')

        # 获取xml中host标签下所有address
        for address in addresses:
            if address.getAttribute('addrtype') == 'ipv4':
                ip = address.getAttribute('addr')

        # 获取xml中host标签下所有port
        ports = host.getElementsByTagName('port')
        for tag_port in ports:

            # 获取符合条件的port、service加入队列（部分元素可能不存在）
            try:
                port = tag_port.getAttribute('portid')
                state = tag_port.getElementsByTagName('state')[0]

                if state.getAttribute('state') == 'open':
                    if (len(tag_port.getElementsByTagName('service')) != 0):
                        service = tag_port.getElementsByTagName('service')[0]
                        name = service.getAttribute('name')

                        # 处理service是http和https的
                        if 'http' in name:
                            parse_list.append((ip, port, 'http'))
                        elif 'https' in name:
                            parse_list.append((ip, port, 'ssl'))
                        else:
                            pass
            
            except:
                logging.error('Error in parse nmap xml')
                pass

    return parse_list


