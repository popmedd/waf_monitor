# -*- coding:utf-8 -*-
# Author:g0dlike
# Create:2017年7月21日

import os
import shutil
import platform
import logging


def run(ip_seg, output_file, rate=500, port_range='1-65535'):

    # 对于已存在的文件进行剪切和备份
    if os.path.isfile(output_file):
        print "Warning:Output File already exist"
        shutil.move(output_file, output_file+".bak")

    # 对输入参数进行处理
    ip_seg = str(ip_seg).translate(None, ';|&')
    rate = str(int(rate))

    # 获取当前操作系统类型，选择合适的masscan程序并整合及执行命令
    path = os.path.split(os.path.realpath(__file__))[0]
    sys_type = platform.system()
    if sys_type == 'Windows':
        path = os.path.join(path, 'masscan.exe')
    elif sys_type == 'Linux':
        path = os.path.join(path, 'masscan')
    else:
        path = os.path.join(path, 'masscan')

    scan_command = str.format("%s -p%s %s --banners -oL %s  --max-rate %s"%(path, port_range, ip_seg, output_file, rate))
    logger = logging.getLogger('waf_monitor')
    logger.debug('Action:' + scan_command)
    #scan_command = str.format("%s -p80,443 %s --banners -oL %s  --max-rate %s"%(path, ip_seg, output_file, rate))
    os.system(scan_command)

    # 读取masscan的输出文件，处理、切割，输出需要的内容
    with open(output_file, 'r') as file_handle:
        file_content = file_handle.readlines()

    res = []
    # 头尾为注释的内容
    try:
        del file_content[0]
        del file_content[-1]
    except:
        return res

    for content in file_content:
        try:
            con_list = content.split(' ', 8)
            if (con_list[0] == 'banner' and (con_list[5] == 'ssl' or con_list[5] == 'http')):
                res.append((con_list[3], con_list[2], con_list[5]))
        except:
            pass


    logger = logging.getLogger('waf_monitor')
    logger.debug("Action: masscan.py return" + str(res))

    return res



