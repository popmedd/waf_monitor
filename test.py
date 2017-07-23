# -*- coding: utf-8 -*-
# Author:g0dlike
# Create:2017年7月21日
import waf_monitor
import json
import importlib
poc_test = json.loads(waf_monitor.get_config('poc', 'poc_msg'))

mod_name = 'poc_xss'
class_name = 'XssPOC'

#poc_mod = __import__('poc.poc_xss')
#poc_class = getattr(poc_mod, class_name)

poc_mod = importlib.import_module('poc.poc_xss')
poc_class = getattr(poc_mod, class_name)

poc_obj = poc_class()
poc_obj.info()


'''
for test in poc_test:
    try:
        poc_module = __import__(poc.)
'''



