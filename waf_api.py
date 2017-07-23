# -*- coding: utf-8 -*-
# Author:g0dlike
# Create:2017年7月22日

import requests
import json
import base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# 禁用安全请求警告
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# 登陆WAF获取登陆Session
def login_waf(waf_ip, waf_port, username, password):

    login_waf_uri = "/SecureSphere/api/v1/auth/session"
    login_waf_url = "https://" + waf_ip + ":" + waf_port + login_waf_uri
    base64_input = username+":"+password
    base64_output = base64.urlsafe_b64encode(base64_input)
    headers = {"Authorization": "Basic "+base64_output, }
    r = requests.post(login_waf_url, verify=False, headers=headers)
    waf_session_id = r.cookies["JSESSIONID"]

    return waf_session_id


def get_all_site(waf_ip, waf_port, waf_session_id):

    get_site_uri = "/SecureSphere/api/v1/conf/sites"
    get_site_url = "https://" + waf_ip + ":" + waf_port + get_site_uri

    cookies = {"JSESSIONID": waf_session_id, }
    r = requests.get(get_site_url, cookies=cookies, verify=False)
    sites_list = json.loads(r.text)['sites']

    return sites_list


def get_all_server_group(waf_ip, waf_port, waf_session_id, site_name):

    get_all_server_group_uri = "/SecureSphere/api/v1/conf/serverGroups/" + site_name
    get_all_server_group_url = "https://" + waf_ip + ":" + waf_port + get_all_server_group_uri

    cookies = {"JSESSIONID": waf_session_id, }
    r = requests.get(get_all_server_group_url, cookies=cookies, verify=False)
    server_group_list = json.loads(r.text)['server-groups']

    return server_group_list


def get_all_protected_ips(waf_ip, waf_port, waf_session_id, site_name, server_group_name):

    get_all_protected_ips_uri = "/SecureSphere/api/v1/conf/serverGroups/" + site_name + "/" + server_group_name + "/protectedIPs"
    get_all_protected_ips_url = "https://" + waf_ip + ":" + waf_port + get_all_protected_ips_uri

    cookies = {"JSESSIONID": waf_session_id, }
    r = requests.get(get_all_protected_ips_url, cookies=cookies, verify=False)
    protected_ips = json.loads(r.text)['protected-ips']

    return protected_ips


def get_all_web_services(waf_ip, waf_port, waf_session_id, site_name, server_group_name):

    get_all_web_services_uri = "/SecureSphere/api/v1/conf/webServices/" + site_name + "/" + server_group_name
    get_all_web_services_url = "https://" + waf_ip + ":" + waf_port + get_all_web_services_uri

    cookies = {"JSESSIONID": waf_session_id, }
    r = requests.get(get_all_web_services_url, cookies=cookies, verify=False)
    web_services = json.loads(r.text)['web-services']

    return web_services


def get_web_service_msg(waf_ip, waf_port, waf_session_id, site_name, server_group_name, web_service_name):

    get_web_service_msg_uri = "/SecureSphere/api/v1/conf/webServices/" + site_name + "/" + server_group_name + "/" + web_service_name
    get_web_service_msg_url = "https://" + waf_ip + ":" + waf_port + get_web_service_msg_uri

    cookies = {"JSESSIONID": waf_session_id, }
    r = requests.get(get_web_service_msg_url, cookies=cookies, verify=False)
    web_service_msg = json.loads(r.text)

    web_ports = []
    if 'ports' in web_service_msg:
        web_ports.extend(web_service_msg['ports'])
    if 'sslPorts' in web_service_msg:
        web_ports.extend(web_service_msg['sslPorts'])

    return web_ports

