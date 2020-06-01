import json
import os
from http_basic_auth import generate_header, parse_header
import requests

def waf_login():
    with open("/etc/waf/waf.json", "r") as waf:
        waf_dict = json.loads(waf.read())
    waf_ip = waf_dict['waf1']['waf_ip']
    waf_port = waf_dict['waf1']['waf_port']
    waf_admin = waf_dict['waf1']['waf_admin']
    waf_password = waf_dict['waf1']['waf_password']
    login_url = "http://"+waf_ip+":"+waf_port+"/restapi/v3.1/login"
    api_headers = {"Content-Type": "application/json"}
    login_payload = {"username": waf_admin, "password": waf_password}
    login_request = requests.post(login_url, headers=api_headers, data=json.dumps(login_payload))
    token_output=login_request.text
    token_split=token_output.split(":")
    token_rstrip=token_split[1].rstrip("}")
    token=token_rstrip.replace('"','')
    auth_header=generate_header('',token)
    waf_url = "http://"+waf_ip+":"+waf_port+"/restapi/v3.1"
    headers = {"Content-Type":"application/json", "Authorization": auth_header}
    return waf_url, headers, waf_ip

with open("/tmp/kubedeploy.json", "r") as kubedeploy:
    kube_dict = json.loads(kubedeploy.read())
print(kube_dict)
print(kube_dict.keys())
backend_ip_list = kube_dict['status']['loadBalancer']['ingress']
backend_ip_dict=backend_ip_list[0]
backend_ip=backend_ip_dict['ip']
print(f"\r\n1. The application is running on {backend_ip}\r\n")
print("2. Configuring Barracuda WAF for protecting the application...\r\n")
waf_url, api_headers, waf_ip = waf_login()
wan_config_api_url = waf_url+ "/system/wan-configuration"
wan_config = requests.get(wan_config_api_url, headers=api_headers)
system_info = json.loads(wan_config.text)
service_ip = system_info['data']['System']['WAN Configuration']['ip-address']
create_svc_url = waf_url+ "/services"
badstore_svc = create_svc_url+"/badstore_svc"
badstore_svc_get = requests.get(create_svc_url, headers=api_headers)
if badstore_svc_get.status_code == 200:
    pass
else:
    svc_payload = {"address-version": "IPv4",
        "ip-address": service_ip,
        "name": "badstore_svc",
        "port": 80,
        "status": "On",
        "type": "HTTP"}
    #create_svc = requests.post(create_svc_url, data=json.dumps(svc_payload), headers = api_headers)
    #print(create_svc.status_code)
svr_get_api = waf_url+"/services/badstore_svc/servers"
svr_get = requests.get(svr_get_api, headers=api_headers)

def server_call():
    svr_create_api = waf_url + "/services/badstore_svc/servers"
    svr_payload = {
        "port": 80,
        "ip-address": backend_ip,
        "address-version": "IPv4",
        "identifier": "IP Address",
        "name": "ext_loadbalancer_ip"
        }
    svr_create = requests.post(svr_create_api, data=json.dumps(svr_payload), headers=api_headers)
    return svr_create.text
try:
    if svr_get.status_code == 200:
        svr_dict=json.loads(svr_get.text)
        svr_data=svr_dict['data']
        print(svr_data['ext_loadbalancer_ip']['ip-address'])
        if svr_data['ext_loadbalancer_ip']['ip-address'] == backend_ip:
            pass
        else:
            server_call()
except:
    server_call()
print(f"3. Server {backend_ip}, is configured for protection !!\r\n")
print(f"4. Access the New Application using http://{waf_ip}/")






