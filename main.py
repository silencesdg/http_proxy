
import json
import os
import socket
import threading
import sys

with open("./config.json","r") as f:
    config_dic = json.load(f)


HOST = 'HOST'
PORT = 'PORT'
RULES = 'RULES'

URI = 'uri'
HOLD_KEY = 'hold_key'
HOLD_VALUE = 'hold_value'
REQUEST_JOB_PATH = 'request_job_path'
RESPONSE_JOB_PATH = 'response_job_path'
REQUEST_FILE = 'request_file'
RESPONSE_FILE = 'response_file'

'''返回request method,uri,header_dic,request_data '''
def parse_request(request):
    datas = request.split('\r\n\r\n')
    headers = datas[0].strip().split('\r\n')

    header_dic = dict(map(lambda x: x.split(':'),headers[1:]))


    lines = header.split('\r\n')
    uri = lines[0].split(' ')[2]
    host = lines[1].split(' ')[1]
    if len(datas) > 1:
        return uri,host,datas[1]
    else:
        return uri,host

def value_with_keychain(keychain,request_data):
    keys = keychain.split('.')
    request_dic = json.loads(request_data)
    while len(keys) > 0:
        key = keys.pop(0)
        request_dic = request_dic[key]
    return request_dic

def hold_request(uri,request_data):
    for rule_dic in config_dic[RULES]:
        if uri is rule_dic[URI]:
            value = value_with_keychain(rule_dic[HOLD_KEY],request_data)
            if value is rule_dic[HOLD_VALUE]:
                if rule_dic[REQUEST_JOB_PATH]:
                    with open(rule_dic[REQUEST_FILE],'w') as f:
                        f.write(request_data)
                    os.system('python ' + rule_dic[REQUEST_JOB_PATH])
                    with open(rule_dic[RESPONSE_FILE],'w') as f_read:
                        request_data = f_read.read()
                    return request_data

    return request_data

def hold_response(uri,request_data,response_data):
     for rule_dic in config_dic[RULES]:
        if uri is rule_dic[URI]:
            value = value_with_keychain(rule_dic[HOLD_KEY],request_data)
            if value is rule_dic[HOLD_VALUE]:
                if rule_dic[RESPONSE_JOB_PATH]:
                    with open(rule_dic[RESPONSE_FILE],'w') as f_write:
                        f_write.write(response_data)
                    os.system('python ' + rule_dic[RESPONSE_JOB_PATH])
                    with open(rule_dic[RESPONSE_FILE],'w') as f_read:
                        response_data = f_read.read()

def main () :
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.bind((config_dic[HOST],config_dic[PORT]))
    server.listen(5)
    request = ''
    while (1):
        conn, addr = server.accept()
        buf = conn.recv(4096)
        request = request + buf

        '''匹配'''
        uri,host,request_data = parse_request(request)

        if 

        if not buf:
            break;
        
    request_data = hold_request(uri,request_data)
        if request_data :
            print ('\nuri:{1}\nrequest_data:{2}'.format(uri,request_data))


if __name__ == '__main__':
    main()
