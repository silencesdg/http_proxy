
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

flag_to_split_header_and_json = '\r\n\r\n'

def parse_request_header(request):
    ''' 
    analysis http request header
    return value : method,uri,header_dict,header_data
    '''
    datas = request.split('\r\n\r\n')
    headers = datas[0].split('\r\n')
    header_dict = dict(map(lambda x: x.strip().split(':'),headers[1:]))
    header_data = datas[0]+'\r\n\r\n'
    # line0 0:POST 1:http: 2://uri 3:http1.1
    line0 = headers[0].split(' ')
    method = line0[0]
    uri = line0[2]
    
    return method,uri,header_dict,header_data



def parse_request(request):
    ''' 
    analysis http request
    return value : request_data
    '''
    request_data = ''
    datas = request.split('\r\n\r\n')
    if len(datas) > 1:
        request_data = datas[1]
    return request_data


def parse_response_header(response):
    ''' 
    analysis http response header
    return value : status_code,header_dict,header_data
    '''
    datas = response.split('\r\n\r\n')
    headers = datas[0].split('\r\n')
    header_data = datas[0]+'\r\n\r\n'
    header_dict = dict(map(lambda x: x.strip().split(':'),headers[1:]))
    status_code = int(headers[0].split(' ')[1])
    return status_code,header_dict,header_data


def parse_response(response):
    ''' 
    analysis http response
    return value : response_data
    '''
    datas = response.split('\r\n\r\n')

    response_data = ''
    if len(datas) > 1 :
        response_data = datas[1]

    return response_data


def value_with_keychain(keychain,json_data):
    keys = keychain.split('.')
    target = json.loads(json_data)
    while len(keys) > 0:
        key = keys.pop(0)
        target = target[key]
    return target

def hold_request(uri,request_data):
    for rule_dic in config_dic[RULES]:
        if uri is rule_dic[URI]:
            value = value_with_keychain(rule_dic[HOLD_KEY],request_data)
            if value is rule_dic[HOLD_VALUE]:
                if rule_dic[REQUEST_JOB_PATH]:
                    with open(rule_dic[REQUEST_FILE],'w') as f_write:
                        f_write.write(request_data)
                    os.system('python ' + rule_dic[REQUEST_JOB_PATH])
                    with open(rule_dic[RESPONSE_FILE],'r') as f_read:
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
                    with open(rule_dic[RESPONSE_FILE],'r') as f_read:
                        response_data = f_read.read()
                    return response_data
    return response_data


def send_held_request(host, uri, port, request, request_data, proxy_held_server):

    ''' send held request to server and hold response to be modified ,then send it to client'''
    c = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        c.connect((host, port))
    except Exception as e:
        c.close()
        proxy_held_server.send(str(type(e)+' '+str(e)+' err'))
        proxy_held_server.close()
        return

    try:
        c.send(request)
        response = ''
        response_data = ''
        while True:
            buf = c.recv(4096)
            response = response + buf
            got_header_dict = False
            if not got_header_dict and flag_to_split_header_and_json in response:
                status_code,header_dict,header_data = parse_response_header(response)
                got_header_dict = True
            if got_header_dict:
                if status_code is 200:
                    break
                if 'Content-Length' in header_dict.keys():
                    if int(header_dict['Content-Length']) <= len(response_data):
                        break

        response_data = parse_response(response)
        response_data = hold_response(uri, request_data, response_data)
        proxy_held_server.send(header_data+response_data)

    except Exception as e:
        proxy_held_server.send(str(type(e)+' '+str(e)+' err'))

    c.close()
    proxy_held_server.close()

def main () :
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.bind((config_dic[HOST],config_dic[PORT]))
    server.listen(5)
    request = ''
    request_data = ''
    uri = ''
    got_header_dict = False
    header_data = ""
    host = ''
    port = ''
    method = ''

    print ('\nstart listening')
    while (1):
        conn, addr = server.accept()
        buf = conn.recv(4096)
        request = request + str(buf,'utf-8')
        print('\n len : '+ str(len(request)))
        if not got_header_dict and flag_to_split_header_and_json in request:
            got_header_dict = True
            print ('\ngot_header,----------------------------------------------------------------')
            method,uri,header_dict,header_data = parse_request_header(request)
            if not header_dict or not uri or not method:
                print ('\nit is not a validation request')
                server.close()
                break
        
        if got_header_dict and method in ['POST']:
            print ('\njudge content-length')
            if 'Content-Length' in header_dict.keys():
                if int(header_dict['Content-Length']) <= len(request_data):
                    break
            else:
                print ('\nconnot get Content-Length in header')
                break

        if not buf:
            break

    ''' handle request '''
    print ('\nparse request')
    request_data = parse_request(request)
    print ('\nhold request')
    request_data = hold_request(uri,request_data)
    if request_data :
        print ('\nuri:{1}\nrequest_data:{2}'.format(uri,request_data))
        request = header_data + request_data

    ''' send request '''
    print ('\nsend request')
    send_held_request(host, uri, 80, request, request_data, server)
    print('\n over')

if __name__ == '__main__':
    main()
