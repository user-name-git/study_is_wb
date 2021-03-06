# coding=utf-8
'''
@Author: yixiaowan 
'''
# coding=utf-8
import hmac
from hashlib import sha1
from hashlib import sha256
import urllib
import time
import uuid
import requests
import sys
import json
import urllib.parse
import codecs
import copy


class Signature:
    def __init__(self, accessKey, secretKey):
        self.access_key = accessKey
        self.secret_key = secretKey

    # 签名
    def sign(self, httpMethod, playlocd, servlet_path):
        # 如果要指定时间，则注释掉下面两行代码
        time_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.localtime())
        playlocd['Timestamp'] = time_str
        parameters = copy.deepcopy(playlocd)
        parameters.pop('Signature')
        sortedParameters = sorted(parameters.items(), key=lambda parameters: parameters[0])
        canonicalizedQueryString = ''
        # 传入参数有list的情况
        for (k, v) in sortedParameters:
            if isinstance(v, list):
                for v_l in v:
                    canonicalizedQueryString += '&' + self.percent_encode(k) + '=' + self.percent_encode(v_l)
                    break
            else:
                canonicalizedQueryString += '&' + self.percent_encode(k) + '=' + self.percent_encode(v)
        # for (k, v) in sortedParameters:
        #     canonicalizedQueryString += '&' + self.percent_encode(k) + '=' + self.percent_encode(v)
        stringToSign = httpMethod + '\n' \
                       + self.percent_encode(servlet_path) + '\n' \
                       + sha256(canonicalizedQueryString[1:].encode('utf-8')).hexdigest()

        key = ("BC_SIGNATURE&" + self.secret_key).encode('utf-8')

        stringToSign = stringToSign.encode('utf-8')
        signature = hmac.new(key, stringToSign, sha1).hexdigest()
        return signature

    def percent_encode(self, encodeStr):
        encodeStr = str(encodeStr)
        res = urllib.parse.quote(encodeStr.encode('utf-8'), '')
        res = res.replace('+', '%20')
        res = res.replace('*', '%2A')
        res = res.replace('%7E', '~')
        return res


class API:
    def __init__(self, accessKey, secretKey, method, url, path, querystring, payload):
        self.accessKey = accessKey
        self.secretKey = secretKey
        self.method = method
        self.url = url
        self.path = path
        self.querystring = querystring
        self.payload = payload

    headers = {'Content-Type': 'application/json'}

    def test(self):
        self.querystring['Signature'] = Signature(self.accessKey, self.secretKey).sign(self.method, self.querystring,
                                                                                       self.path)
        print('请求方法:\n' + self.method)
        print('请求路径:\n' + self.url + self.path)
        print('路径中参数：\n' + json.dumps(self.querystring))
        if self.payload:
            print('请求体中参数: \n' + json.dumps(self.payload))
        res = requests.request(self.method, self.url + self.path, headers=self.headers, json=self.payload,
                               params=self.querystring, timeout=10)
        result = json.loads(res.text)
        print('返回结果：')
        print(res)
        print(result.get('requestId'))
        print('state:' + result.get('state'))
        print('body:' + json.dumps(result.get('body')))
        if result.get('state') != 'OK':
            print('errorCode:' + result.get('errorCode'))
            print('errorMessage:' + result.get('errorMessage'))
        # try:
        #    print('body:'+json.dumps(result.get('body')))
        # except AssertionError as ae:
        #    print('errorCode:'+ result.get('errorCode'))
        #   print('errorMessage:'+ result.get('errorMessage'))
        return res


if __name__ == '__main__':
    # 用户的accessKey和secretKey
    accessKey = '05217d228c7d473c92d53d293dd40ece'
    secretKey = '78e04ba1a43c418c8812bb18cc9bbf30'
    # url
    url = 'https://console-guangxi-1.cmecloud.cn:8443'# https://console-jinan-1.cmecloud.cn:8443  https://console-xian-1.cmecloud.cn:8443  https://console-xian-1.cmecloud.cn:8443
    # 接口详细路径
    path = '/api/v2/monitor/meter-data/add'
    # 请求类型
    method = 'POST'
    # url中参数
    querystring = {"AccessKey": accessKey, "Timestamp": "2020-08-28T20:40:11Z", "Signature": "",
                   "SignatureMethod": "HmacSHA1", "SignatureNonce": "206", "SignatureVersion": "V2.0"}
    # 如果路径url中有参数则按照如下添加
    # querystring["volumeId"] = "f029c8f9-961f-47a1-89f9-f0efb20a7eb2"
    # body中的请求体,如果没有请求体则payload为空，若有则按照如下添加
    # payload = {}
    payload = [{
        "meter": {
            "meterName": "PROC_RUN",
            "meterDesc": "CPU运行队列中进程个数",
            "unit": "个",
            "resourceType":"vm",
            "resourceId": "5e43c26d-fcc5-4e01-8d7c-fc86606fcaa7",
            "resourceName":"xtf03"
        },
        "collectTime": 1607936778,
        "value": "70"
    }]
# payload = {"volumeId": "f0722bcd-cb65-4b62-aae5-b954a07ea28e", "serverId": "ba7262fb-4121-4619-9c9d-fb85f1bbd602"}
api = API(accessKey, secretKey, method, url, path, querystring, payload)
api.test()
