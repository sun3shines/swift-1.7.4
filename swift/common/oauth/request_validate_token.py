#!/usr/bin/env python
#coding=utf8

import time
import json
from swift.common.oauth.bridge import *
import os
import string

def get_accessToken():
    '''Get User Access Token'''
    client = bridgeUtil()
    user_param = {}
    url = 'https://124.16.141.142/oauth/access_token'
    user_param['client_id'] = 'seAgentClient'
    user_param['client_secret'] = 'g2sbeDfvms3sCGql'
    user_param['email'] = 'herh_os@sari.ac.cn'
    user_param['password'] = '123456'
    user_param['grant_type'] = 'password'
    user_param['scope'] = 'user'
    
    # result = client.get_user_access_token(url, user_param)
    # result = {u'access_token': u'EHAzwdzNZ15JrwvZmQUU7PfVkvn9k7TPiFoKQMAP', 
    #           u'token_type': u'Bearer', u'expires': 1430358287, 
    #           u'expires_in': 300}


    result = client.get_user_access_token(url, user_param)
    return result["access_token"]

def validateToken(token):
    '''Validate token & Get User Information'''
    client = bridgeUtil()
    verify_param = {}
    verify_param['resourcename'] = 'SeAgent'
    verify_param['secret'] = '123456'
    verify_param['access_token'] = token
    url = 'https://124.16.141.142/api/token-validation'
    
    # result = {u'status': u'valid', u'scopes': [u'user'],
    #           u'ownerType': u'client', u'owner': u'hnuclient1'}


    result = client.verify_user(url, verify_param)
    return result

if __name__ == '__main__':
    '''湖南大学应用软件会获取user_token,您只需参考token形式,该token只有access_token的值会包含在http head中'''
    user_token = get_accessToken()

    '''方物可以使用以下方式验证user_token的有效性'''
    user_info = validateToken(user_token)

    '''以《云存储接入层API说明V0.6版》中的上传接口为例，复旦大学向方物的服务提交的请求如下构成，请参考打印输出,email是全局唯一的'''
    x_auth = 'X-Auth-Token:' +  user_token
    
    tenant = 'AUTH_' + user_info['owner']['email'].replace('@','').replace('.','')
    
    print 'curl -i -X PUT -T ufw.log "http://IP:Port/v1/' + tenant + '/temp/ufw.log?op=CREATE&overwrite=true&type=NORMAL" -H "' + x_auth + '"'

