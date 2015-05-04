# -*- coding: utf-8 -*-
# Copyright (c) 2011 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from time import gmtime, strftime, time
from traceback import format_exc
from urllib import quote, unquote
from uuid import uuid4
from hashlib import sha1
import hmac
import base64

from eventlet import Timeout
from webob import Response, Request
from webob.exc import HTTPBadRequest, HTTPForbidden, HTTPNotFound, \
    HTTPUnauthorized

from swift.common.middleware.acl import clean_acl, parse_acl, referrer_allowed
from swift.common.utils import cache_from_env, get_logger, get_remote_client, \
    split_path, TRUE_VALUES
from swift.common.http import HTTP_CLIENT_CLOSED_REQUEST

from swift.common.oauth.bridge import *

class OAuth(object):

    def __init__(self, app, conf):
        self.app = app
        self.conf = conf
        self.logger = get_logger(conf, log_route='tempauth')
        
        self.log_headers = conf.get('log_headers', 'f').lower() in TRUE_VALUES
        self.reseller_prefix = conf.get('reseller_prefix', 'AUTH').strip()
        if self.reseller_prefix and self.reseller_prefix[-1] != '_':
            self.reseller_prefix += '_'
        self.logger.set_statsd_prefix('tempauth.%s' % (
            self.reseller_prefix if self.reseller_prefix else 'NONE',))
        self.auth_prefix = conf.get('auth_prefix', '/auth/')
        if not self.auth_prefix:
            self.auth_prefix = '/auth/'
        if self.auth_prefix[0] != '/':
            self.auth_prefix = '/' + self.auth_prefix
        if self.auth_prefix[-1] != '/':
            self.auth_prefix += '/'
        self.token_life = int(conf.get('token_life', 86400))
        
        self.resourcename = conf.get('resourcename', 'SeAgent').strip()
        self.secret = conf.get('secret', '123456').strip()
        self.oauth_host = conf.get('oauth_host', 'https://124.16.141.142').strip()
        self.oauth_url = self.oauth_host+'/api/token-validation'
        self.oauth_port = int(conf.get('oauth_port', '443').strip())
        
    def __call__(self, env, start_response):

        req = Request(env)
        
        try:
            version, account, container, obj = split_path(req.path_info,
                minsegs=1, maxsegs=4, rest_with_last=True)
        except ValueError:
            self.logger.increment('errors')
            return HTTPNotFound(request=req)
        
        token = env.get('HTTP_X_AUTH_TOKEN', env.get('HTTP_X_STORAGE_TOKEN'))
        if token :
            
            user_info = self.get_user_info(env, token)
            if user_info:
                if 'valid' != user_info.get('status'):
                    self.logger.increment('unauthorized')
                    return HTTPUnauthorized()(env, start_response)
                
                if isinstance(user_info['owner'],dict) and user_info['owner'].has_key('email') and user_info['owner'].get('email'):
                    tenant = 'AUTH_' + user_info['owner']['email'].replace('@','').replace('.','')
                else:
                    # tenant = 'AUTH_' + user_info['owner'].replace('@','').replace('.','')
                    self.logger.increment('unauthorized')
                    return HTTPUnauthorized()(env, start_response)
                    
                if account != tenant:
                    self.logger.increment('unauthorized')
                    return HTTPUnauthorized()(env, start_response)
            
                env['REMOTE_USER'] = user_info
                user = user_info 
                env['HTTP_X_AUTH_TOKEN'] = '%s,%s' % (user, token)
                return self.app(env, start_response)
            else:
               
                self.logger.increment('unauthorized')
                return HTTPUnauthorized()(env, start_response)
                
        else:
            self.logger.increment('unauthorized')
            return HTTPUnauthorized()(env, start_response)
       

    def validateToken(self,token):
        '''Validate token & Get User Information'''
        client = bridgeUtil()
        verify_param = {}
        verify_param['resourcename'] = self.resourcename
        verify_param['secret'] = self.secret
        verify_param['access_token'] = token
        url = self.oauth_url
        port = int(self.oauth_port)
        # result = {u'status': u'valid', u'scopes': [u'user'],
        #           u'ownerType': u'client', u'owner': u'hnuclient1'}
    
        result = client.verify_user(url, port,verify_param)
        return result
    
    def get_cache_user_info(self, env, token):
        
        user_info = None
        memcache_client = cache_from_env(env)
        if not memcache_client:
            raise Exception('Memcache required')
        memcache_token_key = '%s/token/%s' % (self.reseller_prefix, token)
        
        cached_auth_data = memcache_client.get(memcache_token_key)
        if cached_auth_data:
            expires, user_info = cached_auth_data
            if expires < time():
                user_info = None

        if not user_info:
            user_info = self.validateToken(token)
            expires = time() + self.token_life
            memcache_token_key = '%s/token/%s' % (self.reseller_prefix, token)
            
            memcache_client.set(memcache_token_key, (expires, user_info),
                                timeout=float(expires - time()))
            
        return user_info

    def get_user_info(self, env, token):
        
        user_info = None
        if not user_info:
            user_info = self.validateToken(token)

        return user_info
  
def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def auth_filter(app):
        return OAuth(app, conf)
    return auth_filter
