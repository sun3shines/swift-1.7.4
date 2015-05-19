# Copyright (c) 2010-2012 OpenStack, LLC.
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

# NOTE: swift_conn
# You'll see swift_conn passed around a few places in this file. This is the
# source httplib connection of whatever it is attached to.
#   It is used when early termination of reading from the connection should
# happen, such as when a range request is satisfied but there's still more the
# source connection would like to send. To prevent having to read all the data
# that could be left, the source connection can be .close() and then reads
# commence to empty out any buffers.
#   These shenanigans are to ensure all related objects can be garbage
# collected. We've seen objects hang around forever otherwise.

import mimetypes
import os
import time
from ConfigParser import ConfigParser
import uuid
import json
import copy

from urlparse import parse_qs
from eventlet import Timeout
from webob.exc import HTTPBadRequest, HTTPForbidden, HTTPMethodNotAllowed, \
    HTTPNotFound, HTTPPreconditionFailed, HTTPServerError
from webob import Request

from swift.common.ring import Ring
from swift.common.utils import get_logger, \
    get_remote_client, split_path, TRUE_VALUES,config_true_value
from swift.common.constraints import check_utf8
from swift.proxy.controllers import AccountController, ObjectController, \
    ContainerController, DirerController,LinkController,Controller

from swift.proxy.controllers.req_param import check_path_parts 

class Application(object):
    """WSGI application for the proxy server."""

    def __init__(self, conf, logger=None, account_ring=None,
                 container_ring=None, object_ring=None):
        if conf is None:
            conf = {}
        if logger is None:
            self.logger = get_logger(conf, log_route='proxy-server')
        else:
            self.logger = logger

        swift_dir = conf.get('swift_dir', '/etc/swift')
        self.node_timeout = int(conf.get('node_timeout', 10000))
        self.conn_timeout = float(conf.get('conn_timeout', 50))
        self.client_timeout = int(conf.get('client_timeout', 60))
        self.put_queue_depth = int(conf.get('put_queue_depth', 10))
        self.object_chunk_size = int(conf.get('object_chunk_size', 65536))
        self.client_chunk_size = int(conf.get('client_chunk_size', 65536))
        self.error_suppression_interval = \
            int(conf.get('error_suppression_interval', 60))
        self.error_suppression_limit = \
            int(conf.get('error_suppression_limit', 10))
        self.recheck_container_existence = \
            int(conf.get('recheck_container_existence', 60))
        self.recheck_account_existence = \
            int(conf.get('recheck_account_existence', 60))
        self.allow_account_management = \
            conf.get('allow_account_management', 'no').lower() in TRUE_VALUES
        self.object_post_as_copy = \
            conf.get('object_post_as_copy', 'true').lower() in TRUE_VALUES
        self.resellers_conf = ConfigParser()
        self.resellers_conf.read(os.path.join(swift_dir, 'resellers.conf'))
        
        
        self.object_ring = object_ring or Ring(swift_dir, ring_name='object')
        self.direr_ring = Ring(swift_dir,ring_name='direr')
        self.link_ring = Ring(swift_dir,ring_name='link')
        self.container_ring = container_ring or Ring(swift_dir,
                ring_name='container')
        self.account_ring = account_ring or Ring(swift_dir,
                ring_name='account')
        
        
        mimetypes.init(mimetypes.knownfiles +
                       [os.path.join(swift_dir, 'mime.types')])
        self.account_autocreate = \
            conf.get('account_autocreate', 'no').lower() in TRUE_VALUES
        self.expiring_objects_account = \
            (conf.get('auto_create_account_prefix') or '.') + \
            'expiring_objects'
        self.expiring_objects_container_divisor = \
            int(conf.get('expiring_objects_container_divisor') or 86400)
        self.max_containers_per_account = \
            int(conf.get('max_containers_per_account') or 0)
        self.max_containers_whitelist = [a.strip()
            for a in conf.get('max_containers_whitelist', '').split(',')
            if a.strip()]
        self.deny_host_headers = [host.strip() for host in
            conf.get('deny_host_headers', '').split(',') if host.strip()]
        self.rate_limit_after_segment = \
            int(conf.get('rate_limit_after_segment', 10))
        self.rate_limit_segments_per_sec = \
            int(conf.get('rate_limit_segments_per_sec', 1))
        self.log_handoffs = \
            conf.get('log_handoffs', 'true').lower() in TRUE_VALUES
        self.allow_static_large_object = config_true_value(
            conf.get('allow_static_large_object', 'true'))
        
    def get_controller(self, req):

        path = req.path
        params = req.GET
        
        version, account, container, obj = split_path(path, 1, 4, True)
        d = dict(version=version,
                account_name=account,
                container_name=container,
                object_name=obj)
        
        d.update(params)
        
        if obj and container and account:
            
            if d.get('ftype') and d.get('ftype') not in ['d','f','l']:
                return None,d
            
            if d.get('ftype') == 'd':
                d['direr_name'] = obj   
                return DirerController,d
            elif d.get('ftype') == 'l':
                d['link_name'] = obj
                return LinkController,d
            d['ftype'] = 'f'
            return ObjectController, d
        
        elif container and account and not obj:
            d['ftype'] = 'c'
            return ContainerController, d
        elif account and not container and not obj:
            d['ftype'] = 'a'
            return AccountController, d
        return None, d

 
    
    def __call__(self, env, start_response):
        try:
             
            req = self.update_request(Request(env))

            return self.handle_request(req)(env, start_response)
        
        except UnicodeError:
            err = HTTPPreconditionFailed(request=req, body='Invalid UTF8')
            return err(env, start_response)
        except (Exception, Timeout):
            start_response('500 Server Error',
                    [('Content-Type', 'text/plain')])
            return ['Internal server error.\n']

    def update_request(self, req):
        if 'x-storage-token' in req.headers and \
                'x-auth-token' not in req.headers:
            req.headers['x-auth-token'] = req.headers['x-storage-token']
        return req

    def handle_request(self, req):
        try:
            self.logger.set_statsd_prefix('proxy-server')
            if req.content_length and req.content_length < 0:
                return HTTPBadRequest(request=req,
                                      body='Invalid Content-Length')

            try:
                if not check_utf8(req.path_info):
                    return HTTPPreconditionFailed(request=req,
                                                  body='Invalid UTF8')
            except UnicodeError:
                return HTTPPreconditionFailed(request=req, body='Invalid UTF8')
            
            try:
                controller, path_parts = self.get_controller(req)
                p = req.path_info
                if isinstance(p, unicode):
                    p = p.encode('utf-8')
            except ValueError:
                return HTTPNotFound(request=req)
            if not controller:
                return HTTPPreconditionFailed(request=req, body='Bad URL')
            if self.deny_host_headers and \
                    req.host.split(':')[0] in self.deny_host_headers:
                return HTTPForbidden(request=req, body='Invalid host header')
            if not check_path_parts(path_parts):
                return HTTPForbidden(request=req, body='Invalid path_parts header')
            
            self.logger.set_statsd_prefix('proxy-server.' +
                                          controller.server_type.lower())
            
            controller = controller(self, **path_parts)
            if 'swift.trans_id' not in req.environ:
                # if this wasn't set by an earlier middleware, set it now
                trans_id = 'tx' + uuid.uuid4().hex
                req.environ['swift.trans_id'] = trans_id
                self.logger.txn_id = trans_id
            req.headers['x-trans-id'] = req.environ['swift.trans_id']
            controller.trans_id = req.environ['swift.trans_id']
            self.logger.client_ip = get_remote_client(req)
            
            try:
                if req.GET.get('op'):
                    req.method = req.GET.get('op')
                    
                handler = getattr(controller, req.method)
                getattr(handler, 'publicly_accessible')
            except AttributeError:
                return HTTPMethodNotAllowed(request=req)
            if path_parts['version']:
                req.path_info_pop()
    
            req.environ['swift.orig_req_method'] = req.method
            return handler(req)
        except (Exception, Timeout):
            self.logger.exception(_('ERROR Unhandled exception in request'))
            return HTTPServerError(request=req)


def app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating WSGI proxy apps."""
    conf = global_conf.copy()
    conf.update(local_conf)
    return Application(conf)
