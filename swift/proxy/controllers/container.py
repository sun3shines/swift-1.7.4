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

import time
from urllib import unquote
from random import shuffle
import syslog

from webob.exc import HTTPBadRequest, HTTPForbidden, HTTPNotFound

from swift.common.utils import normalize_timestamp, public
from swift.common.constraints import MAX_CONTAINER_NAME_LENGTH
from swift.common.http import HTTP_ACCEPTED
from swift.proxy.controllers.base import Controller, delay_denial


class ContainerController(Controller):
    """WSGI controller for container requests"""
    server_type = 'Container'

    # Ensure these are all lowercase
    pass_through_headers = ['x-container-read', 'x-container-write',
                            'x-container-sync-key', 'x-container-sync-to',
                            'x-versions-location']

    def __init__(self, app, account_name, container_name, **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)


    def GETorHEAD(self, req):
        """Handler for HTTP GET/HEAD requests."""
        if not self.account_info(self.account_name)[1]:
            return HTTPNotFound(request=req)
        part, nodes = self.app.container_ring.get_nodes(self.account_name, self.container_name)
        
        shuffle(nodes)
        resp = self.GETorHEAD_base(req, _('Container'), part, nodes,
                req.path_info, len(nodes))

        if not req.environ.get('swift_owner', False):
            for key in ('x-container-read', 'x-container-write',
                        'x-container-sync-key', 'x-container-sync-to'):
                if key in resp.headers:
                    del resp.headers[key]
        return resp

    @public
    @delay_denial
    def GET(self, req):
        """Handler for HTTP GET requests."""
        if not req.environ['fwuser_info'].get('lock'):
            req.environ['fwuser_info']['comment'] = 'get object list'
            req.environ['fwuser_info']['lock'] = True
            
        return self.GETorHEAD(req)

    @public
    @delay_denial
    def LISTDIR(self, req):
        """Handler for HTTP GET requests."""
        
        if not req.environ['fwuser_info'].get('lock'):
            req.environ['fwuser_info']['comment'] = 'get object list'
            req.environ['fwuser_info']['lock'] = True
            
        old_method = req.method
        req.method = 'GET'
        req.headers['x-recursive']=str(req.GET('recursive','False')).lower()
        resp = self.GETorHEAD(req)
        req.method = old_method
        return resp
    
    @public
    @delay_denial
    def HEAD(self, req):
        
        if not req.environ['fwuser_info'].get('lock'):
            req.environ['fwuser_info']['comment'] = 'get container attr'
            req.environ['fwuser_info']['lock'] = True
            
        """Handler for HTTP HEAD requests."""
        return self.GETorHEAD(req)

    @public
    @delay_denial
    def META(self, req):
        
        if not req.environ['fwuser_info'].get('lock'):
            req.environ['fwuser_info']['comment'] = 'get container attr'
            req.environ['fwuser_info']['lock'] = True
            
        """Handler for HTTP META requests."""
        if not self.account_info(self.account_name)[1]:
            return HTTPNotFound(request=req)
        part, nodes = self.app.container_ring.get_nodes(self.account_name, self.container_name)
        
        shuffle(nodes)
        resp = self.META_base(req, _('Container'), part, nodes,
                req.path_info, len(nodes))

        if not req.environ.get('swift_owner', False):
            for key in ('x-container-read', 'x-container-write',
                        'x-container-sync-key', 'x-container-sync-to'):
                if key in resp.headers:
                    del resp.headers[key]
        return resp
    

    @public
    def PUT(self, req):
        """HTTP PUT request handler."""
        
        if not req.environ['fwuser_info'].get('lock'):
            req.environ['fwuser_info']['comment'] = 'create container'
            req.environ['fwuser_info']['lock'] = True
            
        if len(self.container_name) > MAX_CONTAINER_NAME_LENGTH:
            resp = HTTPBadRequest(request=req)
            resp.body = 'Container name length of %d longer than %d' % \
                        (len(self.container_name), MAX_CONTAINER_NAME_LENGTH)
            return resp
        account_partition, accounts = \
            self.account_info(self.account_name,
                              autocreate=self.app.account_autocreate)
        
        if not accounts:
            return HTTPNotFound(request=req)
        container_partition, containers = self.app.container_ring.get_nodes(self.account_name, self.container_name)
        headers = []
        for account in accounts:
            
            nheaders = {'X-Timestamp': normalize_timestamp(time.time()),
                        'x-trans-id': self.trans_id,
                        'X-Account-Host': '%(ip)s:%(port)s' % account,
                        'X-Account-Partition': account_partition,
                        'X-Account-Device': account['device'],
                        'Connection': 'close'}
            self.transfer_headers(req.headers, nheaders)
            headers.append(nheaders)
        
        resp = self.make_requests(req, self.app.container_ring,
                container_partition, 'PUT', req.path_info, headers)
        return resp

    @public
    def POST(self, req):
        """HTTP POST request handler."""
        
        if not req.environ['fwuser_info'].get('lock'):
            req.environ['fwuser_info']['comment'] = 'update container'
            req.environ['fwuser_info']['lock'] = True
            
        account_partition, accounts = \
            self.account_info(self.account_name,
                              autocreate=self.app.account_autocreate)
        if not accounts:
            return HTTPNotFound(request=req)
        container_partition, containers = self.app.container_ring.get_nodes(self.account_name, self.container_name)
        headers = {'X-Timestamp': normalize_timestamp(time.time()),
                   'x-trans-id': self.trans_id,
                   'Connection': 'close'}
        self.transfer_headers(req.headers, headers)
       
        resp = self.make_requests(req, self.app.container_ring,
                container_partition, 'POST', req.path_info,
                [headers] * len(containers))
        return resp

    @public
    def DELETE(self, req):
        """HTTP DELETE request handler."""
        
        if not req.environ['fwuser_info'].get('lock'):
            req.environ['fwuser_info']['comment'] = 'delete container'
            req.environ['fwuser_info']['lock'] = True
            
        account_partition, accounts = self.account_info(self.account_name)
        if not accounts:
            return HTTPNotFound(request=req)
        container_partition, containers = self.app.container_ring.get_nodes(self.account_name, self.container_name)
        headers = []
        for account in accounts:
            headers.append({'X-Timestamp': normalize_timestamp(time.time()),
                           'X-Trans-Id': self.trans_id,
                           'X-Account-Host': '%(ip)s:%(port)s' % account,
                           'X-Account-Partition': account_partition,
                           'X-Account-Device': account['device'],
                           'Connection': 'close'})
        
        resp = self.make_requests(req, self.app.container_ring,
                    container_partition, 'DELETE', req.path_info, headers)
        # Indicates no server had the container
        if resp.status_int == HTTP_ACCEPTED:
            return HTTPNotFound(request=req)
        return resp
