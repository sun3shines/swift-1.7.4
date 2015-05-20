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

try:
    import simplejson as json
except ImportError:
    import json
import mimetypes
import re
import time
from datetime import datetime
from urllib import unquote, quote
from hashlib import md5
from random import shuffle

from eventlet import sleep, GreenPile, Timeout
from eventlet.queue import Queue
from eventlet.timeout import Timeout
from webob.exc import HTTPAccepted, HTTPBadRequest, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPRequestEntityTooLarge, HTTPRequestTimeout, \
    HTTPServerError, HTTPServiceUnavailable
from webob import Request, Response

from swift.common.utils import ContextPool, normalize_timestamp, TRUE_VALUES, \
    public
from swift.common.bufferedhttp import http_connect
from swift.common.constraints import  check_object_creation, \
    CONTAINER_LISTING_LIMIT, MAX_FILE_SIZE
from swift.common.exceptions import ChunkReadTimeout, \
    ChunkWriteTimeout, ConnectionTimeout, ListingIterNotFound, \
    ListingIterNotAuthorized, ListingIterError
from swift.common.http import is_success, is_client_error, HTTP_CONTINUE, \
    HTTP_CREATED, HTTP_MULTIPLE_CHOICES, HTTP_NOT_FOUND, \
    HTTP_INTERNAL_SERVER_ERROR, HTTP_SERVICE_UNAVAILABLE, \
    HTTP_INSUFFICIENT_STORAGE, HTTPClientDisconnect
from swift.proxy.controllers.base import Controller, delay_denial

from swift.common.env_utils import *

class LinkController(Controller):
    """WSGI controller for object requests."""
    server_type = 'Object'

    def __init__(self, app, account_name, container_name, link_name,
                 **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name)
        self.link_name = unquote(link_name)

    @public
    @delay_denial
    def CREATESYMLINK(self, req):
        
        # env_comment(req.environ, 'create link')
            
        (container_partition, containers,_) = self.container_info(self.account_name, self.container_name,
                account_autocreate=self.app.account_autocreate)
        
        if not containers:
            return HTTPNotFound(request=req)
        
        link_partition, link_nodes = self.app.link_ring.get_nodes(self.account_name, self.container_name, self.link_name)
        
        headers = []
        for container in containers:
            
            nheaders = {'X-Timestamp': normalize_timestamp(time.time()),
                        'x-trans-id': self.trans_id,
                        'X-Container-Host': '%(ip)s:%(port)s' % container,
                        'X-Container-Partition': container_partition,
                        'X-Container-Device': container['device'],
                        'x-link-dst':req.headers['Destination'],
                        'x-ftype':req.GET['ftype'],
                        'Connection': 'close'}
                 
            self.transfer_headers(req.headers, nheaders)
            headers.append(nheaders)
            
        resp = self.make_requests(req, self.app.link_ring,
                link_partition, 'PUT', req.path_info, headers)
        
        return resp


