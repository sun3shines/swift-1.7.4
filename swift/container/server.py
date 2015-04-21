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

from __future__ import with_statement

import os
import time
import traceback
from urllib import unquote
from xml.sax import saxutils
from datetime import datetime

from eventlet import Timeout
from webob import Request, Response
from webob.exc import HTTPAccepted, HTTPBadRequest, HTTPConflict, \
    HTTPCreated, HTTPInternalServerError, HTTPNoContent, \
    HTTPNotFound, HTTPPreconditionFailed, HTTPMethodNotAllowed

from swift.common.utils import get_logger, get_param, hash_path, public, \
    normalize_timestamp, storage_directory, split_path, validate_sync_to, \
    TRUE_VALUES, validate_device_partition, json
from swift.common.constraints import CONTAINER_LISTING_LIMIT, \
    check_mount, check_float, check_utf8, FORMAT2CONTENT_TYPE
from swift.common.bufferedhttp import http_connect
from swift.common.exceptions import ConnectionTimeout

from swift.common.http import HTTP_NOT_FOUND, is_success, \
    HTTPInsufficientStorage

DATADIR = 'containers'


class ContainerController(object):
    """WSGI Controller for the container server."""

    # Ensure these are all lowercase
    save_headers = ['x-container-read', 'x-container-write',
                    'x-container-sync-key', 'x-container-sync-to']

    def __init__(self, conf):
        self.logger = get_logger(conf, log_route='container-server')
        self.root = conf.get('devices', '/srv/node/')
        self.mount_check = conf.get('mount_check', 'true').lower() in \
                              TRUE_VALUES
        self.node_timeout = int(conf.get('node_timeout', 3000))
        self.conn_timeout = float(conf.get('conn_timeout', 50))
        self.allowed_sync_hosts = [h.strip()
            for h in conf.get('allowed_sync_hosts', '127.0.0.1').split(',')
            if h.strip()]
          
        self.auto_create_account_prefix = \
            conf.get('auto_create_account_prefix') or '.'
        
        if conf.get('allow_versions', 'f').lower() in TRUE_VALUES:
            self.save_headers.append('x-versions-location')
            
    def _get_container_broker(self, drive, part, account, container):
        
        return None
        
    def account_update(self, req, account, container, broker):
        """
        Update the account server with latest container info.

        :param req: webob.Request object
        :param account: account name
        :param container: container name
        :param borker: container DB broker object
        :returns: if the account request returns a 404 error code,
                  HTTPNotFound response object, otherwise None.
        """
        account_host = req.headers.get('X-Account-Host')
        account_partition = req.headers.get('X-Account-Partition')
        account_device = req.headers.get('X-Account-Device')
        if all([account_host, account_partition, account_device]):
            account_ip, account_port = account_host.rsplit(':', 1)
            new_path = '/' + '/'.join([account, container])
            info = broker.get_info()
            account_headers = {'x-put-timestamp': info['put_timestamp'],
                'x-delete-timestamp': info['delete_timestamp'],
                'x-object-count': info['object_count'],
                'x-bytes-used': info['bytes_used'],
                'x-trans-id': req.headers.get('x-trans-id', '-')}
            if req.headers.get('x-account-override-deleted', 'no').lower() == \
                    'yes':
                account_headers['x-account-override-deleted'] = 'yes'
            try:
                with ConnectionTimeout(self.conn_timeout):
                    conn = http_connect(account_ip, account_port,
                        account_device, account_partition, 'PUT', new_path,
                        account_headers)
                with Timeout(self.node_timeout):
                    account_response = conn.getresponse()
                    account_response.read()
                    if account_response.status == HTTP_NOT_FOUND:
                        return HTTPNotFound(request=req)
                    elif not is_success(account_response.status):
                        self.logger.error(_('ERROR Account update failed '
                            'with %(ip)s:%(port)s/%(device)s (will retry '
                            'later): Response %(status)s %(reason)s'),
                            {'ip': account_ip, 'port': account_port,
                             'device': account_device,
                             'status': account_response.status,
                             'reason': account_response.reason})
            except (Exception, Timeout):
                self.logger.exception(_('ERROR account update failed with '
                    '%(ip)s:%(port)s/%(device)s (will retry later)'),
                    {'ip': account_ip, 'port': account_port,
                     'device': account_device})
        return None

    @public
    def DELETE(self, req):
        
        """Handle HTTP DELETE request."""
        start_time = time.time()
        try:
            drive, part, account, container, obj = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
        if 'x-timestamp' not in req.headers or \
                    not check_float(req.headers['x-timestamp']):
            return HTTPBadRequest(body='Missing timestamp', request=req,
                        content_type='text/plain')
        if self.mount_check and not check_mount(self.root, drive):
            return HTTPInsufficientStorage(drive=drive, request=req)
        broker = self._get_container_broker(drive, part, account, container)
        
        if account.startswith(self.auto_create_account_prefix) and obj and \
                not os.path.exists(broker.db_file):
            pass
        
        if not os.path.exists(broker.db_file):
            return HTTPNotFound()
        if obj:     # delete object
            return HTTPNoContent(request=req)
        else:
            # delete container
            if not broker.empty():
                return HTTPConflict(request=req)
            existed = float(broker.get_info()['put_timestamp']) and \
                      not broker.is_deleted()
            broker.delete_db(req.headers['X-Timestamp'])
            if not broker.is_deleted():
                return HTTPConflict(request=req)
            resp = self.account_update(req, account, container, broker)
            if resp:
                return resp
            if existed:
                return HTTPNoContent(request=req)
            return HTTPNotFound()

    @public
    def PUT(self, req):
        """Handle HTTP PUT request."""
        
        start_time = time.time()
        try:
            drive, part, account, container, obj = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
        if 'x-timestamp' not in req.headers or \
                    not check_float(req.headers['x-timestamp']):
            return HTTPBadRequest(body='Missing timestamp', request=req,
                        content_type='text/plain')
        if 'x-container-sync-to' in req.headers:
            err = validate_sync_to(req.headers['x-container-sync-to'],
                                   self.allowed_sync_hosts)
            if err:
                return HTTPBadRequest(err)
        if self.mount_check and not check_mount(self.root, drive):
            return HTTPInsufficientStorage(drive=drive, request=req)
        timestamp = normalize_timestamp(req.headers['x-timestamp'])
        broker = self._get_container_broker(drive, part, account, container)
        if obj:     # put container object
            
            if not os.path.exists(broker.db_file):
                return HTTPNotFound()
            return HTTPCreated(request=req)
        else:   # put container
            if not os.path.exists(broker.db_file):
                
                created = True
            else:
                created = broker.is_deleted()
                broker.update_put_timestamp(timestamp)
                if broker.is_deleted():
                    return HTTPConflict(request=req)
            metadata = {}
            metadata.update((key, (value, timestamp))
                for key, value in req.headers.iteritems()
                if key.lower() in self.save_headers or
                   key.lower().startswith('x-container-meta-'))
            if metadata:
                if 'X-Container-Sync-To' in metadata:
                    if 'X-Container-Sync-To' not in broker.metadata or \
                            metadata['X-Container-Sync-To'][0] != \
                            broker.metadata['X-Container-Sync-To'][0]:
                        broker.set_x_container_sync_points(-1, -1)
                broker.update_metadata(metadata)
            resp = self.account_update(req, account, container, broker)
            if resp:
                return resp
            if created:
                return HTTPCreated(request=req)
            else:
                return HTTPAccepted(request=req)

    @public
    def HEAD(self, req):
        """Handle HTTP HEAD request."""
        
        start_time = time.time()
        try:
            drive, part, account, container, obj = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
        if self.mount_check and not check_mount(self.root, drive):
            return HTTPInsufficientStorage(drive=drive, request=req)
        broker = self._get_container_broker(drive, part, account, container)
        
        if broker.is_deleted():
            return HTTPNotFound(request=req)
        info = broker.get_info()
        headers = {
            'X-Container-Object-Count': info['object_count'],
            'X-Container-Bytes-Used': info['bytes_used'],
            'X-Timestamp': info['created_at'],
            'X-PUT-Timestamp': info['put_timestamp'],
        }
        headers.update((key, value)
            for key, (value, timestamp) in broker.metadata.iteritems()
            if value != '' and (key.lower() in self.save_headers or
                                key.lower().startswith('x-container-meta-')))
        return HTTPNoContent(request=req, headers=headers)

    @public
    def GET(self, req):
        """Handle HTTP GET request."""
        start_time = time.time()
        try:
            drive, part, account, container, obj = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
        if self.mount_check and not check_mount(self.root, drive):
            return HTTPInsufficientStorage(drive=drive, request=req)
        broker = self._get_container_broker(drive, part, account, container)
        
        if broker.is_deleted():
            return HTTPNotFound(request=req)
        info = broker.get_info()
        resp_headers = {
            'X-Container-Object-Count': info['object_count'],
            'X-Container-Bytes-Used': info['bytes_used'],
            'X-Timestamp': info['created_at'],
            'X-PUT-Timestamp': info['put_timestamp'],
        }
        resp_headers.update((key, value)
            for key, (value, timestamp) in broker.metadata.iteritems()
            if value != '' and (key.lower() in self.save_headers or
                                key.lower().startswith('x-container-meta-')))
        try:
            path = get_param(req, 'path')
            prefix = get_param(req, 'prefix')
            delimiter = get_param(req, 'delimiter')
            if delimiter and (len(delimiter) > 1 or ord(delimiter) > 254):
                # delimiters can be made more flexible later
                return HTTPPreconditionFailed(body='Bad delimiter')
            marker = get_param(req, 'marker', '')
            end_marker = get_param(req, 'end_marker')
            limit = CONTAINER_LISTING_LIMIT
            given_limit = get_param(req, 'limit')
            if given_limit and given_limit.isdigit():
                limit = int(given_limit)
                if limit > CONTAINER_LISTING_LIMIT:
                    return HTTPPreconditionFailed(request=req,
                        body='Maximum limit is %d' % CONTAINER_LISTING_LIMIT)
            query_format = get_param(req, 'format')
        except UnicodeDecodeError, err:
            return HTTPBadRequest(body='parameters not utf8',
                                  content_type='text/plain', request=req)
        if query_format:
            req.accept = FORMAT2CONTENT_TYPE.get(query_format.lower(),
                                                 FORMAT2CONTENT_TYPE['plain'])
        try:
            out_content_type = req.accept.best_match(
                                    ['text/plain', 'application/json',
                                     'application/xml', 'text/xml'],
                                    default_match='text/plain')
        except AssertionError, err:
            return HTTPBadRequest(body='bad accept header: %s' % req.accept,
                                  content_type='text/plain', request=req)
        container_list = broker.list_objects_iter(limit, marker, end_marker,
                                                  prefix, delimiter, path)
        
        out_content_type = 'application/json'
        if out_content_type == 'application/json':
            data = []
            for (name, size, etag) in container_list:
                
                data.append({ 'bytes': size,'hash': etag,'name': name})
                    
            container_list = json.dumps(data)
        
        else:
            if not container_list:
                return HTTPNoContent(request=req, headers=resp_headers)
            container_list = '\n'.join(r[0] for r in container_list) + '\n'
        ret = Response(body=container_list, request=req, headers=resp_headers)
        ret.content_type = out_content_type
        ret.charset = 'utf-8'
        return ret

    @public
    def POST(self, req):
        """Handle HTTP POST request."""
        start_time = time.time()
        try:
            drive, part, account, container = split_path(unquote(req.path), 4)
            validate_device_partition(drive, part)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                  request=req)
        if 'x-timestamp' not in req.headers or \
                not check_float(req.headers['x-timestamp']):
            return HTTPBadRequest(body='Missing or bad timestamp',
                request=req, content_type='text/plain')
        if 'x-container-sync-to' in req.headers:
            err = validate_sync_to(req.headers['x-container-sync-to'],
                                   self.allowed_sync_hosts)
            if err:
                return HTTPBadRequest(err)
        if self.mount_check and not check_mount(self.root, drive):
            return HTTPInsufficientStorage(drive=drive, request=req)
        broker = self._get_container_broker(drive, part, account, container)
        if broker.is_deleted():
            return HTTPNotFound(request=req)
        timestamp = normalize_timestamp(req.headers['x-timestamp'])
        metadata = {}
        metadata.update((key, (value, timestamp))
            for key, value in req.headers.iteritems()
            if key.lower() in self.save_headers or
               key.lower().startswith('x-container-meta-'))
        if metadata:
            if 'X-Container-Sync-To' in metadata:
                if 'X-Container-Sync-To' not in broker.metadata or \
                        metadata['X-Container-Sync-To'][0] != \
                        broker.metadata['X-Container-Sync-To'][0]:
                    broker.set_x_container_sync_points(-1, -1)
            broker.update_metadata(metadata)
        return HTTPNoContent(request=req)

    def __call__(self, env, start_response):
        
        start_time = time.time()
        req = Request(env)
        self.logger.txn_id = req.headers.get('x-trans-id', None)
        if not check_utf8(req.path_info):
            res = HTTPPreconditionFailed(body='Invalid UTF8')
        else:
            try:
                # disallow methods which have not been marked 'public'
                try:
                    method = getattr(self, req.method)
                    getattr(method, 'publicly_accessible')
                except AttributeError:
                    res = HTTPMethodNotAllowed()
                else:
                    res = method(req)
            except (Exception, Timeout):
                self.logger.exception(_('ERROR __call__ error with %(method)s'
                    ' %(path)s '), {'method': req.method, 'path': req.path})
                res = HTTPInternalServerError(body=traceback.format_exc())
        trans_time = '%.4f' % (time.time() - start_time)
        log_message = '%s - - [%s] "%s %s" %s %s "%s" "%s" "%s" %s' % (
            req.remote_addr,
            time.strftime('%d/%b/%Y:%H:%M:%S +0000',
                          time.gmtime()),
            req.method, req.path,
            res.status.split()[0], res.content_length or '-',
            req.headers.get('x-trans-id', '-'),
            req.referer or '-', req.user_agent or '-',
            trans_time)
        
        self.logger.info(log_message)
        return res(env, start_response)


def app_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating WSGI container server apps"""
    conf = global_conf.copy()
    conf.update(local_conf)
    return ContainerController(conf)
