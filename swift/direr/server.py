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

from swift.common.utils import get_uuid
from cloud.swift.common.utils import  X_CONTENT_LENGTH,X_ETAG

class DirerController(object):
    """WSGI Controller for the container server."""

    # Ensure these are all lowercase
    save_headers = ['x-container-read', 'x-container-write',
                    'x-container-sync-key', 'x-container-sync-to']

    def __init__(self,app, conf):

        self.app = app
        self.logger = get_logger(conf, log_route='container-server')
        self.root = conf.get('devices', '/srv/node/')
        self.mount_check = conf.get('mount_check', 'true').lower() in \
                              TRUE_VALUES
        self.node_timeout = int(conf.get('node_timeout', 3000))
        self.conn_timeout = float(conf.get('conn_timeout', 50))
          

    def _get_direr_broker(self, drive, part, account, container,direr):
        
        return None
        
    def _get_meta_broker(self, drive, part, account, container,direr,recycle_uuid):
         
        return None
     
    def account_update(self, req, account,bytes_val,add_flag = True):
        
        account_host = req.headers.get('X-Account-Host')
        account_partition = req.headers.get('X-Account-Partition')
        account_device = req.headers.get('X-Account-Device')
        if all([account_host, account_partition, account_device]):
            account_ip, account_port = account_host.rsplit(':', 1)
            new_path = '/' + account
            
            if add_flag:
                bytes_key = 'x-account-meta-bytes-add'
            else:
                bytes_key = 'x-account-meta-bytes-del'
                
            account_headers = {bytes_key:str(bytes_val),
                'X-Timestamp': normalize_timestamp(time.time()),
                'x-trans-id': req.headers.get('x-trans-id', '-')}
            
            try:
                with ConnectionTimeout(self.conn_timeout):
                    conn = http_connect(account_ip, account_port,
                        account_device, account_partition, 'POST', new_path,
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
          
        try:
            drive, part, account, container, direr = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
            
        if self.mount_check and not check_mount(self.root, drive):
            return HTTPInsufficientStorage(drive=drive, request=req)
        
        broker = self._get_direr_broker(drive, part, account, container,direr)
        
        # if not broker.empty():
        #     return HTTPConflict(request=req)
        
        dirsize = broker.get_data_dir_size()
        
        if broker.is_deleted():
            return HTTPNotFound()
        
        broker.delete_db()
        if not broker.is_deleted():
            return HTTPConflict(request=req)
        
        object_versions = req.headers.get('x-versions-location')
        if object_versions:
            lcontainer = object_versions.split('/')[0]
            ver_broker = self._get_direr_broker(drive, part, account, lcontainer,direr)
            if not ver_broker.is_deleted():
                versize = ver_broker.get_data_dir_size()
                ver_broker.delete_db()
                dirsize = versize + dirsize
                                
        self.account_update(req, account, dirsize, add_flag=False)
        return HTTPNoContent(request=req)
        
    @public
    def RESET(self, req):
          
        try:
            drive, part, account, container, direr = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
            
        if self.mount_check and not check_mount(self.root, drive):
            return HTTPInsufficientStorage(drive=drive, request=req)
        
        broker = self._get_direr_broker(drive, part, account, container,direr)
        
        dirsize = broker.get_data_dir_size()
        
        if broker.is_deleted():
            return HTTPNotFound()
    
        broker.reset_db()
        
        object_versions = req.headers.get('x-versions-location')
        if object_versions:
            lcontainer = object_versions.split('/')[0]
            ver_broker = self._get_direr_broker(drive, part, account, lcontainer,direr)
            if not ver_broker.is_deleted():
                versize = ver_broker.get_data_dir_size()
                ver_broker.delete_db()
                dirsize = versize + dirsize
        self.account_update(req, account, dirsize, add_flag=False)
                     
        return HTTPNoContent(request=req)
        
        
        
    @public
    def DELETE_RECYCLE(self, req):
        
        try:
            drive, part, account, src_container, src_direr = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
        
        recycle_uuid = get_uuid()
        recycle_container = 'recycle'
        
        user_obj = 'user' + '/' + recycle_uuid
        
        if self.mount_check and not check_mount(self.root, drive):
            return HTTPInsufficientStorage(drive=drive, request=req)
        
        src_broker = self._get_direr_broker(drive, part, account, src_container,src_direr)
        user_broker = self._get_meta_broker(drive, part, account, recycle_container,user_obj,recycle_uuid)
        
        if src_broker.is_deleted():
            return HTTPNotFound()
        
        if not user_broker.is_deleted():
            self.del_dir(user_broker.datadir)
                                
        if user_broker.fhr_dir_is_deleted():
            user_broker.create_dir_object(user_broker.fhr_path)
            
        user_broker.move(src_broker.datadir)
        
        if user_broker.is_deleted():
            return HTTPConflict(request=req)
         
        user_broker.metadata = src_broker.metadata
        user_broker.metadata['user_path'] = '/' + src_container + '/' + src_direr
        user_broker.metadata['recycle_uuid'] = recycle_uuid
        user_broker.metadata['ftype'] = 'd'
        user_broker.metadata[X_CONTENT_LENGTH] = '0'
        user_broker.metadata[X_ETAG] = 'dir'
        
        user_broker.update_metadata(user_broker.metadata)
                
        return HTTPCreated(request=req)
    
        
    @public
    def MOVE_RECYCLE(self, req):
        
        try:
            drive, part, account, src_container, src_direr = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
        
        try:
            dst_path = req.headers.get('x-move-dst')
            dst_container, dst_direr = split_path(
                unquote(dst_path), 1, 2, True)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
            
        recycle_uuid = src_direr[5:]
        
        if self.mount_check and not check_mount(self.root, drive):
            return HTTPInsufficientStorage(drive=drive, request=req)
        
        src_broker = self._get_meta_broker(drive, part, account, src_container,src_direr,recycle_uuid)
        dst_broker = self._get_direr_broker(drive, part, account, dst_container,dst_direr)
        
        if src_broker.is_deleted():
            return HTTPNotFound()
        
        if not dst_broker.is_deleted():
            return HTTPConflict(request=req)
                                
        if dst_broker.fhr_dir_is_deleted():
            dst_broker.create_dir_object(dst_broker.fhr_path)
            
        dst_broker.move(src_broker.datadir)
        
        if dst_broker.is_deleted():
            return HTTPConflict(request=req)
         
        src_broker.meta_del()
                
        return HTTPCreated(request=req)
        
    @public
    def PUT(self, req):
        
        try:
            drive, part, account, container, direr = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
            
        if self.mount_check and not check_mount(self.root, drive):
            return HTTPInsufficientStorage(drive=drive, request=req)
        
        broker = self._get_direr_broker(drive, part, account, container,direr)
        
        if not os.path.exists(broker.db_file):
            created = True
        else:
            created = broker.is_deleted()
            broker.update_put_timestamp()
            if broker.is_deleted():
                return HTTPConflict(request=req)
            
        if created:
            return HTTPCreated(request=req)
        else:
            return HTTPAccepted(request=req)

    @public
    def MOVE(self, req):
        
        try:
            drive, part, account, src_container, src_direr = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
        
        if 'recycle' == src_container:
            return self.MOVE_RECYCLE(req)
        
        try:
            dst_path = req.headers.get('x-move-dst')
            dst_container, dst_direr = split_path(
                unquote(dst_path), 1, 2, True)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
            
            
        if self.mount_check and not check_mount(self.root, drive):
            return HTTPInsufficientStorage(drive=drive, request=req)
        
        src_broker = self._get_direr_broker(drive, part, account, src_container,src_direr)
        dst_broker = self._get_direr_broker(drive, part, account, dst_container,dst_direr)
        
        if src_broker.is_deleted():
            return HTTPNotFound()
        
        if not dst_broker.is_deleted():
            return HTTPConflict(request=req)
                                
        dst_broker.move(src_broker.datadir)
        
        if dst_broker.is_deleted():
            return HTTPConflict(request=req)
            
        object_versions = req.headers.get('x-versions-location')
        if object_versions:
            lcontainer = object_versions.split('/')[0]
            ver_broker = self._get_direr_broker(drive, part, account, lcontainer,src_direr)
            if not ver_broker.is_deleted():
                dst_broker = self._get_direr_broker(drive, part, account, lcontainer,dst_direr)
                
                if not dst_broker.is_deleted():
                    dst_broker.delete_db()
                                
                dst_broker.move(ver_broker.datadir)
                
        return HTTPCreated(request=req)
    
    
    @public
    def COPY(self, req):
        
        try:
            drive, part, account, src_container, src_direr = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
        
        try:
            dst_path = req.headers.get('x-copy-dst')
            dst_container, dst_direr = split_path(
                unquote(dst_path), 1, 2, True)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
            
            
        if self.mount_check and not check_mount(self.root, drive):
            return HTTPInsufficientStorage(drive=drive, request=req)
        
        src_broker = self._get_direr_broker(drive, part, account, src_container,src_direr)
        dst_broker = self._get_direr_broker(drive, part, account, dst_container,dst_direr)
        dirsize = src_broker.get_data_dir_size()
        if src_broker.is_deleted():
            return HTTPNotFound()
        
        if not dst_broker.is_deleted():
            return HTTPConflict(request=req)
                                
        dst_broker.copy(src_broker.datadir)
        
        if dst_broker.is_deleted():
            return HTTPConflict(request=req)
            
        object_versions = req.headers.get('x-versions-location')
        if object_versions:
            lcontainer = object_versions.split('/')[0]
            ver_broker = self._get_direr_broker(drive, part, account, lcontainer,src_direr)
            if not ver_broker.is_deleted():
                dst_broker = self._get_direr_broker(drive, part, account, lcontainer,dst_direr)
                
                if not dst_broker.is_deleted():
                    dst_broker.delete_db()
                                
                dst_broker.copy(ver_broker.datadir)
                dstsize = dst_broker.get_data_dir_size()
                dirsize = dstsize + dirsize
                
        self.account_update(req, account, dirsize, add_flag=True)
        
        return HTTPCreated(request=req)
    
        
    @public
    def META_GET(self, req):
        
        try:
            drive, part, account, container, direr = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
        
        if container != 'recycle':
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
        
        if self.mount_check and not check_mount(self.root, drive):
            return HTTPInsufficientStorage(drive=drive, request=req)
        
        broker = self._get_direr_broker(drive, part, account, container,direr)
        
        if broker.is_deleted():
            return HTTPNotFound(request=req)
        
        try:
            out_content_type = req.accept.best_match(
                                    ['text/plain', 'application/json',
                                     'application/xml', 'text/xml'],
                                    default_match='text/plain')
        except AssertionError, err:
            return HTTPBadRequest(body='bad accept header: %s' % req.accept,
                                  content_type='text/plain', request=req)
            
        out_content_type = 'application/json'
        
        container_list = broker.list_objects_meta_iter()
        if out_content_type == 'application/json':
            data = []
            for objdata in container_list:
                if 'recycle' == container:
                    (name, size, etag,path,uuid,ftype) = objdata
                    data.append({'bytes': size,'hash': etag,'name': name,'path':path,'uuid':uuid,'ftype':ftype})
                else:
                    (name, size, etag) = objdata
                    data.append({'bytes': size,'hash': etag,'name': name})
            container_list = json.dumps(data)
       
        else:
            if not container_list:
                return HTTPNoContent(request=req )
            container_list = '\n'.join(r[0] for r in container_list) + '\n'
            
        ret = Response(body=container_list, request=req )
        ret.content_type = out_content_type
        ret.charset = 'utf-8'
        return ret
    
    @public
    def GET(self, req):
        
        try:
            drive, part, account, container, direr = split_path(
                unquote(req.path), 4, 5, True)
            validate_device_partition(drive, part)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), content_type='text/plain',
                                request=req)
        
        if container == 'recycle':
            return self.META_GET(req)
        
        if self.mount_check and not check_mount(self.root, drive):
            return HTTPInsufficientStorage(drive=drive, request=req)
        
        broker = self._get_direr_broker(drive, part, account, container,direr)
        
        if broker.is_deleted():
            return HTTPNotFound(request=req)
        
        try:
            out_content_type = req.accept.best_match(
                                    ['text/plain', 'application/json',
                                     'application/xml', 'text/xml'],
                                    default_match='text/plain')
        except AssertionError, err:
            return HTTPBadRequest(body='bad accept header: %s' % req.accept,
                                  content_type='text/plain', request=req)
            
        out_content_type = 'application/json'
        container_list = broker.list_objects_iter()
        if out_content_type == 'application/json':
            data = []
            for (name, create_at,size, etag) in container_list:
                
                data.append({'bytes': size,
                             'hash': etag,
                            'name': name,
                            'modificationTime':str(create_at)})
            container_list = json.dumps(data)
       
        else:
            if not container_list:
                return HTTPNoContent(request=req )
            container_list = '\n'.join(r[0] for r in container_list) + '\n'
            
        ret = Response(body=container_list, request=req )
        ret.content_type = out_content_type
        ret.charset = 'utf-8'
        return ret

    def __call__(self, env, start_response):

        start_time = time.time()
        req = Request(env)

        if 'd' != req.headers.get('X-Ftype'):
            return self.app(env,start_response)

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


def filter_factory(global_conf, **local_conf):
    """paste.deploy app factory for creating WSGI container server apps"""
    conf = global_conf.copy()
    conf.update(local_conf)

    def direr_filter(app):
        return DirerController(app,conf)
    return direr_filter

