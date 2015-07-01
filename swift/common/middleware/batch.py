# -*- coding: utf-8 -*-
# Copyright (c) 2013 OpenStack, LLC.
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

import tarfile
from urllib import quote, unquote
from xml.sax import saxutils
from webob.exc import  HTTPBadGateway, \
    HTTPCreated, HTTPBadRequest, HTTPNotFound, HTTPUnauthorized, HTTPOk, \
    HTTPPreconditionFailed, HTTPRequestEntityTooLarge, HTTPNotAcceptable, \
    HTTPLengthRequired

from webob import Request

from swift.common.mx_swob import wsgify

from swift.common.utils import json, TRUE_VALUES
from swift.common.constraints import check_utf8, MAX_FILE_SIZE
from swift.common.http import HTTP_BAD_REQUEST, HTTP_UNAUTHORIZED, \
    HTTP_NOT_FOUND
from swift.common.constraints import MAX_OBJECT_NAME_LENGTH, \
    MAX_CONTAINER_NAME_LENGTH

from swift.common.env_utils import *
from swift.common.utils import split_path
from swift.common.bufferedhttp import jresponse

MAX_PATH_LENGTH = MAX_OBJECT_NAME_LENGTH + MAX_CONTAINER_NAME_LENGTH + 2


class CreateContainerError(Exception):
    def __init__(self, msg, status_int, status):
        self.status_int = status_int
        self.status = status
        Exception.__init__(self, msg)


ACCEPTABLE_FORMATS = ['text/plain', 'application/json', 'application/xml',
                      'text/xml']


def get_response_body(data_format, data_dict, error_list):
    
    data_dict['Errors'] = error_list
    return data_dict
    
class Batch(object):
    

    def __init__(self, app, conf):
        self.app = app
        
    def batch_delete(self,req):
        
        try:
            version, account, _junk = split_path(req.path,2, 3, True)
        except ValueError:
            return HTTPNotFound(request=req)

        out_content_type = 'application/json'
        if not out_content_type:
            return HTTPNotAcceptable(request=req)
        
        failed_files = []
        success_count = not_found_count = 0
        failed_file_response_type = HTTPBadRequest

        batchparams = json.loads(req.body)
        for param in batchparams.get('list'):
            
            ppath = param.get('path').strip()
            pftype = param.get('ftype').strip()
            
            new_env = req.environ.copy()    
            del(new_env['wsgi.input'])
            new_env['CONTENT_LENGTH'] = 0
            new_path = '/' + version + '/' + account+ ppath
            
            if isinstance(new_path, unicode):
                new_path = new_path.encode('utf-8')
                
            if not check_utf8(new_path):
                failed_files.append([quote(new_path),
                                     HTTPPreconditionFailed().status])
                continue
        
            new_env['PATH_INFO'] = new_path
            new_env['QUERY_STRING'] = new_env['QUERY_STRING'] + '&ftype=%s' % (pftype)
            
            if isinstance(new_env.get('PATH_INFO'), unicode):
                new_env['PATH_INFO'] = new_env['PATH_INFO'].encode('utf-8')
            
            new_req = Request.blank(new_path, new_env)
            new_req.GET['ftype'] = pftype
            
            
            resp = new_req.get_response(self.app)
            if resp.status_int // 100 == 2:
                success_count += 1
            elif resp.status_int == HTTP_NOT_FOUND:
                not_found_count += 1
            elif resp.status_int == HTTP_UNAUTHORIZED:
                return HTTPUnauthorized(request=req)
            else:
                if resp.status_int // 100 == 5:
                    failed_file_response_type = HTTPBadGateway
                failed_files.append([quote(new_path), resp.status])

        resp_body = get_response_body(
            out_content_type,
            {'Number Deleted': success_count,
             'Number Not Found': not_found_count},
            failed_files)
        
        if batchparams.get('list') and success_count < len(batchparams.get('list')):
            return jresponse('-1','some failed',req,200,param=resp_body)
        
        elif batchparams.get('list') and success_count == len(batchparams.get('list')):
            return jresponse('0','',req,200)
        
        '''
        if (success_count or not_found_count) and not failed_files:
            return jresponse('0','',req,200,param=resp_body)
        
        if failed_files:
            return failed_file_response_type(
                json.dumps(resp_body), content_type=out_content_type)
        ''' 
        return HTTPBadRequest('Invalid batch delete.')
    
    def batch_copy(self,req):
        
        try:
            version, account, _junk = split_path(req.path,2, 3, True)
        except ValueError:
            return HTTPNotFound(request=req)

        out_content_type = 'application/json'
        if not out_content_type:
            return HTTPNotAcceptable(request=req)
        
        failed_files = []
        success_count = not_found_count = 0
        failed_file_response_type = HTTPBadRequest

        batchparams = json.loads(req.body)
        for param in batchparams.get('list'):
            
            pfrom = param.get('from').strip()
            pto = param.get('to').strip()
            pftype = param.get('ftype').strip()
            
            new_env = req.environ.copy()    
            del(new_env['wsgi.input'])
            new_env['CONTENT_LENGTH'] = 0
        
            new_path = '/' + version + '/' + account+ pfrom
            if isinstance(new_path, unicode):
                new_path = new_path.encode('utf-8')
            if not check_utf8(new_path):
                failed_files.append([quote(new_path),
                                     HTTPPreconditionFailed().status])
                continue
        
            new_env['PATH_INFO'] = new_path
            new_env['QUERY_STRING'] = new_env['QUERY_STRING'] + '&ftype=%s' % (pftype)
            
            new_req = Request.blank(new_path, new_env)
            
            new_req.headers['Destination'] = pto
            new_req.GET['ftype'] = pftype
            
            
            resp = new_req.get_response(self.app)
            if resp.status_int // 100 == 2:
                success_count += 1
            elif resp.status_int == HTTP_NOT_FOUND:
                not_found_count += 1
            elif resp.status_int == HTTP_UNAUTHORIZED:
                return HTTPUnauthorized(request=req)
            else:
                if resp.status_int // 100 == 5:
                    failed_file_response_type = HTTPBadGateway
                failed_files.append([quote(new_path), resp.status])

        resp_body = get_response_body(
            out_content_type,
            {'Number Copyed': success_count,
             'Number Not Found': not_found_count},
            failed_files)
        
        if batchparams.get('list') and success_count < len(batchparams.get('list')):
            return jresponse('-1','some failed',req,200,param=resp_body)
        
        elif batchparams.get('list') and success_count == len(batchparams.get('list')):
            return jresponse('0','',req,200)
        
        '''
        if (success_count or not_found_count) and not failed_files:
            return jresponse('0','',req,200,param=resp_body)
        
        if failed_files:
            return failed_file_response_type(
                json.dumps(resp_body), content_type=out_content_type)
        ''' 
        return HTTPBadRequest('Invalid batch delete.')
    

    def batch_move(self,req):
        
        try:
            version, account, _junk = split_path(req.path,2, 3, True)
        except ValueError:
            return HTTPNotFound(request=req)

        out_content_type = 'application/json'
        if not out_content_type:
            return HTTPNotAcceptable(request=req)
        
        failed_files = []
        success_count = not_found_count = 0
        failed_file_response_type = HTTPBadRequest

        batchparams = json.loads(req.body)
        
        move_flag = False
        move_resp = None
        
        for param in batchparams.get('list'):
            
            pfrom = param.get('from').strip()
            pto = param.get('to').strip()
            pftype = param.get('ftype').strip()
            
            if pfrom.find('_versions') != -1:
                move_flag = True
                
            new_env = req.environ.copy()    
            del(new_env['wsgi.input'])
            new_env['CONTENT_LENGTH'] = 0
        
            new_path = '/' + version + '/' + account+ pfrom
            if isinstance(new_path, unicode):
                new_path = new_path.encode('utf-8')
                
            if not check_utf8(new_path):
                failed_files.append([quote(new_path),
                                     HTTPPreconditionFailed().status])
                continue
        
            new_env['PATH_INFO'] = new_path
            new_env['QUERY_STRING'] = new_env['QUERY_STRING'] + '&ftype=%s' % (pftype)
            
                
            new_req = Request.blank(new_path, new_env)
            
            new_req.headers['Destination'] = pto
            new_req.GET['ftype'] = pftype
            
            
            resp = new_req.get_response(self.app)
            
            if not move_resp:
                move_resp = resp
                
            if resp.status_int // 100 == 2:
                success_count += 1
            elif resp.status_int == HTTP_NOT_FOUND:
                not_found_count += 1
            elif resp.status_int == HTTP_UNAUTHORIZED:
                return HTTPUnauthorized(request=req)
            else:
                if resp.status_int // 100 == 5:
                    failed_file_response_type = HTTPBadGateway
                failed_files.append([quote(new_path), resp.status])

        resp_body = get_response_body(
            out_content_type,
            {'Number Moved': success_count,
             'Number Not Found': not_found_count},
            failed_files)
        
        if move_flag and batchparams.get('list') and len(batchparams.get('list'))==2:
            return move_resp
        
        if batchparams.get('list') and success_count < len(batchparams.get('list')):
            return jresponse('-1','some failed',req,200,param=resp_body)
        
        elif batchparams.get('list') and success_count == len(batchparams.get('list')):
            return jresponse('0','',req,200)
        
        '''
        if (success_count or not_found_count) and not failed_files:
            
            return jresponse('0','',req,200,param=resp_body)
        
        if failed_files:
            return failed_file_response_type(
                json.dumps(resp_body), content_type=out_content_type)
        '''
         
        return HTTPBadRequest('Invalid batch move.')
        
    
    def batch_recycle(self,req):
        
        
        try:
            version, account, _junk = split_path(req.path,2, 3, True)
        except ValueError:
            return HTTPNotFound(request=req)

        out_content_type = 'application/json'
        if not out_content_type:
            return HTTPNotAcceptable(request=req)
        
        failed_files = []
        success_count = not_found_count = 0
        failed_file_response_type = HTTPBadRequest

        batchparams = json.loads(req.body)
        for param in batchparams.get('list'):
            
            puuid = param.get('uuid').strip()
            ppath = param.get('path').strip()
            pftype = param.get('ftype').strip()
            
            new_env = req.environ.copy()    
            del(new_env['wsgi.input'])
            new_env['CONTENT_LENGTH'] = 0
        
            new_path = '/' + version + '/' + account+ '/' + 'recycle/user' + '/' + puuid
            if isinstance(new_path, unicode):
                new_path = new_path.encode('utf-8')
                
            if not check_utf8(new_path):
                failed_files.append([quote(new_path),
                                     HTTPPreconditionFailed().status])
                continue
        
            new_env['PATH_INFO'] = new_path
            new_env['QUERY_STRING'] = new_env['QUERY_STRING'] + '&ftype=%s' % (pftype)
            
            new_req = Request.blank(new_path, new_env)
            
            new_req.headers['Destination'] = ppath
            new_req.GET['ftype'] = pftype
            new_req.GET['op'] = 'MOVE'
            
            resp = new_req.get_response(self.app)
            if resp.status_int // 100 == 2:
                success_count += 1
            elif resp.status_int == HTTP_NOT_FOUND:
                not_found_count += 1
            elif resp.status_int == HTTP_UNAUTHORIZED:
                return HTTPUnauthorized(request=req)
            else:
                if resp.status_int // 100 == 5:
                    failed_file_response_type = HTTPBadGateway
                failed_files.append([quote(new_path), resp.status])

        resp_body = get_response_body(
            out_content_type,
            {'Number Recycled': success_count,
             'Number Not Found': not_found_count},
            failed_files)
        
        if batchparams.get('list') and success_count < len(batchparams.get('list')):
            return jresponse('-1','some failed',req,200,param=resp_body)
        
        elif batchparams.get('list') and success_count == len(batchparams.get('list')):
            return jresponse('0','',req,200)
        
        '''
        if (success_count or not_found_count) and not failed_files:
            return jresponse('0','',req,200,param=resp_body)
        
        if failed_files:
            return failed_file_response_type(
                json.dumps(resp_body), content_type=out_content_type)
        ''' 
        return HTTPBadRequest('Invalid batch delete.')
    
    def batch_reset(self,req):

        try:
            version, account, _junk = split_path(req.path,2, 3, True)
        except ValueError:
            return HTTPNotFound(request=req)

        out_content_type = 'application/json'
        if not out_content_type:
            return HTTPNotAcceptable(request=req)
        
        failed_files = []
        success_count = not_found_count = 0
        failed_file_response_type = HTTPBadRequest

        rcyc_flag = False
        rcy_resp = None
        
        batchparams = json.loads(req.body)
        for param in batchparams.get('list'):
            
            ppath = param.get('path').strip()
            pftype = param.get('ftype').strip()
            
            if ppath.find('/recycle/meta') != -1:
                rcyc_flag = True
                    
            new_env = req.environ.copy()    
            del(new_env['wsgi.input'])
            new_env['CONTENT_LENGTH'] = 0
            new_path = '/' + version + '/' + account+ ppath
            if isinstance(new_path, unicode):
                new_path = new_path.encode('utf-8')
                
            if not check_utf8(new_path):
                failed_files.append([quote(new_path),
                                     HTTPPreconditionFailed().status])
                continue
        
            new_env['PATH_INFO'] = new_path
            new_env['QUERY_STRING'] = new_env['QUERY_STRING'] + '&ftype=%s' % (pftype)
            new_req = Request.blank(new_path, new_env)
            new_req.GET['ftype'] = pftype
            
            
            resp = new_req.get_response(self.app)
            if not rcy_resp:
                rcy_resp = resp
                
            if resp.status_int // 100 == 2:
                success_count += 1
            elif resp.status_int == HTTP_NOT_FOUND:
                not_found_count += 1
            elif resp.status_int == HTTP_UNAUTHORIZED:
                return HTTPUnauthorized(request=req)
            else:
                if resp.status_int // 100 == 5:
                    failed_file_response_type = HTTPBadGateway
                failed_files.append([quote(new_path), resp.status])

        resp_body = get_response_body(
            out_content_type,
            {'Number Reseted': success_count,
             'Number Not Found': not_found_count},
            failed_files)
        
        if rcyc_flag:
            return rcy_resp
        
        if batchparams.get('list') and success_count < len(batchparams.get('list')):
            return jresponse('-1','some failed',req,200,param=resp_body)
        
        elif batchparams.get('list') and success_count == len(batchparams.get('list')):
            return jresponse('0','',req,200)
        
        '''
        if (success_count or not_found_count) and not failed_files:
            return jresponse('0','',req,200,param=resp_body)
            
        if failed_files:
            return failed_file_response_type(
                json.dumps(resp_body), content_type=out_content_type)
        ''' 
        return HTTPBadRequest('Invalid batch delete.')
    
    def handle_batch(self, req):
        
        
        if 'DELETE' == req.GET.get('op'):
            return self.batch_delete(req)
        
        if 'RESET' == req.GET.get('op'):
            return self.batch_reset(req)
        
        if 'MOVE' == req.GET.get('op'):
            return self.batch_move(req)
        
        if 'COPY' == req.GET.get('op'):
            return self.batch_copy(req)
        if 'MOVERECYCLE' == req.GET.get('op'):
            return self.batch_recycle(req)
        
        return HTTPBadRequest('Invalid batch operations')

    @wsgify
    def __call__(self, req):
         
        container = split_path(req.path, 1, 4, True)[2]
        if 'batch' == container:
            return self.handle_batch(req)

        return self.app


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def batch_filter(app):
        return Batch(app, conf)
    return batch_filter
