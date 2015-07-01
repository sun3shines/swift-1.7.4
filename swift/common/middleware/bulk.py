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
from swift.common.bufferedhttp import jresponse

from swift.common.utils import split_path

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

class Bulk(object):

    def __init__(self, app, conf):
        self.app = app
        self.max_containers = int(
            conf.get('max_containers_per_extraction', 10000))
        self.max_failed_extractions = int(
            conf.get('max_failed_extractions', 1000))
        self.max_deletes_per_request = int(
            conf.get('max_deletes_per_request', 1000))

    def create_container(self, req, container_path):
        """
        Makes a subrequest to create a new container.
        :params container_path: an unquoted path to a container to be created
        :returns: None on success
        :raises: CreateContainerError on creation error
        """
        new_env = req.environ.copy()
        new_env['PATH_INFO'] = container_path
        new_env['swift.source'] = 'EA'
        create_cont_req = Request.blank(container_path, environ=new_env)
        resp = create_cont_req.get_response(self.app)
        if resp.status_int // 100 != 2:
            raise CreateContainerError(
                "Create Container Failed: " + container_path,
                resp.status_int, resp.status)

    def get_objs_to_delete(self, req):
        """
        Will populate objs_to_delete with data from request input.
        :params req: a Swob request
        :returns: a list of the contents of req.body when separated by newline.
        :raises: HTTPException on failures
        """
        line = ''
        data_remaining = True
        objs_to_delete = []
        if req.content_length is None and \
                req.headers.get('transfer-encoding', '').lower() != 'chunked':
            raise HTTPLengthRequired(request=req)

        while data_remaining:
            if '\n' in line:
                obj_to_delete, line = line.split('\n', 1)
                objs_to_delete.append(unquote(obj_to_delete))
            else:
                data = req.environ['wsgi.input'].read(MAX_PATH_LENGTH)
                if data:
                    line += data
                else:
                    data_remaining = False
                    if line.strip():
                        objs_to_delete.append(unquote(line))
            if len(objs_to_delete) > self.max_deletes_per_request:
                raise HTTPRequestEntityTooLarge(
                    'Maximum Bulk Deletes: %d per request' %
                    self.max_deletes_per_request)
            if len(line) > MAX_PATH_LENGTH * 2:
                raise HTTPBadRequest('Invalid File Name')
        return objs_to_delete

    def handle_delete(self, req, objs_to_delete=None, user_agent='BulkDelete',
                      swift_source='BD'):
        """
        :params req: a swob Request
        :raises HTTPException: on unhandled errors
        :returns: a swob Response
        """
        try:
            vrs, account, _junk = split_path(req.path,2, 3, True)
        except ValueError:
            return HTTPNotFound(request=req)

        incoming_format = req.headers.get('Content-Type')
        if incoming_format and not incoming_format.startswith('text/plain'):
            # For now only accept newline separated object names
            return HTTPNotAcceptable(request=req)
        out_content_type = 'application/json'
        if not out_content_type:
            return HTTPNotAcceptable(request=req)

        if objs_to_delete is None:
            objs_to_delete = self.get_objs_to_delete(req)
        failed_files = []
        success_count = not_found_count = 0
        failed_file_response_type = HTTPBadRequest
        for obj_to_delete in objs_to_delete:
            obj_to_delete = obj_to_delete.strip().lstrip('/')
            if not obj_to_delete:
                continue
            delete_path = '/'.join(['', vrs, account, obj_to_delete])
            if not check_utf8(delete_path):
                failed_files.append([quote(delete_path),
                                     HTTPPreconditionFailed().status])
                continue
            new_env = req.environ.copy()
            
            new_env['PATH_INFO'] = delete_path
            del(new_env['wsgi.input'])
            new_env['CONTENT_LENGTH'] = 0
            new_env['HTTP_USER_AGENT'] = \
                '%s %s' % (req.environ.get('HTTP_USER_AGENT'), user_agent)
            new_env['swift.source'] = swift_source
            delete_obj_req = Request.blank(delete_path, new_env)
            resp = delete_obj_req.get_response(self.app)
            if resp.status_int // 100 == 2:
                success_count += 1
            elif resp.status_int == HTTP_NOT_FOUND:
                not_found_count += 1
            elif resp.status_int == HTTP_UNAUTHORIZED:
                return HTTPUnauthorized(request=req)
            else:
                if resp.status_int // 100 == 5:
                    failed_file_response_type = HTTPBadGateway
                failed_files.append([quote(delete_path), resp.status])

        resp_body = get_response_body(
            out_content_type,
            {'Number Deleted': success_count,
             'Number Not Found': not_found_count},
            failed_files)
        if (success_count or not_found_count) and not failed_files:
            return jresponse('0','',req,200,param=resp_body)
        
        if failed_files:
            return failed_file_response_type(
                json.dumps(resp_body), content_type=out_content_type)
        return HTTPBadRequest('Invalid bulk delete.')

    @wsgify
    def __call__(self, req):
        extract_type = req.GET.get('extract-archive')
        
        if 'bulk-delete' in req.GET and req.method == 'DELETE':
            return self.handle_delete(req)

        return self.app


def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def bulk_filter(app):
        return Bulk(app, conf)
    return bulk_filter
