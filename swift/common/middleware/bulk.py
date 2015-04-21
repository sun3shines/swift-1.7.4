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
    """
    Returns a properly formatted response body according to format.
    :params data_format: resulting format
    :params data_dict: generated data about results.
    :params error_list: list of quoted filenames that failed
    """
    if data_format == 'text/plain':
        output = ''
        for key in sorted(data_dict.keys()):
            output += '%s: %s\n' % (key, data_dict[key])
        output += 'Errors:\n'
        output += '\n'.join(
            ['%s, %s' % (name, status)
             for name, status in error_list])
        return output
    if data_format == 'application/json':
        data_dict['Errors'] = error_list
        return json.dumps(data_dict)
    if data_format.endswith('/xml'):
        output = '<?xml version="1.0" encoding="UTF-8"?>\n<delete>\n'
        for key in sorted(data_dict.keys()):
            xml_key = key.replace(' ', '_').lower()
            output += '<%s>%s</%s>\n' % (xml_key, data_dict[key], xml_key)
        output += '<errors>\n'
        output += '\n'.join(
            ['<object>'
             '<name>%s</name><status>%s</status>'
             '</object>' % (saxutils.escape(name), status) for
             name, status in error_list])
        output += '</errors>\n</delete>\n'
        return output
    raise HTTPNotAcceptable('Invalid output type')


class Bulk(object):
    """
    Middleware that will do many operations on a single request.

    Extract Archive:

    Expand tar files into a swift account. Request must be a PUT with the
    query parameter ?extract-archive=format specifying the format of archive
    file. Accepted formats are tar, tar.gz, and tar.bz2.

    For a PUT to the following url:

    /v1/AUTH_Account/$UPLOAD_PATH?extract-archive=tar.gz

    UPLOAD_PATH is where the files will be expanded to. UPLOAD_PATH can be a
    container, a pseudo-directory within a container, or an empty string. The
    destination of a file in the archive will be built as follows:

    /v1/AUTH_Account/$UPLOAD_PATH/$FILE_PATH

    Where FILE_PATH is the file name from the listing in the tar file.

    If the UPLOAD_PATH is an empty string, containers will be auto created
    accordingly and files in the tar that would not map to any container (files
    in the base directory) will be ignored.

    Only regular files will be uploaded. Empty directories, symlinks, etc will
    not be uploaded.

    If all valid files were uploaded successfully will return an HTTPCreated
    response. If any files failed to be created will return an HTTPBadGateway
    response. In both cases the response body will specify the number of files
    successfully uploaded and a list of the files that failed. The return body
    will be formatted in the way specified in the request's Accept header.
    Acceptable formats are text/plain, application/json, application/xml, and
    text/xml.

    There are proxy logs created for each file (which becomes a subrequest) in
    the tar. The subrequest's proxy log will have a swift.source set to "EA"
    the log's content length will reflect the unzipped size of the file. If
    double proxy-logging is used the leftmost logger will not have a
    swift.source set and the content length will reflect the size of the
    payload sent to the proxy (the unexpanded size of the tar.gz).

    Bulk Delete:

    Will delete multiple objects or containers from their account with a
    single request. Responds to DELETE requests with query parameter
    ?bulk-delete set. The Content-Type should be set to text/plain.
    The body of the DELETE request will be a newline separated list of url
    encoded objects to delete. You can only delete 1000 (configurable) objects
    per request. The objects specified in the DELETE request body must be URL
    encoded and in the form:

    /container_name/obj_name

    or for a container (which must be empty at time of delete)

    /container_name

    If all items were successfully deleted (or did not exist), will return an
    HTTPOk. If any failed to delete, will return an HTTPBadGateway. In
    both cases the response body will specify the number of items
    successfully deleted, not found, and a list of those that failed.
    The return body will be formatted in the way specified in the request's
    Accept header. Acceptable formats are text/plain, application/json,
    application/xml, and text/xml.

    There are proxy logs created for each object or container (which becomes a
    subrequest) that is deleted. The subrequest's proxy log will have a
    swift.source set to "BD" the log's content length of 0. If double
    proxy-logging is used the leftmost logger will not have a
    swift.source set and the content length will reflect the size of the
    payload sent to the proxy (the list of objects/containers to be deleted).
    """

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
        out_content_type = req.accept.best_match(ACCEPTABLE_FORMATS)
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
            return HTTPOk(resp_body, content_type=out_content_type)
        if failed_files:
            return failed_file_response_type(
                resp_body, content_type=out_content_type)
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
