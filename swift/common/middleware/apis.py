# -*- coding: utf-8 -*-
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

from eventlet import Timeout
from webob import Request
from webob.exc import HTTPServerError
import uuid

from swift.common.utils import get_logger
from swift.common.apis.api_quota import *
from swift.common.apis.api_dir import *

class ApiMiddleware(object):

    def __init__(self, app, conf):
        self.app = app
        self.logger = get_logger(conf, log_route='catch-errors')

    def __call__(self, env, start_response):
        if is_get_quota(env):
            get_quota_env(env)
            
        elif is_set_quota(env):
            set_quota_env(env)
            
        elif is_dir_create(env):
            dir_creaet_env(env)
            
        elif is_file_create(env):
            file_creaet_env(env)
            
        elif is_file_open(env):
            file_open_env(env)
            
        elif is_link_create(env):
            link_creaet_env(env)
            
        elif is_file_rename(env):
            file_rename_env(env)
            
        elif is_file_attr(env):
            file_attr_env(env)
            
        elif is_file_permission(env):
            file_permission_env(env)
            
        elif is_list_recycle(env):
            list_recycle_env(env)
            
        elif is_clear_recycle(env):
            clear_recycle_env(env)
            
        return self.app(env, start_response)

def filter_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)

    def api_filter(app):
        return ApiMiddleware(app, conf)
    return api_filter
