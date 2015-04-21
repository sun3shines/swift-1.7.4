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

"""
Implementation of WSGI Request and Response objects.

This library has a very similar API to Webob.  It wraps WSGI request
environments and response values into objects that are more friendly to
interact with.
"""

from collections import defaultdict
from cStringIO import StringIO
import UserDict
import time
from functools import partial
from datetime import datetime, timedelta, tzinfo
from email.utils import parsedate
import urlparse
import urllib2
import re
import random
import functools
import inspect
from webob import Request, Response

from webob.exc import HTTPAccepted, HTTPBadRequest, \
    HTTPCreated, HTTPForbidden, HTTPInternalServerError, \
    HTTPMethodNotAllowed, HTTPNoContent, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPConflict,HTTPException
    

def wsgify(func):
    """
    A decorator for translating functions which take a swob Request object and
    return a Response object into WSGI callables.  Also catches any raised
    HTTPExceptions and treats them as a returned Response.
    """
    argspec = inspect.getargspec(func)
    if argspec.args and argspec.args[0] == 'self':
        @functools.wraps(func)
        def _wsgify_self(self, env, start_response):
            try:
                return func(self, Request(env))(env, start_response)
            except HTTPException, err_resp:
                return err_resp(env, start_response)
        return _wsgify_self
    else:
        @functools.wraps(func)
        def _wsgify_bare(env, start_response):
            try:
                return func(Request(env))(env, start_response)
            except HTTPException, err_resp:
                return err_resp(env, start_response)
        return _wsgify_bare



