# -*- coding: utf-8 -*-


from swift.common.utils import split_path,qsparam

def is_get_quota(env):
    method = env.get('REQUEST_METHOD')
    path = env.get('PATH_INFO')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    _, _, container,_ = split_path(path,1, 4,True)
    
    if 'GET' == method and 'info' == param.get('op') and 'quota'==container: 
        return True
    return False

def get_quota_env(env):
    
    path = env['PATH_INFO']
    env['REQUEST_METHOD'] = 'META'
    env['PATH_INFO'] = env['RAW_PATH_INFO'] = '/'.join(path.split('/')[:-1])
    env.pop('QUERY_STRING')
    return True

def is_set_quota(env):
    method = env.get('REQUEST_METHOD')
    path = env.get('PATH_INFO')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    _, _, container,_ = split_path(path,1, 4,True)
    
    if 'POST' == method and 'createstorage' == param.get('op') and 'quota'==container: 
        return True
    return False

def set_quota_env(env):
    
    path = env['PATH_INFO']
    env['REQUEST_METHOD'] = 'POST'
    env['PATH_INFO'] = env['RAW_PATH_INFO'] = '/'.join(path.split('/')[:-1])
    env.pop('QUERY_STRING')
    return True

