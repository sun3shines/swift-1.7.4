# -*- coding: utf-8 -*-

from swift.common.utils import split_path,qsparam,newparamqs

def is_dir_create(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'PUT' == method and 'MKDIRS' == param.get('op'): 
        return True
    
    return False

def dir_creaet_env(env):
    
    if not env['fwuser_info'].get('lock'):
        env['fwuser_info']['comment'] = 'create dir'
        env['fwuser_info']['lock'] = True
        
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    param['ftype'] = 'd'
    env['QUERY_STRING'] = newparamqs(param)
    
    return True

def is_file_create(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'PUT' == method and 'CREATE' == param.get('op'): 
        return True
    
    return False

def file_creaet_env(env):

    if not env['fwuser_info'].get('lock'):
        env['fwuser_info']['comment'] = 'create file'
        env['fwuser_info']['lock'] = True
            
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    param['ftype'] = 'f'
    param.pop('op')
    env['QUERY_STRING'] = newparamqs(param)
    
    return True

def is_file_open(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'GET' == method and 'OPEN' == param.get('op'): 
        return True
    
    return False

def file_open_env(env):
    
    if not env['fwuser_info'].get('lock'):
        env['fwuser_info']['comment'] = 'get file'
        env['fwuser_info']['lock'] = True
        
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    param.pop('op')
    param['ftype'] = 'f'
    env['QUERY_STRING'] = newparamqs(param)
    return True

def is_link_create(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'PUT' == method and 'CREATESYMLINK' == param.get('op'): 
        return True
    
    return False

def link_creaet_env(env):
    
    if not env['fwuser_info'].get('lock'):
        env['fwuser_info']['comment'] = 'create link'
        env['fwuser_info']['lock'] = True
        
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    param['ftype'] = 'l'
    if param.has_key('destination'):
        dst = param.get('destination')
        env['HTTP_DESTINATION'] = dst
        param.pop('destination')
    env['QUERY_STRING'] = newparamqs(param)
    
def is_file_rename(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'PUT' == method and 'RENAME' == param.get('op') and 'f'==param.get('ftype'): 
        return True
    
    return False

def file_rename_env(env):
    
    if not env['fwuser_info'].get('lock'):
        env['fwuser_info']['comment'] = 'rename file'
        env['fwuser_info']['lock'] = True
        
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    if param.has_key('destination'):
        dst = param.get('destination')
        env['HTTP_DESTINATION'] = dst
        param.pop('destination')
    param['op'] = 'MOVE'
    env['QUERY_STRING'] = newparamqs(param)
    
    return True

def is_file_attr(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'GET' == method and 'GETFILEATTR' == param.get('op'): 
        return True
    
    return False

def file_attr_env(env):
    
    if not env['fwuser_info'].get('lock'):
        env['fwuser_info']['comment'] = 'get file attr'
        env['fwuser_info']['lock'] = True
        
    env['REQUEST_METHOD'] = 'META'
    env.pop('QUERY_STRING')
    
    return True

def is_file_permission(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'PUT' == method and 'SETPERMISSION' == param.get('op'): 
        return True
    
    return False

def file_permission_env(env):

    if not env['fwuser_info'].get('lock'):
        env['fwuser_info']['comment'] = 'set file permission'
        env['fwuser_info']['lock'] = True
        
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    if param.has_key('permission'):
        dst = param.get('permission')
        env['HTTP_X_OBJECT_PERMISSON'] = dst
        param.pop('permission')
        
    param.pop('op')
    param['ftype'] = 'f'
    env['QUERY_STRING'] = newparamqs(param)
    env['REQUEST_METHOD'] = 'POST'
    return True

def is_file_versions(env):
    
    method = env.get('REQUEST_METHOD')
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)
    
    if 'GET' == method and 'GETHISTORY' == param.get('op'): 
        return True
    
    return False

def file_versions_env(env):

    if not env['fwuser_info'].get('lock'):
        env['fwuser_info']['comment'] = 'get file versions'
        env['fwuser_info']['lock'] = True
        
    path = env.get('PATH_INFO')
    vers,account, container,obj = split_path(path,1, 4,True)
    env['PATH_INFO'] = env['RAW_PATH_INFO'] = '/'.join(['',vers,account,container+'_versions'])
    
    qs = env.get('QUERY_STRING','') 
    param = qsparam(qs)    
    param.pop('op')
    param['prefix'] = obj+'/'
    env['QUERY_STRING'] = newparamqs(param)
    
    return True