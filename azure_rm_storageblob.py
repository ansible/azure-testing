#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2015 Chris Houseknecht, <chouse@ansible.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#

import ConfigParser
import json 
import os
from os.path import expanduser
import re
import time

DOCUMENTATION = '''
---
module: azure_rm_storageblob
'''

HAS_AZURE = True
HAS_REQUESTS = True
LOG_PATH = "azure_rm_storageblob.log"
NAME_PATTERN = re.compile(r"^(?!-)(?!.*--)[a-z0-9\-]+$")

try:
    from azure.storage.blob import BlobService
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
    from azure.mgmt.storage.storagemanagement import AccountType, StorageAccountUpdateParameters, \
                                                     CustomDomain, StorageAccountCreateParameters, \
                                                     OperationStatus, KeyName
except ImportError:
    HAS_AZURE = False

try:
    import requests
except ImportError:
    HAS_REQUESTS = False


def module_impl(rm, log, params, check_mode=False):

    if not HAS_AZURE:
        raise Exception("The Azure python sdk is not installed (try 'pip install azure')")

    if not HAS_REQUESTS:
        raise Exception("The requests python module is not installed (try 'pip install requests')")

    resource_group = params.get('resource_group')
    account_name = params.get('account_name')
    container_name = params.get('container_name')
    mode = params.get('mode')
    x_ms_meta_name_values = params.get('x_ms_meta_name_values')
    x_ms_blob_public_access = params.get('x_ms_blob_public_access')
    prefix = params.get('prefix')
    marker = params.get('marker')
    max_results = params.get('max_results')
    blob_name = params.get('blob_name')
    file_path = prams.get('file_path')

    results = dict(changed=False)

    storage_client = rm.get_storage_client() 
    
    if not resource_group:
        raise Exception("Parameter error: resource_group cannot be None.")
    
    if not account_name:
        raise Exception("Parameter error: account_name cannot be None.")

    if not container_name:
        raise Exception("Parameter error: container_name cannot be None.")

    if not NAME_PATTERN.match(container_name):
        raise Exception("Parameter error: container_name must consist of lowercase letters, numbers and hyphens. It must begin with " +
            "a letter or number. It may not contain two consecutive hyphens.")

    # add file path validation

    results['account_name'] = account_name
    results['resource_group'] = resource_group 
    results['container_name'] = container_name

    try:
        keys = {}
        response = storage_client.storage_accounts.list_keys(resource_group, account_name)
        keys[KeyName.key1] = response.storage_account_keys.key1
        keys[KeyName.key2] = response.storage_account_keys.key2
    except AzureHttpError as e:
        log('Error getting keys for account %s' % account_name)
        raise Exception(str(e.message))

    try:
        if mode in ['create','update','gather_facts']:
            log('create container %s' % container_name)    
            blob_service = BlobService(account_name, keys[KeyName.key1])
            results['container'] = blob_service.get_container_properties(container_name)
            results['container']['meta_data'] = blob_service.get_container_metadata(container_name)
            # Add call to get_container_acl - if it would actually return results
        elif mode == 'delete':
            log('delete container %s' % container_name)
            results['changed'] = True
    except AzureMissingResourceHttpError:
        log('container %s does not exist' % container_name)
        if mode == 'create':
            results['changed'] = True

    if mode == 'gather_facts':
         results['changed'] = False
         log('Stopping at gathering facts.')
         return results

    if mode == 'update' or (mode == 'create' and not results['changed']):
        # update the container
        log('update container %s' % container_name)
        if x_ms_meta_name_values:
            log('set meta_name_values')
            blob_service.set_container_metadata(container_name, x_ms_meta_name_values)

        if x_ms_blob_public_access:
            access = x_ms_blob_public_access
            if x_ms_blob_public_access == 'private':
                access = None
            log('set access to %s' % access)
            blob_service.set_container_acl(container_name=container_name, x_ms_blob_public_access=access)

        results['container']['meta_data'] = blob_service.get_container_metadata(container_name)
        # Add call to get_container_acl - if it would actually return results

    elif mode == 'create' and results['changed']:
        # create the container
        log('create container %s' % container_name)
        blob_service.create_container(container_name, x_ms_meta_name_values, x_ms_blob_public_access)
        results['container'] = blob_service.get_container_properties(container_name)
        results['container']['meta_data'] = blob_service.get_container_metadata(container_name)
        # Add call to get_container_acl - if it would actually return results

    elif mode == 'delete' and results['changed']:
        blob_service.delete_container(container_name)

    elif mode == 'list':
        response = blob_service.list_blobs(
            container_name,
            prefix,
            marker,
            maxresults
        )
        results['blobs'] = []
        for blob in response.blobs:
            b = dict(
                name = blob.name,
                snapshot = blob.snapshot,
                url = blob.url,
                last_modified = blob.properties.last_modified,
                content_length = blob.properties.content_length,
                blob_type = blob.properties.blob_type,
            )
            results['blobs'].append(b)

    elif mode == 'put':
        blob_service.put_block_blob_from_path(
            container_name,
            blob_name,
            file_path,
            max_connections=5
        )

    return results

def main():
    module = AnsibleModule(
        argument_spec=dict(
            profile = dict(type='str'),
            subscription_id = dict(type='str'),
            client_id = dict(type='str'),
            client_secret = dict(type='str'),
            tenant_id = dict(type='str'),
            resource_group = dict(required=True, type='str'),
            account_name = dict(required=True, type='str'),
            container_name = dict(required=True, type='str'),
            x_ms_meta_name_values = dict(type='dict'),
            x_ms_blob_public_access = dict(type='str', choices=['blob','container','private']),
            prefix = dict(type='str'),
            marker = dict(type='str'),
            max_results = dict(type='int'),
            blob_name = dict(type='str'),
            file_path = dict(type='str'),
            mode = dict(type='str'),
            debug = dict(type='bool', default=False)
        ),
        supports_check_mode=False
    )

    check_mode = module.check_mode
    debug = module.params.get('debug')

    if debug:
        log = azure_rm_log(LOG_PATH)
    else:
        log = azure_rm_log()
    
    try:
        rm = azure_rm_resources(module.params, log.log)
    except Exception as e:
        module.fail_json(msg=e.args[0])

    try:
        result = module_impl(rm, log.log, module.params, check_mode)
    except Exception as e:
        module.fail_json(msg=e.args[0])

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *

# Assumes running ansible from source and there is a copy or symlink for azure_rm_common
# found in local lib/ansible/module_utils
from ansible.module_utils.azure_rm_common import *

if __name__ == '__main__':
    main()
