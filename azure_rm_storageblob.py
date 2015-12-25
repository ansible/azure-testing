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
import hashlib
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

def path_check(path):
    if os.path.exists(path):
        return True
    else:
        return False

def get_container_facts(bs, container_name):
    container = None
    try:
        container = bs.get_container_properties(container_name)
        container['meta_data'] = bs.get_container_metadata(container_name)
    except AzureMissingResourceHttpError:
        pass
    return container

def get_blob_facts(bs, container_name, blob_name):
    blob = None
    try: 
        blob = bs.get_blob_properties(container_name, blob_name)
    except AzureMissingResourceHttpError:
        pass
    return blob

def put_block_blob(bs, container_name, blob_name, file_path, md5):
    bs.put_block_blob_from_path(
        container_name=container_name,
        blob_name=blob_name,
        file_path=file_path,
        x_ms_blob_content_md5=md5,
        max_connections=5
    )

def get_md5(file_path, block_size=2**20):
    # hash sent to azure needs to be base64 encoded
    # https://github.com/Azure/azure-storage-python/issues/11
    md5 = hashlib.md5()
    f = open(file_path, 'rb')
    while True:
        data = f.read(block_size)
        if not data:
            break
        md5.update(data)
    return md5.digest().encode('base64')[:-1] 

def module_impl(rm, log, params, md5, check_mode=False):

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
    file_path = params.get('file_path')
    over_write = params.get('over_write')

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

    # put (upload), get (download), geturl (return download url (Ansible 1.3+), getstr (download object as string (1.3+)), list (list keys (2.0+)), create (bucket), delete (bucket), and delobj (delete object)
    try:
        log('Getting keys')
        keys = {}
        response = storage_client.storage_accounts.list_keys(resource_group, account_name)
        keys[KeyName.key1] = response.storage_account_keys.key1
        keys[KeyName.key2] = response.storage_account_keys.key2
    except AzureHttpError as e:
        log('Error getting keys for account %s' % account_name)
        raise Exception(str(e.message))

    try:
        log('Create blob service')
        bs = BlobService(account_name, keys[KeyName.key1])
    except Exception as e:
        log('Error creating blob service.')
        raise Exception(str(e.args[0]))

    if mode == 'create':
        container = get_container_facts(bs, container_name)
        if container is not None:
            # container exists
            results['container'] = container
            results['msg'] = "Container already exists."
            return results
        # create the container
        if not check_mode:
            log('Create container %s' % container_name)
            bs.create_container(container_name, x_ms_meta_name_values, x_ms_blob_public_access)
            results['container'] = get_container_facts(bs, container_name)
        results['msg'] = "Container created successfully."
        results['changed'] = True
        return results

    if mode == 'update':
        container = get_container_facts(bs, container_name)
        if container is None:
            # container does not exist
            if not check_mode:
                log('Create container %s' % container_name)
                bs.create_container(container_name, x_ms_meta_name_values, x_ms_blob_public_access)
            results['changed'] = True
            results['msg'] = 'Container created successfully.'
            results['conainer'] = get_container_facts(bs, container_name)
            return results     
        # update existing container
        results['msg'] = "Container not changed."
        if x_ms_meta_name_values:
            if not check_mode:
                log('Update x_ms_meta_name_values for container %s' % container_name)
                bs.set_container_metadata(container_name, x_ms_meta_name_values)
            results['changed'] = True
            results['msg'] = 'Container updated successfully.'
        if x_ms_blob_public_access:
            access = x_ms_blob_public_access
            if x_ms_blob_public_access == 'private':
                access = None
            if not check_mode:
                log('Set access to %s for container %s' % (access, container_name))
                bs.set_container_acl(container_name=container_name, x_ms_blob_public_access=access)
            results['changed'] = True
            results['msg'] = 'Container updated successfully.'
        results['conainer'] = get_container_facts(bs, container_name)
        return results

    if mode == 'delete':
        container = get_container_facts(bs, container_name)
        if container is None:
            results['msg'] = "Container does not exist."
            return results
        if not check_mode:
            log('Deleting container %s' % container_name)
            bs.delete_container(container_name)
        results['changed'] = True
        results['msg'] = 'Container deleted successfully.'
        return results

    if mode == 'delete_blob':
        if blob_name is None:
            raise Exception("Parameter error: blob_name cannot be None.")
        
        container = get_container_facts(bs, container_name)
        if container is None:
            raise Exception("Requested container %s does not exist." % container_name)

        if not check_mode:
            log('Deleteing %s from container %s.' % (blob_name, container_name))
            bs.delete_blob(container_name, blob_name)
        
        results['changed'] = True
        results['msg'] = 'Blob successfully deleted.'
        return results

    if mode == 'put':
        if blob_name is None:
            raise Exception("Parameter error: blob_name cannot be None.")

        if file_path is None:
            raise Exception("Parameter error: file_path cannot be None.")

        if not path_check(file_path):
            raise Exception("File %s does not exist." % file_path)

        container = get_container_facts(bs, container_name)
        blob = None
        if container is not None:
            blob = get_blob_facts(bs, container_name, blob_name)

        if container is not None and blob is not None:
            # both container and blob already exist
            md5_remote = blob['content-md5']
            md5_local = get_md5(file_path)
            results['container'] = container
            results['blob'] = blob

            if md5_local == md5_remote:
                sum_matches = True
                results['msg'] = 'File checksums match. File not uploaded.'
                if over_write == 'always':
                    if not check_mode:
                        log('Uploading %s to container %s.' % (file_path, container_name))
                        put_block_blob(bs, container_name, blob_name, file_path, md5_local)
                        results['blob'] = get_blob_facts(bs, container_name, blob_name)
                    results['changed'] = True
                    results['msg'] = 'File successfully uploaded.'
            else:
                sum_matches = False
                if over_write in ('always', 'different'):
                    if not check_mode:
                        log('Uploading %s to container %s.' % (file_path, container_name))
                        put_block_blob(bs, container_name, blob_name, file_path, md5_local)
                        results['blob'] = get_blob_facts(bs, container_name, blob_name)
                    results['changed'] = True
                    results['msg'] = 'File successfully uploaded.'
                else:
                    results['msg'] = "WARNING: Checksums do not match. Use overwrite parameter to force upload."
            return results

        if container is None:
            # container does not exist. create container and upload.
            if not check_mode:
                log('Creating container %s.' % (file_path, container_name))
                bs.create_container(container_name, x_ms_meta_name_values, x_ms_blob_public_access)
                log('Uploading %s to container %s.' % (file_path, container_name))
                bs.put_block_blob_from_path(
                    container_name,
                    blob_name,
                    file_path,
                    max_connections=5
                )
                results['conainer'] = get_container_facts(bs, container_name)
                results['blob'] = get_blob_facts(bs, container_name, blob_name)
            results['changed'] = True
            results['msg'] = 'Successfully created container and uploaded file.'
            return results

        if container is not None:
            # container exists. just upload.
            if not check_mode:
                log('Uploading %s to container %s.' % (file_path, container_name))
                bs.put_block_blob_from_path(
                    container_name,
                    blob_name,
                    file_path,
                    max_connections=5
                )
                results['blob'] = get_blob_facts(bs, container_name, blob_name)
            results['changed'] = True
            results['msg'] = 'Successfully updloaded file.'
            return results

    if mode == 'list':
        container = get_container_facts(bs, container_name)
        if container is None:
            raise Exception("Requested container %s does not exist." % container_name)
        response = bs.list_blobs(
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
            over_write= dict(type='str', aliases=['force'], default='always'),
            mode = dict(type='str'),
            debug = dict(type='bool', default=False)
        ),
        supports_check_mode=True
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
        result = module_impl(rm, log.log, module.params, module.md5, check_mode)
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
