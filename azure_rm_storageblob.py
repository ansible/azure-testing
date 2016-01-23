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
import datetime
import hashlib
import json 
import os
from os.path import expanduser
import re
import time

DOCUMENTATION = '''
---
module: azure_rm_storageblob

short_description: Create, read, update and delete Azure storage accounts.
description:
    - Create and manage blob containers within a given storage account, upload and download objects to the blob container, and control
      access to the objects.
    - For authentication with Azure pass subscription_id, client_id, client_secret and tenant_id. Or, create a ~/.azure/credentials 
      file with one or more profiles. When using a credentials file, if no profile option is provided, Azure modules look for a 
      'default' profile. Each profile should include subscription_id, client_id, client_secret and tenant_id values.
options:
    profile:
        description:
            - security profile found in ~/.azure/credentials file
        required: false
        default: null
    subscription_id:
        description:
            - Azure subscription Id that owns the resource group and storage accounts.
        required: false
        default: null
    client_id:
        description:
            - Azure client_id used for authentication.
        required: false
        default: null
    client_secret:
        description:
            - Azure client_secrent used for authentication.
        required: false
        default: null
    tenant_id:
        description:
            - Azure tenant_id used for authentication.
        required: false
        default: null
    account_name:
        description:
            - name of the storage account.
        required: true
        default: null
    access_token:
        description:
            - use mode 'get_token' to generate an access_token value. Pass the token as parameter 'access_token' along with mode 'get_url', permissions, hours and days to create a secure, temporary url for accessing a blob object.
        required: false
        default: null
    blob_name:
        description:
            - name of the blob object when using modes get, put, delete_blob and get_url.
        required: false
        default: null
    container_name:
        description:
            - name of a blob container within the storage account.
        required: true
        default: null
    days:
        description:
            - integer number of days. Use when creating a secured url with mode 'get_url' or with mode 'update' to add an ACL to a container.
        rquired: false
        default: null
    debug:
        description:
            - turn on debugging for the module. Will create a log file in the current working directory.
    file_path:
        description:
            - path to a file when uploading (mode 'put') or downloading (mode 'get') a blob object.
        required: false
        default: null
    hours:
        description:
            - integer number of hours. Use when creating a secured url with mode 'get_url' or with mode 'update' to add an ACL to a container.
        required: false
        default: null
    marker:
        description:
            - use with mode 'list' to identify the portion of the list to be returned with the next list operation. The operation returns a 
              marker value within the response body if the list returned was not complete. The marker value may then be used in a subsequent 
              call to request the next set of list items.
        required: false
        default: null
    max_results:
        description:
            - use with mode 'list' to limit the number of blob objects returned.
        required: false
        default: null
    mode:
        description:
            - determines the operation or function to be performed. For container operations use: create, update, delete. For blob object 
              operations use: get, put, list, get_url, get_token.
        required: true
        default: null
    overwrite:
        description:
            - when uploading or downloading a blob object determines if matching objects will be overwritten. Set to: always, different, never.
        required: false
        default: 'always'
    permissions:
        description:
            - use with modes 'get_token' and 'update'. Will be a string containing a combination of the letters r, w, d representing 
              read, write and delete.
        required: false
        default: null
    prefix:
        description:
            - use with mode 'list' to filter results, returning only blobs whose names begin with the specified prefix.
        required: false
        default: null
    resource_group:
        description:
            - name of resource group.
        required: true
        default: null
    x_ms_meta_name_values:
        description:
            - use with mode 'update' or 'put' to add metadata to a container or object. A dict containing name, value as metadata.
        required: false
        default: null
    x_ms_blob_public_access:
        description:
            - use with mode 'update' to set a container's public access level. Set to one of: container, blob, private.
        required: false
        default: null
    x_ms_blob_cache_control:
        description:
            - use with mode 'put' to set the blob object's cache control option. Returned with read requests.
        required: false
        default: null
    x_ms_blob_content_encoding:
        description:
            - use with mode 'put' to set the blob object's content encoding. Returned with read requests.
        required: false
        default: null
    x_ms_blob_content_language:
        description:
            - use with mode 'put' to set the blob object's content language. Returned with read requests.
        required: false
        default: null
    x_ms_blob_content_type:
        description:
            - use with mode 'put' to set the blob object's content type. Returned with read requests.

requirements:
    - "python >= 2.7"
    - "azure >= 1.0.2"
author: "Chris Houseknecht @chouseknecht"
'''

EXAMPLES = '''
# Simple PUT operation
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: mycontainer
    blob_name: image.png
    file_path: /my/images/image.png
    mode: put

# Simple GET operation
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: mycontainer
    blob_name: image.png
    file_path: /downloads/image.png
    mode: get

# PUT/upload with metadata
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: mycontainer
    blob_name: image.png
    file_path: /my/images/image.png
    x_ms_blob_content_type: image/png
    x_ms_meta_name_values:
        val1: foo
        val2: bar
    mode: put

# List blob objects in a container
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: mycontainer
    mode: list

# List blob objects with options
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: mycontainer
    prefix: /my/desired/
    marker: /my/desired/0023.txt
    max_results: 50
    mode: list

# Create an empty container
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: emptycontainer
    mode: create

# Create a container with an object
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: newcontainer
    blob_name: file1.txt
    file_path: /myfiles/file1.txt
    mode: put

# Delete a container and its contents
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: newcontainer
    mode: delete

# GET an object but don't download when file checksums match
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: newcontainer
    blob_name: file1.txt
    file_path: /myfiles/file1.txt
    mode: get
    overwrite: different

# Get an objet but don't download when file already exists
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: newcontainer
    blob_name: file1.txt
    file_path: /myfiles/file1.txt
    mode: get
    overwrite: never

# Delete an object from a container
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: newcontainer
    blob_name: file1.txt
    mode: delete_blob

'''

HAS_AZURE = True
HAS_REQUESTS = True
LOG_PATH = "azure_rm_storageblob.log"
NAME_PATTERN = re.compile(r"^(?!-)(?!.*--)[a-z0-9\-]+$")

try:
    from azure.storage import AccessPolicy, SharedAccessPolicy, SignedIdentifier, SignedIdentifiers
    from azure.storage.blob import BlobService, BlobSharedAccessPermissions
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
    from azure.mgmt.storage.storagemanagement import (
        AccountType,
        StorageAccountUpdateParameters,
        CustomDomain,
        StorageAccountCreateParameters,
        OperationStatus,
        KeyName
    )
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
        container['permissions'] = []
        acl = bs.get_container_acl(container_name)
        for identifier in acl.signed_identifiers:
            i = dict(
                id = identifier.id,
                permission = identifier.access_policy.permission,
                start = identifier.access_policy.start,
                expiry = identifier.access_policy.expiry
            )
            container['permissions'].append(i)
    except AzureMissingResourceHttpError:
        pass
    return container

def container_check(bs, container_name):
    container = get_container_facts(bs, container_name)
    if container is None:
        raise Exception("Requested container %s not found." % container_name)
    return container

def get_blob_facts(bs, container_name, blob_name):
    blob = None
    try: 
        blob = bs.get_blob_properties(container_name, blob_name)
    except AzureMissingResourceHttpError:
        pass
    return blob

def blob_check(bs, container_name, blob_name):
    blob = get_blob_facts(bs, container_name, blob_name)
    if blob is None:
        raise Exception("Requested blob %s not found in container %s." % (blob_name, container_name))
    return blob

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

def put_block_blob(bs, container_name, blob_name, file_path, x_ms_meta_name_values,
    x_ms_blob_cache_control, x_ms_blob_content_encoding, x_ms_blob_content_language, x_ms_blob_content_type):
    md5_local = get_md5(file_path)
    bs.put_block_blob_from_path(
        container_name=container_name,
        blob_name=blob_name,
        file_path=file_path,
        x_ms_blob_content_md5=md5_local,
        x_ms_meta_name_values=x_ms_meta_name_values,
        x_ms_blob_cache_control=x_ms_blob_cache_control,
        x_ms_blob_content_encoding=x_ms_blob_content_encoding,
        x_ms_blob_content_language=x_ms_blob_content_language,
        x_ms_blob_content_type=x_ms_blob_content_type,
        max_connections=5
    )

def get_shared_access_policy(permission, hours=0, days=0):
    # https://github.com/Azure/azure-storage-python/blob/master/tests/test_storage_blob.py
    date_format = "%Y-%m-%dT%H:%M:%SZ"
    start = datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
    expiry = start + datetime.timedelta(hours=hours, days=days)
    return SharedAccessPolicy(
        AccessPolicy(
            start.strftime(date_format),
            expiry.strftime(date_format),
            permission
        )
    )

def get_identifier(id, hours, days, permission):
    date_format = "%Y-%m-%dT%H:%M:%SZ"
    start = datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
    expiry = start + datetime.timedelta(hours=hours, days=days)
    si = SignedIdentifier()
    si.id = id
    si.access_policy.start = start.strftime(date_format)
    si.access_policy.expiry = expiry.strftime(date_format)
    si.access_policy.permission = permission
    return si

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
    x_ms_blob_cache_control = params.get('x_ms_blob_cache_control')
    x_ms_blob_content_encoding = params.get('x_ms_blob_content_encoding')
    x_ms_blob_content_language = params.get('x_ms_blob_content_language')
    x_ms_blob_content_type = params.get('x_ms_blob_content_type')
    prefix = params.get('prefix')
    marker = params.get('marker')
    max_results = params.get('max_results')
    blob_name = params.get('blob_name')
    file_path = params.get('file_path')
    overwrite = params.get('overwrite')
    permissions = params.get('permissions')
    hours = params.get('hours')
    days = params.get('days')
    access_token = params.get('access_token')

    results = dict(changed=False)

    storage_client = rm.storage_client
    
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
            return results     
        # update existing container
        results['msg'] = "Container not changed."
        if x_ms_meta_name_values:
            if not check_mode:
                log('Update x_ms_meta_name_values for container %s' % container_name)
                bs.set_container_metadata(container_name, x_ms_meta_name_values)
            results['changed'] = True
            results['msg'] = 'Container meta data updated successfully.'
        if x_ms_blob_public_access:
            access = x_ms_blob_public_access
            if x_ms_blob_public_access == 'private':
                access = None
            if not check_mode:
                log('Set access to %s for container %s' % (access, container_name))
                bs.set_container_acl(container_name=container_name, x_ms_blob_public_access=access)
            results['changed'] = True
            results['msg'] = 'Container ACL updated successfully.'
        if permissions:
            if hours == 0 and days == 0:
                raise Exception("Parameter error: expecting hours > 0 or days > 0")
            id = "%s-%s" % (container_name, permissions) 
            si = get_identifier(id, hours, days, permissions)
            identifiers = SignedIdentifiers()
            identifiers.signed_identifiers.append(si)
            if not check_mode:
                log('Set permissions to %s for container %s' % (permissions, container_name))
                bs.set_container_acl(container_name=container_name,signed_identifiers=identifiers)
            results['changed'] = True
            results['msg'] = 'Container ACL updated successfully.'
        results['container'] = get_container_facts(bs, container_name)
        return results

    if mode == 'delete':
        container = get_container_facts(bs, container_name)
        if container is None:
            results['msg'] = "Container %s could not be found." % container_name
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
        
        container = container_check(bs, container_name)
        blob = get_blob_facts(bs, container_name, blob_name)

        if not blob:
            results['msg'] = 'Blob %s could not be found in container %s.' % (blob_name, container_name)
            return results

        if not check_mode:
            log('Deleteing %s from container %s.' % (blob_name, container_name))
            bs.delete_blob(container_name, blob_name)
        results['changed'] = True
        results['msg'] = 'Blob successfully deleted.'
        return results

    if mode == 'put':
        if not blob_name:
            raise Exception("Parameter error: blob_name cannot be None.")

        if not file_path :
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
                if overwrite == 'always':
                    if not check_mode:
                        log('Uploading %s to container %s.' % (file_path, container_name))
                        put_block_blob(
                            bs,
                            container_name,
                            blob_name,
                            file_path,
                            x_ms_meta_name_values,
                            x_ms_blob_cache_control,
                            x_ms_blob_content_encoding,
                            x_ms_blob_content_language,
                            x_ms_blob_content_type
                        )
                        results['blob'] = get_blob_facts(bs, container_name, blob_name)
                    results['changed'] = True
                    results['msg'] = 'File successfully uploaded.'
            else:
                sum_matches = False
                if overwrite in ('always', 'different'):
                    if not check_mode:
                        log('Uploading %s to container %s.' % (file_path, container_name))
                        put_block_blob(
                            bs,
                            container_name,
                            blob_name,
                            file_path,
                            x_ms_meta_name_values,
                            x_ms_blob_cache_control,
                            x_ms_blob_content_encoding,
                            x_ms_blob_content_language,
                            x_ms_blob_content_type
                        )
                        results['blob'] = get_blob_facts(bs, container_name, blob_name)
                    results['changed'] = True
                    results['msg'] = 'File successfully uploaded.'
                else:
                    results['msg'] = "WARNING: Checksums do not match. Use overwrite parameter to force upload."
            return results

        if container is None:
            # container does not exist. create container and upload.
            if not check_mode:
                log('Creating container %s.' % container_name)
                bs.create_container(container_name, x_ms_meta_name_values, x_ms_blob_public_access)
                log('Uploading %s to container %s.' % (file_path, container_name))
                put_block_blob(
                    bs,
                    container_name,
                    blob_name,
                    file_path,
                    x_ms_meta_name_values,
                    x_ms_blob_cache_control,
                    x_ms_blob_content_encoding,
                    x_ms_blob_content_language,
                    x_ms_blob_content_type
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
                put_block_blob(
                    bs,
                    container_name,
                    blob_name,
                    file_path,
                    x_ms_meta_name_values,
                    x_ms_blob_cache_control,
                    x_ms_blob_content_encoding,
                    x_ms_blob_content_language,
                    x_ms_blob_content_type
                )
                results['blob'] = get_blob_facts(bs, container_name, blob_name)
            results['changed'] = True
            results['msg'] = 'Successfully updloaded file.'
            return results

    if mode == 'list':
        container = container_check(bs, container_name)
        response = bs.list_blobs(
            container_name,
            prefix,
            marker,
            max_results
        )
        results['blobs'] = []
        for blob in response.blobs:
            b = dict(
                name = blob.name,
                snapshot = blob.snapshot,
                last_modified = blob.properties.last_modified,
                content_length = blob.properties.content_length,
                blob_type = blob.properties.blob_type,
            )
            results['blobs'].append(b)
        return results

    if mode == 'get':
        if file_path is None:
            raise Exception("Parameter error: file_path cannot be None.")
        
        container = container_check(bs, container_name)
        blob = blob_check(bs, container_name, blob_name)
        path_exists = path_check(file_path)
        
        if not path_exists or overwrite == 'always':
            if not check_mode:
                bs.get_blob_to_path(container_name, blob_name, file_path)
            results['changed'] = True
            results['msg'] = "Blob %s successfully downloaded to %s." % (blob_name, file_path)
            return results

        if path_exists:
            md5_remote = blob['content-md5']
            md5_local = get_md5(file_path)

            if md5_local == md5_remote:
                sum_matches = True
                if overwrite == 'always':
                    if not check_mode:
                        bs.get_blob_to_path(container_name, blob_name, file_path)
                    results['changed'] = True
                    results['msg'] = "Blob %s successfully downloaded to %s." % (blob_name, file_path)
                else:
                    results['msg'] = "Local and remote object are identical, ignoring. Use overwrite parameter to force."
            else:
                sum_matches = False
                if overwrite in ('always', 'different'):
                    if not check_mode:
                        bs.get_blob_to_path(container_name, blob_name, file_path)
                    results['changed'] = True
                    results['msg'] = "Blob %s successfully downloaded to %s." % (blob_name, file_path)
                else:
                    results['msg'] ="WARNING: Checksums do not match. Use overwrite parameter to force download."
        
        if sum_matches is True and overwrite == 'never':
            results['msg'] = "Local and remote object are identical, ignoring. Use overwrite parameter to force."
        
        return results

    if mode == 'get_url':
        if not blob_name:
            raise Exception("Parameter error: blob_name cannot be None.")

        container = container_check(bs, container_name)
        blob = blob_check(bs, container_name, blob_name)

        url = bs.make_blob_url(
            container_name=container_name,
            blob_name=blob_name,
            sas_token=access_token)
        results['url'] = url
        results['msg'] = "Url: %s" % url
        return results

    if mode == 'get_token':
        if hours == 0 and days == 0:
            raise Exception("Parameter error: expecting hours > 0 or days > 0")
        container = container_check(bs, container_name)
        blob = blob_check(bs, container_name, blob_name)
        results['blob_name'] = blob_name
        sap = get_shared_access_policy(permissions, hours=hours, days=days)
        token = bs.generate_shared_access_signature(container_name, blob_name, sap)
        results['access_token'] = token
        return results

def main():
    module_args = dict(
        access_token = dict(type='str'),
        account_name = dict(required=True, type='str'),
        blob_name = dict(type='str'),
        container_name = dict(required=True, type='str'),
        days = dict(type='int', default=0),
        file_path = dict(type='str'),
        hours = dict(type='int', default=0),
        marker = dict(type='str'),
        max_results = dict(type='int'),
        mode = dict(type='str', choices=['create', 'update', 'delete', 'get', 'put', 'list', 'get_url', 'get_token', 'delete_blob']),
        overwrite = dict(type='str', aliases=['force'], default='always'),
        permissions = dict(type='str'),
        prefix = dict(type='str'),
        resource_group = dict(required=True, type='str'),
        x_ms_blob_cache_control = dict(type='str'),
        x_ms_blob_content_encoding = dict(type='str'),
        x_ms_blob_content_language = dict(type='str'),
        x_ms_blob_content_type = dict(type='str'),
        x_ms_blob_public_access = dict(type='str', choices=['blob','container','private']),
        x_ms_meta_name_values = dict(type='dict'),
    )
    
    module = azure_module(
        argument_spec=module_args,
        supports_check_mode=True
    )

    rm = AzureRM(module)

    try:
        result = module_impl(rm, module.debug, module.params, module.check_mode)
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
