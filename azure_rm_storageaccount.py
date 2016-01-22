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
module: azure_rm_storageaccount
short_description: Create, read, update and delete Azure storage accounts.
description:
    - Use to create and manage storage accounts within a given resource group. Use gather_facts option to get all the attributes, 
      including endpoints and keys for a particular storage account, or use the gather_list option to gather facts for all storage 
      accounts within a resource group.
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
    resource_group:
        description:
            - name of resource group.
        required: true
        default: null
    name:
        description:
            - name of the storage account.
        required: true
        default: null
    state:
        description:
            - can be one of 'absent' or 'present'. When set to present the storage group will be created or updated. 
              When set to absent the storage group will be deleted.
        required: false
        default: present
    location:
        description:
            - name of the Azure location where the storage account will reside on creation. Required when the storage account
              is created. Cannot be changed after storage account creation.
        required: false
        default: null
    account_type:
        desscription:
            - type of storage account. Can be one of 'Premium_LRS', 'Standard_GRS', 'Standard_LRS', 'Standard_RAGRS',
              'Standard_ZRS'. Required when creating a storage account. Note that StandardZRS and PremiumLRS accounts cannot be
              changed to other account types, and other account types cannot be changed to StandardZRS or PremiumLRS.
        required: false
        default: null
    custom_domain:
        description:
            - User domain assigned to the storage account. Must be a dictionary with 'name' and 'use_sub_domain' keys where 'name' 
              is the CNAME source. Only one custom domain is supported per storage account at this time. To clear the existing custom 
              domain, use an empty string for the custom domain name property.
            - Can be added to an existing storage account. Will be ignored during storage account creation.
        required: false
        default: null
    tags:
        description:
            - dictionary of key, value pairs to be assigned to the storage account. Can be included during both create and update
              operations.
        required: false
        default: null
    gather_facts:
        description:
            - Set to True to get all attributes including endpoints and keys for a given storage account. Expects resource_group
              and name to be present.
        required: false
        default: false
    gather_list:
        description:
            - Set to True to get all attributes for all storage accounts within a given resource group. Expects resource_group to be
              present.
        required: false
        default: false
    requirements:
        - "python >= 2.7"
        - "azure >= 1.0.2"
    author: "Chris Houseknecht @chouseknecht"
'''


HAS_AZURE = True
HAS_REQUESTS = True
LOG_PATH = "azure_rm_storageaccount.log"
NAME_PATTERN = re.compile(r"^[a-z0-9]+$")

try:
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

def list_storage_accounts(resource_group, storage_client, log):
    '''
    List storage accounts for a given resource group.
    '''
    results = dict(
        changed=False,
        storage_accounts=[]
    )
    log('Getting list of storage accounts for resource group %s' % resource_group)
    try:
        response = storage_client.storage_accounts.list_by_resource_group(resource_group)
        for storage_account in response.storage_accounts:
            s = {}
            s['id'] = storage_account.id
            s['name'] = storage_account.name
            s['location'] = storage_account.location
            s['resource_group'] = resource_group
            s['type'] = storage_account.type
            s['account_type'] = storage_account.account_type
            s['provisioning_state'] = storage_account.provisioning_state
            
            s['custom_domain'] = None
            if storage_account.custom_domain:
                s['custom_domain'] = {
                    'name': storage_account.custom_domain.name,
                    'use_sub_domain': storage_account.custom_domain.use_sub_domain
                }
            
            s['primary_location'] = storage_account.primary_location
            
            s['primary_endpoints'] = None
            if storage_account.primary_endpoints:
                s['primary_endpoints'] = {
                    'blob': storage_account.primary_endpoints.blob,
                    'queue': storage_account.primary_endpoints.queue,
                    'table': storage_account.primary_endpoints.table
                }

            s['secondary_endpoints'] = None
            if storage_account.secondary_endpoints:
                s['secondary_endpoints'] = {
                    'blob': storage_account.secondary_endpoints.blob,
                    'queue': storage_account.secondary_endpoints.queue,
                    'table': storage_account.secondary_endpoints.table
                }
        
            s['secondary_location'] = storage_account.secondary_location
            s['status_of_primary'] = storage_account.status_of_primary
            s['status_of_secondary'] = storage_account.status_of_secondary
        
            s['tags'] = {}
            if storage_account.tags:
                s['tags'] = storage_account.tags

            s['keys'] = {}
            keys = storage_client.storage_accounts.list_keys(resource_group, storage_account.name)
            s['keys'][KeyName.key1] = keys.storage_account_keys.key1
            s['keys'][KeyName.key2] = keys.storage_account_keys.key2

            results['storage_accounts'].append(s)

    except AzureHttpError as e:
        log('Error listing storage accounts for resource group %s' % resource_group)
        raise Exception(str(e.message))

    return results

def check_account_type(type):
    valid_types = (
        AccountType.premium_lrs,
        AccountType.standard_grs,
        AccountType.standard_lrs,
        AccountType.standard_ragrs,
        AccountType.standard_zrs
    )
    if type in valid_types:
       return True
    raise Exception("Invalid account_type. Must be one of: %s, %s, %s, %s, %s" % valid_types)

def module_impl(rm, log, params, check_mode=False):

    if not HAS_AZURE:
        raise Exception("The Azure python sdk is not installed (try 'pip install azure')")

    if not HAS_REQUESTS:
        raise Exception("The requests python module is not installed (try 'pip install requests')")

    resource_group = params.get('resource_group')
    account_name = params.get('name')
    location = params.get('location')
    state = params.get('state')
    gather_facts = params.get('gather_facts')
    gather_list = params.get('gather_list')
    account_type = params.get('account_type')
    custom_domain = params.get('custom_domain')
    tags = params.get('tags')
    
    results = dict(changed=False)

    storage_client = rm.storage_client
    
    if not resource_group:
        raise Exception("Parameter error: resource_group cannot be None.")
    
    if gather_list:
        # gather facts for all storage accounts in a given resource group and get out
        return list_storage_accounts(resource_group, storage_client, log)

    if not account_name:
        raise Exception("Parameter error: name cannot be None.")

    if not NAME_PATTERN.match(account_name):
        raise Exception("Parameter error: name must contain numbers and lowercase letters only.")

    if len(account_name) < 3 or len(account_name) > 24:
        raise Exception("Parameter error: name length must be between 3 and 24 characters.")

    if account_type:
        check_account_type(account_type)

    if custom_domain:
        log("custom_domain: %s" % str(custom_domain))
        if not isinstance(custom_domain, dict):
            raise Exception("Parameter Error: expecting custom_domain to be type of dictionary.")
        if custom_domain.get('name', None) is None:
            raise Exception("Parameter error: expecting custom_domain to have a name attribute of type string.")
        if custom_domain.get('use_sub_domain', None) is None:
            raise Exception("Parameter error: expecting custom_domain to have a use_sub_domain attribute of type boolean.")
    
    results['name'] = account_name
    results['resource_group'] = resource_group 

    try:
        if state == 'present' or gather_facts:
            log('Get properties for account %s' % account_name)
            response = storage_client.storage_accounts.get_properties(resource_group, account_name)
            results['id'] = response.storage_account.id
            results['name'] = response.storage_account.name
            results['location'] = response.storage_account.location
            results['resource_group'] = resource_group
            results['type'] = response.storage_account.type
            results['account_type'] = response.storage_account.account_type
            results['provisioning_state'] = response.storage_account.provisioning_state
            
            results['custom_domain'] = None
            if response.storage_account.custom_domain:
                results['custom_domain'] = {
                    'name': response.storage_account.custom_domain.name,
                    'use_sub_domain': response.storage_account.custom_domain.use_sub_domain
                }
            
            results['primary_location'] = response.storage_account.primary_location
            
            results['primary_endpoints'] = None
            if response.storage_account.primary_endpoints:
                results['primary_endpoints'] = {
                    'blob': response.storage_account.primary_endpoints.blob,
                    'queue': response.storage_account.primary_endpoints.queue,
                    'table': response.storage_account.primary_endpoints.table
                }

            results['secondary_endpoints'] = None
            if response.storage_account.secondary_endpoints:
                results['secondary_endpoints'] = {
                    'blob': response.storage_account.secondary_endpoints.blob,
                    'queue': response.storage_account.secondary_endpoints.queue,
                    'table': response.storage_account.secondary_endpoints.table
                }
        
            results['secondary_location'] = response.storage_account.secondary_location
            results['status_of_primary'] = response.storage_account.status_of_primary
            results['status_of_secondary'] = response.storage_account.status_of_secondary
        
            results['tags'] = {}
            if response.storage_account.tags:
                results['tags'] = response.storage_account.tags

            results['keys'] = {}
            keys = storage_client.storage_accounts.list_keys(resource_group, account_name)
            results['keys'][KeyName.key1] = keys.storage_account_keys.key1
            results['keys'][KeyName.key2] = keys.storage_account_keys.key2
        
        elif state == 'absent':
            log('State absent for account %s' % account_name)
            results['changed'] = True

    except AzureMissingResourceHttpError:
        log('Storage account %s does not exist' % account_name)
        if state == 'present':
            results['changed'] = True

    if gather_facts:
        results['changed'] = False
        results['status'] = 'Succeeded'
        log('Stopping at gathering facts.')
        return results

    if state == 'present' and not results['changed']:
        # update the storage account

        log('Update storage account %s.' % account_name)

        if account_type:
            if account_type != results['account_type']:
                if results['account_type'] in [AccountType.premium_lrs, AccountType.standard_zrs]:
                    raise Exception("Storage accounts of type %s and %s cannot be changed." % (
                        AccountType.premium_lrs,
                        AccountType.standard_zrs
                    ))
                if account_type in [AccountType.premium_lrs, AccountType.standard_zrs]:
                    raise Exception("Storage account of type %s cannot be changed to a type of %s or %s." % (
                        results['account_type'],
                        AccountType.premium_lrs,
                        AccountType.standard_zrs
                    ))
                results['changed'] = True
                results['account_type'] = account_type

                if results['changed'] and not check_mode:
                    # Perform the update. The API only allows changing one attribute per call.
                    parameters = StorageAccountUpdateParameters(account_type=results['account_type'])
                    try:
                        storage_client.storage_accounts.update(resource_group, account_name, parameters)
                    except AzureHttpError as e:
                        raise Exception(str(e.message))

        if custom_domain:
            if not results['custom_domain'] or \
               results['custom_domain']['name'] != custom_domain['name'] or \
               results['custom_domain']['use_sub_domain'] != custom_domain['use_sub_domain']:
                results['changed'] = True
                results['custom_domain'] = dict(
                    name = custom_domain['name'],
                    use_sub_domain = custom_domain['use_sub_domain']
                )
            
            if results['changed'] and not check_mode:
                new_domain = CustomDomain(name=custom_domain['name'], use_sub_domain=custom_domain['use_sub_domain'])
                parameters = StorageAccountUpdateParameters(custom_domain=new_domain)
                try:
                    storage_client.storage_accounts.update(resource_group, account_name, parameters)
                except AzureHttpError as e:
                    raise Exception(str(e.message))

        if tags:
            for tag_key in tags:
                if results['tags'].get(tag_key, None):
                    if results['tags'][tag_key] != tags[tag_key]:
                        results['changed'] = True
                        results['tags'][tag_key] = tags[tag_key]
                else:
                    results['changed'] = True
                    results['tags'][tag_key] = tags[tag_key]

            if results['changed'] and not check_mode:
                parameters = StorageAccountUpdateParameters(tags=results['tags'])
                try:
                    storage_client.storage_accounts.update(resource_group, account_name, parameters)
                except AzureHttpError as e:
                    raise Exception(str(e.message))

        return results
    
    elif state == 'present' and results['changed']:
        # create the storage account

        log('Create storage account %s.' % account_name)

        if not location:
            raise Exception('Parameter error: location cannot be None when creating a storage account.')

        if not account_type:
            raise Exception('Parameter error: account_type cannot be None when creating a storage account.')

        try:
            response = storage_client.storage_accounts.check_name_availability(account_name)
        except AzureHttpError as e:
            log('Error attempting to validate name.')
            raise Exception(str(e.message))

        if not response.name_available:
            log('Error name not available.')
            raise Exception("%s - %s" % (response.message, response.reason))

        results['location'] = location
        results['account_type'] = account_type
        results['name'] = account_name
        results['resource_group'] = resource_group
        results['tags'] = {}
        if tags:
            results['tags'] = tags

        if check_mode:
            return results

        try:
            parameters = StorageAccountCreateParameters(account_type = results['account_type'], location=results['location'], tags=results['tags'])
            response = storage_client.storage_accounts.create(resource_group, account_name, parameters)
            results['status'] = response.status
            results['status_code'] = response.status_code
            
            # The create response contains no account attributes. If we wait again, the attributes will be there.
            delay = response.retry_after
            if response.retry_after == 0:
                delay = 25
            log('Waiting %ssec before attempting GET')
            time.sleep(delay)

            log('Calling get_properties...')
            response = storage_client.storage_accounts.get_properties(resource_group, account_name)

            results['id'] = response.storage_account.id
            results['type'] = response.storage_account.type
            results['provisioning_state'] = response.storage_account.provisioning_state
            results['custom_domain'] = {}
            results['primary_location'] = response.storage_account.primary_location
            
            results['primary_endpoints'] = None
            if response.storage_account.primary_endpoints:
                results['primary_endpoints'] = {
                    'blob': response.storage_account.primary_endpoints.blob,
                    'queue': response.storage_account.primary_endpoints.queue,
                    'table': response.storage_account.primary_endpoints.table
                }

            results['secondary_endpoints'] = None
            if response.storage_account.secondary_endpoints:
                results['secondary_endpoints'] = {
                    'blob': response.storage_account.secondary_endpoints.blob,
                    'queue': response.storage_account.secondary_endpoints.queue,
                    'table': response.storage_account.secondary_endpoints.table
                }
        
            results['secondary_location'] = response.storage_account.secondary_location
            results['status_of_primary'] = response.storage_account.status_of_primary
            results['status_of_secondary'] = response.storage_account.status_of_secondary

            results['keys'] = {}
            keys = storage_client.storage_accounts.list_keys(resource_group, account_name)
            results['keys'][KeyName.key1] = keys.storage_account_keys.key1
            results['keys'][KeyName.key2] = keys.storage_account_keys.key2

        except AzureHttpError as e:
            log('Error creating storage account.')
            raise Exception(str(e.message))

    elif state == 'absent' and results['changed']:
        # delete

        log('Delete storage account %s' % account_name)
        
        if check_mode:
            return results

        try:
            response = storage_client.storage_accounts.delete(resource_group, account_name)
            results['status_code'] = response.status_code
            results['status'] = OperationStatus.Succeeded
        except  AzureHttpError as e:
            raise Exception(str(e.message))

    return results

def main():
    
    module_args = dict(
        resource_group = dict(required=True, type='str'),
        name = dict(type='str'),
        state = dict(default='present', choices=['present', 'absent']),
        location = dict(type='str'),
        tags = dict(type='dict'),
        account_type = dict(type='str'),
        custom_domain = dict(type='dict'),
        gather_facts = dict(type='bool', default=False),
        gather_list = dict(type='bool', default=False),
    )

    module = azure_module(
        argument_spec=module_args,
        supports_check_mode=True
    )

    try:
        rm = AzureRM(module)
    except Exception as e:
        module.fail_json(msg=e.args[0])

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
