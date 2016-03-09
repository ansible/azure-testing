#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2016 Chris Houseknecht, <chouseknecht@ansible.com>
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
import sys


# normally we'd put this at the bottom to preserve line numbers, but we can't use a forward-defined base class
# without playing games with __metaclass__ or runtime base type hackery.
# TODO: figure out a better way...
from ansible.module_utils.basic import *

# Assumes running ansible from source and there is a copy or symlink for azure_rm_common
# found in local lib/ansible/module_utils
from ansible.module_utils.azure_rm_common import *

HAS_AZURE = True

try:
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
    from azure.mgmt.storage.models import AccountType,\
                                          StorageAccountUpdateParameters,\
                                          CustomDomain, StorageAccountCreateParameters, KeyName
except:
    HAS_AZURE = False



DOCUMENTATION = '''
---
module: azure_rm_storageaccount

short_description: Create, read, update and delete Azure storage accounts.

description:
    - Create and manage storage accounts within a given resource group. Use gather_facts option to get all the attributes,
      including endpoints and keys for a particular storage account, or use the gather_list option to gather facts for
      all storage accounts within a resource group.
    - For authentication pass subscription_id, client_id, secret and tenant. Or, create a ~/.azure/credentials
      file with one or more profiles. When using a credentials file, if no profile option is provided, the module will
      look for a 'default' profile. Each profile should include subscription_id, client_id, secret and tenant values.

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
    secret:
        description:
            - Azure client_secrent used for authentication.
        required: false
        default: null
    tenant:
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
        default: null
    state:
        description:
            - Assert the state of the storage account.
            - "present" will created the account, if it does not exist, or update it, if it does exist.
            - "absent" will remove the storage account.
        required: false
        default: present
        choices:
            - absent
            - present
    location:
        description:
            - name of the Azure location where the storage account will reside on creation. Required when the storage account
              is created. Cannot be changed after storage account creation.
        required: false
        default: null
    account_type:
        description:
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
            - Dictionary of string:string pairs to assign as tags to the storage account.
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


NAME_PATTERN = re.compile(r"^[a-z0-9]+$")


class AzureRMStorageAccount(AzureRMModuleBase):
    def __init__(self, **kwargs):

        if not HAS_AZURE:
            raise Exception("The Azure python sdk is not installed. Try 'pip install azure'")

        module_arg_spec = dict(
            resource_group=dict(required=True, type='str'),
            name=dict(type='str'),
            state=dict(default='present', choices=['present', 'absent']),
            location=dict(type='str'),
            tags=dict(type='dict'),
            account_type=dict(type='str', choices=[], aliases=['type']),
            custom_domain=dict(type='dict'),
            gather_facts=dict(type='bool', default=False),
            gather_list=dict(type='bool', default=False),

            # TODO: implement object security
        )

        for attr, value in AccountType.__dict__.iteritems():
            if not re.match('_', attr):
                module_arg_spec['account_type']['choices'].append(getattr(AccountType, attr, None))

        self.results = dict(
            changed=False,
            check_mode=self.check_mode
        )

        self.account_dict = None
        self.resource_group = None
        self.name = None
        self.state = None
        self.location = None
        self.account_type = None
        self.custom_domain = None
        self.gather_facts = None
        self.gather_list = None

    def exec_module_impl(self, **kwargs):

        for key, value in kwargs.iteritems():
            setattr(self, key, value)

        if self.gather_list:
            # gather facts for all storage accounts in a given resource group and get out
            self.list_accounts()
            return self.results

        if not name:
            raise Exception("Parameter error: name cannot be None.")

        if not NAME_PATTERN.match(name):
            raise Exception("Parameter error: name must contain numbers and lowercase letters only.")

        if len(name) < 3 or len(name) > 24:
            raise Exception("Parameter error: name length must be between 3 and 24 characters.")

        if self.custom_domain:
            self.log("custom_domain: {0}".format(self.custom_domain))
            if self.custom_domain.get('name', None) is None:
                self.fail("Parameter error: expecting custom_domain to have a name attribute of type string.")
            if self.custom_domain.get('use_sub_domain', None) is None:
                self.fail("Parameter error: expecting custom_domain to have a use_sub_domain "
                          "attribute of type boolean.")

        self.account_dict = self.get_account()
        self.results['results'] = self.account_dict

        if self.gather_facts:
            self.results['changed'] = False
            return self.results

        if self.state == 'present':
            if self.account_dict is None:
                self.create_account()
            self.update_account()
        elif self.state == 'absent':
            self.delete_account()

        return self.results

    def check_name_availability(self):
        try:
            response = self.storage_client.storage_accounts.check_name_availability(self.name)
        except AzureHttpError, e:
            self.log('Error attempting to validate name.')
            self.fail("Error checking name availability: {0}".format(str(e.)))

        if not response.name_available:
            self.debug('Error name not available.')
            self.fail("{0} - {1}".format(response.message, response.reason))


    def get_account(self):
        account_obj = None
        account_dict = None

        try:
            self.log('Get properties for account {0}'.format(self.name))
            account_obj = self.storage_client.storage_accounts.get_properties(self.resource_group, self.name)
        except AzureMissingResourceHttpError:
            pass

        if account_obj is not None:
            account_dict = dict(
                id=account_obj.id,
                name=account_obj.name,
                location=account_obj.location,
                resource_group=self.resource_group,
                type=account_obj.type,
                account_type=account_obj.account_type,
                provisioning_state=account_obj.provisioning_state,
                secondary_location=account_obj.secondary_location,
                status_of_primary=account_obj.status_of_primary,
                status_of_secondary=account_obj.status_of_secondary,
                primary_location=account_obj.primary_location
            )
            account_dict['custom_domain'] = None
            if account_obj.custom_domain:
                account_dict['custom_domain'] = dict(
                    name=account_obj.custom_domain.name,
                    use_sub_domain=account_obj.custom_domain.use_sub_domain
                )
            account_dict['primary_endpoints'] = None
            if account_obj.primary_endpoints:
                account_dict['primary_endpoints'] = dict(
                    blob=account_obj.primary_endpoints.blob,
                    queue=account_obj.primary_endpoints.queue,
                    table=account_obj.primary_endpoints.table
                )

            account_dict['secondary_endpoints'] = None
            if account_obj.secondary_endpoints:
                account_dict['secondary_endpoints'] = dict(
                    blob=account_obj.secondary_endpoints.blob,
                    queue=account_obj.secondary_endpoints.queue,
                    table=account_obj.secondary_endpoints.table
                )

            account_dict['tags'] = None
            if account_obj.tags:
                account_dict['tags'] = account_obj.tags

            # account_dict['keys'] = {}
            # keys = self.storage_client.storage_accounts.list_keys(self.resource_group, self.name)
            # account_dict['keys'][KeyName.key1] = keys.key1
            # account_dict['keys'][KeyName.key2] = keys.key2

        return account_dict

    def update_account(self):
        self.debug('Update storage account {0}'.format(self.name))
        if self.account_type:
            if self.account_type != self.account_dict['account_type']:
                # change the account type
                if self.account_dict['account_type'] in [AccountType.premium_lrs, AccountType.standard_zrs]:
                    self.fail("Storage accounts of type {0} and {1} cannot be changed.".format(
                        AccountType.premium_lrs, AccountType.standard_zrs))
                if self.account_type in [AccountType.premium_lrs, AccountType.standard_zrs]:
                    self.fail("Storage account of type {0} cannot be changed to a type of {1} or {2}.".format(
                        self.account_dict['account_type'], AccountType.premium_lrs, AccountType.standard_zrs))
                self.results['changed'] = True
                self.account_dict['account_type'] = self.account_type

                if self.results['changed'] and not self.check_mode:
                    # Perform the update. The API only allows changing one attribute per call.
                    try:
                        parameters = StorageAccountUpdateParameters(account_type=self.account_dict['account_type'])
                        self.storage_client.storage_accounts.update(self.resource_group,
                                                                    self.name,
                                                                    parameters)
                    except AzureHttpError, e:
                        self.fail("Failed to update account_type: {0}".format(str(e)))

        if self.custom_domain:
            if not self.account_dict['custom_domain'] or \
               self.account_dict['custom_domain'] != self.account_dict['custom_domain']:
                self.results['changed'] = True
                self.account_dict['custom_domain'] = self.custom_domain

            if self.results['changed'] and not self.check_mode:
                new_domain = CustomDomain(name=self.custom_domain['name'],
                                          use_sub_domain=self.custom_domain['use_sub_domain'])
                parameters = StorageAccountUpdateParameters(custom_domain=new_domain)
                try:
                    self.storage_client.storage_accounts.update(self.resource_group, self.name, parameters)
                except AzureHttpError, e:
                    self.fail("Failed to update custom domain: {0}".format(str(e)))

        if self.tags:
            if self.account_dict['tags'] != self.tags:
                self.results['changed'] = True
                self.account_dict['tags'] = self.tags

            if self.results['changed'] and not self.check_mode:
                parameters = StorageAccountUpdateParameters(tags=self.account_dict'tags'])
                try:
                    self.storage_client.storage_accounts.update(self.resource_group, self.name, parameters)
                except AzureHttpError, e:
                     self.fail("Failed to update tags: {0}".format(str(e)))

    def create_account(self):
        self.log("Creating account {0}".format(self.name))

        if not self.location:
            self.fail('Parameter error: location required when creating a storage account.')

        if not self.account_type:
            self.fail('Parameter error: account_type required when creating a storage account.')

        self.check_name_availability()
        
        self.account_dict = dict(
            location=self.location,
            account_type=self.account_type,
            name =self.name,
            resource_group=self.resource_group,
        )
        self.account_dict['tags'] = {}

        if self.tags:
            self.account_dict['tags'] = self.tags

        if not self.check_mode:
            self.results['changed'] = True
            try:
                parameters = StorageAccountCreateParameters(account_type=self.account_type, location=self.location, tags=self.tags)
                response = self.storage_client.storage_accounts.create(self.resource_group, self.name, parameters)
                delay = 20
                while not response.done():
                    # The create response contains no account attributes. If we wait again, the attributes will be there.
                    self.debug("Waiting {0}sec before attempting GET".format(delay))
                    time.sleep(delay)
                response = response.result()
            except AzureHttpError as e:
                self.log('Error creating storage account.')
                self.fail("Failed to create account: {0}".format(str(e)))

            if response is not None:
                self.account_dict = dict(
                    id=response.id,
                    type=response.type,
                    provisioning_state=response.provisioning_state,
                    custom_domain=dict(),
                    primary_location=response.primary_location,
                    secondary_location=response.secondary_location,
                    status_of_primary=response.status_of_primary,
                    status_of_secondary=response.status_of_secondary
                )

                self.account_dict['primary_endpoints'] = None
                if response.primary_endpoints:
                    self.account_dict['primary_endpoints'] = {
                        'blob': response.primary_endpoints.blob,
                        'queue': response.primary_endpoints.queue,
                        'table': response.primary_endpoints.table
                    }

                self.account_dict['secondary_endpoints'] = None
                if response.secondary_endpoints:
                    self.account_dict['secondary_endpoints'] = {
                        'blob': response.secondary_endpoints.blob,
                        'queue': response.secondary_endpoints.queue,
                        'table': response.secondary_endpoints.table
                    }

                # results['keys'] = {}
                # keys = self.storage_client.storage_accounts.list_keys(self.resource_group, self.name)
                # results['keys'][KeyName.key1] = keys.key1
                # results['keys'][KeyName.key2] = keys.key2

    def delete_account(self):

        ## TODO -- check if the account has containers. Don't delete without a force option

        self.log('Delete storage account {0}'.format(self.name))
        self.results['changed'] = True
        if not self.check_mode:
            try:
                self.storage_client.storage_accounts.delete(self.resource_group, self.name)
            except  AzureHttpError, e:
                self.fail("Failed to delete the account: {0}".format(str(e)))


    def list_accounts(self):
        self.debug('List storage accounts for resource group {0}'.format(self.resource_group))
        try:
            response = self.storage_client.storage_accounts.list_by_resource_group(self.resource_group)
        except AzureHttpError as e:
            self.log('Error listing storage accounts for resource group %s' % resource_group)
            self.fail("Failed to list storage accounts for resource group: {0}".format(str(e)))

        self.log(str(response))

        # if response:
        # for storage_account in response.storage_accounts:
        #     s = {}
        #     s['id'] = storage_account.id
        #     s['name'] = storage_account.name
        #     s['location'] = storage_account.location
        #     s['resource_group'] = resource_group
        #     s['type'] = storage_account.type
        #     s['account_type'] = storage_account.account_type
        #     s['provisioning_state'] = storage_account.provisioning_state
        #
        #     s['custom_domain'] = None
        #     if storage_account.custom_domain:
        #         s['custom_domain'] = {
        #             'name': storage_account.custom_domain.name,
        #             'use_sub_domain': storage_account.custom_domain.use_sub_domain
        #         }
        #
        #     s['primary_location'] = storage_account.primary_location
        #
        #     s['primary_endpoints'] = None
        #     if storage_account.primary_endpoints:
        #         s['primary_endpoints'] = {
        #             'blob': storage_account.primary_endpoints.blob,
        #             'queue': storage_account.primary_endpoints.queue,
        #             'table': storage_account.primary_endpoints.table
        #         }
        #
        #     s['secondary_endpoints'] = None
        #     if storage_account.secondary_endpoints:
        #         s['secondary_endpoints'] = {
        #             'blob': storage_account.secondary_endpoints.blob,
        #             'queue': storage_account.secondary_endpoints.queue,
        #             'table': storage_account.secondary_endpoints.table
        #         }
        #
        #     s['secondary_location'] = storage_account.secondary_location
        #     s['status_of_primary'] = storage_account.status_of_primary
        #     s['status_of_secondary'] = storage_account.status_of_secondary
        #
        #     s['tags'] = {}
        #     if storage_account.tags:
        #         s['tags'] = storage_account.tags
        #
        #     s['keys'] = {}
        #     keys = storage_client.storage_accounts.list_keys(resource_group, storage_account.name)
        #     s['keys'][KeyName.key1] = keys.storage_account_keys.key1
        #     s['keys'][KeyName.key2] = keys.storage_account_keys.key2
        #
        #     results['storage_accounts'].append(s)

def main():
    if '--interactive' in sys.argv:
        # import the module here so we can reset the default complex args value
        import ansible.module_utils.basic

        ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
            name='mdavis12341',
            resource_group="rm_demo",
            state='absent',
            location='West US',
            account_type="Premium_LRS",

            log_mode='stderr',
            #filter_logger=False,
        ))

    AzureRMStorageAccount().exec_module()

if __name__ == '__main__':
    main()
