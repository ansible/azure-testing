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


# normally we'd put this at the bottom to preserve line numbers, but we can't use a forward-defined base class
# without playing games with __metaclass__ or runtime base type hackery.
# TODO: figure out a better way...
from ansible.module_utils.basic import *

# Assumes running ansible from source and there is a copy or symlink for azure_rm_common
# found in local lib/ansible/module_utils
from ansible.module_utils.azure_rm_common import *

HAS_AZURE = True

try:
    from msrestazure.azure_exceptions import CloudError
    from azure.storage.cloudstorageaccount import CloudStorageAccount
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
    from azure.mgmt.storage.models import AccountType,\
                                          AccountStatus, \
                                          ProvisioningState, \
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
            - Set to True to get all attributes including endpoints for a given storage account. Expects resource_group
              and name to be present.
        required: false
        default: false
    gather_list:
        description:
            - Set to True to get all attributes for all storage accounts within a given resource group.
        required: false
        default: false

requirements:
    - "python >= 2.7"
    - "azure >= 1.0.2"

author: "Chris Houseknecht @chouseknecht"
'''
EXAMPLES = '''
    - name: remove account, if it exists
      azure_rm_storageaccount:
        resource_group: Testing
        location: 'East US 2'
        name: clh0002
        state: absent

    - name: create an account
      azure_rm_storageaccount:
        resource_group: Testing
        location: 'East US 2'
        name: clh0002
        type: Standard_RAGRS
'''

RETURNS = '''
{
    "changed": true,
    "check_mode": false,
    "results": {
        "account_type": "Standard_RAGRS",
        "custom_domain": null,
        "id": "/subscriptions/3f7e29ba-24e0-42f6-8d9c-5149a14bda37/resourceGroups/testing/providers/Microsoft.Storage/storageAccounts/clh0003",
        "location": "eastus2",
        "name": "clh0003",
        "primary_endpoints": {
            "blob": "https://clh0003.blob.core.windows.net/",
            "queue": "https://clh0003.queue.core.windows.net/",
            "table": "https://clh0003.table.core.windows.net/"
        },
        "primary_location": "eastus2",
        "provisioning_state": "Succeeded",
        "resource_group": "Testing",
        "secondary_endpoints": {
            "blob": "https://clh0003-secondary.blob.core.windows.net/",
            "queue": "https://clh0003-secondary.queue.core.windows.net/",
            "table": "https://clh0003-secondary.table.core.windows.net/"
        },
        "secondary_location": "centralus",
        "status_of_primary": "Available",
        "status_of_secondary": "Available",
        "tags": null,
        "type": "Microsoft.Storage/storageAccounts"
    }
}

# For gather_list:

{
    "changed": false,
    "check_mode": false,
    "results": [
        {
            "account_type": "Standard_RAGRS",
            "custom_domain": null,
            "id": "/subscriptions/3f7e29ba-24e0-42f6-8d9c-5149a14bda37/resourceGroups/testing/providers/Microsoft.Storage/storageAccounts/clh0001",
            "location": "eastus2",
            "name": "clh0001",
            "primary_endpoints": {
                "blob": "https://clh0001.blob.core.windows.net/",
                "queue": "https://clh0001.queue.core.windows.net/",
                "table": "https://clh0001.table.core.windows.net/"
            },
            "primary_location": "eastus2",
            "provisioning_state": "Succeeded",
            "resource_group": "Testing",
            "secondary_endpoints": {
                "blob": "https://clh0001-secondary.blob.core.windows.net/",
                "queue": "https://clh0001-secondary.queue.core.windows.net/",
                "table": "https://clh0001-secondary.table.core.windows.net/"
            },
            "secondary_location": "centralus",
            "status_of_primary": "Available",
            "status_of_secondary": "Available",
            "tags": null,
            "type": "Microsoft.Storage/storageAccounts"
        }
    ]
}
'''

NAME_PATTERN = re.compile(r"^[a-z0-9]+$")


class AzureRMStorageAccount(AzureRMModuleBase):
    def __init__(self, **kwargs):

        if not HAS_AZURE:
            raise Exception("The Azure python sdk is not installed. Try 'pip install azure'")

        self.module_arg_spec = dict(
            account_type=dict(type='str', choices=[], aliases=['type']),
            custom_domain=dict(type='dict'),
            force=dict(type='bool', default=False),
            location=dict(type='str'),
            name=dict(type='str'),
            resource_group=dict(required=True, type='str'),
            state=dict(default='present', choices=['present', 'absent']),
            tags=dict(type='dict'),

            # TODO: implement object security
        )

        for key in AccountType:
            self.module_arg_spec['account_type']['choices'].append(getattr(key, 'value'))

        super(AzureRMStorageAccount, self).__init__(self.module_arg_spec,
                                                    supports_check_mode=True,
                                                    **kwargs)
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

    def exec_module_impl(self, **kwargs):

        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if not self.name:
            self.fail("Parameter error: name cannot be None.")

        if not NAME_PATTERN.match(self.name):
            self.fail("Parameter error: name must contain numbers and lowercase letters only.")

        if len(self.name) < 3 or len(self.name) > 24:
            self.fail("Parameter error: name length must be between 3 and 24 characters.")

        if self.custom_domain:
            self.log("custom_domain: {0}".format(self.custom_domain))
            if self.custom_domain.get('name', None) is None:
                self.fail("Parameter error: expecting custom_domain to have a name attribute of type string.")
            if self.custom_domain.get('use_sub_domain', None) is None:
                self.fail("Parameter error: expecting custom_domain to have a use_sub_domain "
                          "attribute of type boolean.")

        self.account_dict = self.get_account()
        if self.account_dict is not None:
            self.results['results'] = self.account_dict
        else:
            self.results['results'] = dict()

        if self.state == 'present':
            if self.account_dict is None:
                self.results['results'] = self.create_account()
            else:
                self.update_account()
        elif self.state == 'absent':
            if self.account_dict is not None:
                self.delete_account()
                self.results['results'] = dict()

        return self.results

    def check_name_availability(self):
        try:
            response = self.storage_client.storage_accounts.check_name_availability(self.name)
        except AzureHttpError, e:
            self.log('Error attempting to validate name.')
            self.fail("Error checking name availability: {0}".format(str(e)))

        if not response.name_available:
            self.log('Error name not available.')
            self.fail("{0} - {1}".format(response.message, response.reason))

    def get_account(self):
        self.log('Get properties for account {0}'.format(self.name))
        account_obj = None
        account_dict = None

        try:
            account_obj = self.storage_client.storage_accounts.get_properties(self.resource_group, self.name)
        except CloudError:
            pass

        if account_obj is not None:
            account_dict = self.account_obj_to_dict(account_obj)

        return account_dict

    def account_obj_to_dict(self, account_obj):
        account_dict = dict(
            id=account_obj.id,
            name=account_obj.name,
            location=account_obj.location,
            resource_group=self.resource_group,
            type=account_obj.type,
            account_type=account_obj.account_type.value,
            provisioning_state=account_obj.provisioning_state.value,
            secondary_location=account_obj.secondary_location,
            status_of_primary=(account_obj.status_of_primary.value
                               if account_obj.status_of_primary is not None else None),
            status_of_secondary=(account_obj.status_of_secondary.value
                                 if account_obj.status_of_secondary is not None else None),
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

        return account_dict

    def update_account(self):
        self.log('Update storage account {0}'.format(self.name))
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
                parameters = StorageAccountUpdateParameters(tags=self.account_dict['tags'])
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
        
        if self.check_mode:
            account_dict = dict(
                location=self.location,
                account_type=self.account_type,
                name =self.name,
                resource_group=self.resource_group,
                tags=dict()
            )
            if self.tags:
                account_dict['tags'] = self.tags
            return account_dict
        else:
            self.results['changed'] = True
            try:
                parameters = StorageAccountCreateParameters(account_type=self.account_type, location=self.location,
                                                            tags=self.tags)
                poller = self.storage_client.storage_accounts.create(self.resource_group, self.name, parameters)
            except AzureHttpError, e:
                self.log('Error creating storage account.')
                self.fail("Failed to create account: {0}".format(str(e)))

            self.log('Checking poller for result:')
            while not poller.done():
                delay = 20
                self.log("Waiting for {0} sec".format(delay))
                poller.wait(timeout=delay)
            # The actual result we finally get back from poller.result() seems to be empty.
            # Make a call to the API to get actual results
            return self.get_account()

    def delete_account(self):
        if self.account_dict['provisioning_state'] != ProvisioningState.succeeded.value:
            self.fail("Account provisioning has not completed. State is: {0}".format(
                self.account_dict['provisioning_state']))

        if self.account_dict['provisioning_state'] == ProvisioningState.succeeded.value and \
           self.account_has_blob_containers() and not self.force:
            self.fail("Account contains blob containers. Is it in use? Use the force option to attempt deletion.")

        self.log('Delete storage account {0}'.format(self.name))
        self.results['changed'] = True
        if not self.check_mode:
            try:
                self.storage_client.storage_accounts.delete(self.resource_group, self.name)
            except AzureHttpError, e:
                self.fail("Failed to delete the account: {0}".format(str(e)))

    def account_has_blob_containers(self):
        '''
        If there are blob containers, then there are likely VMs depending on this account and it should
        not be deleted.
        '''
        self.log('Checking for existing blob containers')
        keys = dict()
        try:
            # Get keys from the storage account
            account_keys = self.storage_client.storage_accounts.list_keys(self.resource_group, self.name)
            keys['key1'] = account_keys.key1
            keys['key2'] = account_keys.key2
        except AzureHttpError, e:
            self.log("Error getting keys for account {0}".format(e))
            self.fail("check_for_container:Failed to get account keys: {0}".format(e))

        try:
            cloud_storage = CloudStorageAccount(self.name, keys['key1']).create_page_blob_service()
        except Exception, e:
            self.log("Error creating blob service: {0}".format(e))
            self.fail("check_for_container:Error creating blob service: {0}".format(e))

        try:
            response = cloud_storage.list_containers()
        except AzureMissingResourceHttpError:
            # No blob storage available?
            return False

        if len(response.items) > 0:
            return True
        return False


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
