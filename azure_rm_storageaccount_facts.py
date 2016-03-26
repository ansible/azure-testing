#!/usr/bin/python
#
# (c) 2016 Matt Davis, <mdavis@redhat.com>
#          Chris Houseknecht, <house@redhat.com>
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
except:
    HAS_AZURE = False


DOCUMENTATION = '''
---
module: azure_rm_storageaccount

short_description: Create, read, update and delete Azure storage accounts.

description:
    - Get facts for a specific storage account including keys.

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
    name:
        description:
            - Only show results for a specific account.
        default: null
    resource_group:
        description:
            - name of resource group.
        required: true
        default: null

requirements:
    - "python >= 2.7"
    - "azure >= 2.0.0"

authors:
    - "Chris Houseknecht house@redhat.com"
    - "Matt Davis mdavis@redhat.com"
'''

EXAMPLES = '''
    - name: Get facts for one account
      azure_rm_storageaccount_facts:
        resource_group: Testing
        name: clh0002

    - name: Get facts for all accounts
      azure_rm_storageaccount_facts:
        resource_group: Testing

'''

RETURNS = '''
{
    "changed": true,
    "check_mode": false,
    "results": [
        {
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
    ]
}
'''

NAME_PATTERN = re.compile(r"^[a-z0-9]+$")


class AzureRMStorageAccountFacts(AzureRMModuleBase):
    def __init__(self, **kwargs):

        if not HAS_AZURE:
            raise Exception("The Azure python sdk is not installed. Try 'pip install azure'")

        self.module_arg_spec = dict(
            name=dict(type='str'),
            resource_group=dict(required=True, type='str'),
        )

        super(AzureRMStorageAccountFacts, self).__init__(self.module_arg_spec,
                                                    supports_check_mode=True,
                                                    **kwargs)
        self.results = dict(
            changed=False,
            check_mode=self.check_mode,
            results=[]
        )

        self.name = None
        self.resource_group = None

    def exec_module_impl(self, **kwargs):

        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if self.name is not None:
            self.results['results'].append(self.get_account())
        else:
            self.results['results'] = self.list_accounts()

        return self.results

    def get_account(self):
        self.log('Get properties for account {0}'.format(self.name))
        account_obj = None
        account_dict = dict()

        try:
            account_obj = self.storage_client.storage_accounts.get_properties(self.resource_group, self.name)
        except CloudError:
            pass

        if account_obj is not None:
            account_dict = self.account_obj_to_dict(account_obj)

        return account_dict

    def list_accounts(self):
        self.log('List storage accounts for resource group {0}'.format(self.resource_group))
        try:
            response = self.storage_client.storage_accounts.list_by_resource_group(self.resource_group)
        except AzureHttpError as e:
            self.log('Error listing storage accounts for resource group %s' % resource_group)
            self.fail("Failed to list storage accounts for resource group: {0}".format(str(e)))

        results = []
        for item in response:
            results.append(self.account_obj_to_dict(item))

        return results

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

        try:
            # Get keys from the storage account
            account_dict['keys'] = dict()
            account_keys = self.storage_client.storage_accounts.list_keys(self.resource_group, account_obj.name)
            account_dict['keys']['key1'] = account_keys.key1
            account_dict['keys']['key2'] = account_keys.key2
        except AzureHttpError, e:
            self.log("Error getting keys for account {0}".format(e))
            self.fail("account_obj_to_dict:Failed to get account keys: {0}".format(e))

        return account_dict


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

    AzureRMStorageAccountFacts().exec_module()

if __name__ == '__main__':
    main()
