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
from ansible.module_utils.azure_rm_common import *

try:
    from msrestazure.azure_exceptions import CloudError
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
except:
    # This is handled in azure_rm_common
    pass


DOCUMENTATION = '''
---
module: azure_rm_storageaccount_facts

short_description: Get storage account facts.

description:
    - Get facts for one storage account or all storage accounts within a resource group.
    - For authentication with Azure you can pass parameters, set environment variables or use a profile stored
      in ~/.azure/credentials. Authentication is possible using a service principal or Active Directory user.
    - To authenticate via service principal pass subscription_id, client_id, secret and tenant or set set environment
      variables AZURE_SUBSCRIPTION_ID, AZURE_CLIENT_ID, AZURE_SECRET and AZURE_TENANT.
    - To Authentication via Active Directory user pass ad_user and password, or set AZURE_AD_USER and
      AZURE_PASSWORD in the environment.
    - Alternatively, credentials can be stored in ~/.azure/credentials. This is an ini file containing
      a [default] section and the following keys: subscription_id, client_id, secret and tenant or
      ad_user and password. It is also possible to add additional profiles. Specify the profile
      by passing profile or setting AZURE_PROFILE in the environment.

options:
    profile:
        description:
            - Security profile found in ~/.azure/credentials file
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
            - Name of resource group from which to gather facts.
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
    "changed": false,
    "check_mode": false,
    "results": [
        {
            "id": "/subscriptions/3f7e29ba-24e0-42f6-8d9c-5149a14bda37/resourceGroups/testing/providers/Microsoft.Storage/storageAccounts/testaccount001",
            "location": "eastus2",
            "name": "testaccount001",
            "properties": {
                "accountType": "Standard_LRS",
                "creationTime": "2016-03-28T02:46:58.290113Z",
                "primaryEndpoints": {
                    "blob": "https://testaccount001.blob.core.windows.net/",
                    "file": "https://testaccount001.file.core.windows.net/",
                    "queue": "https://testaccount001.queue.core.windows.net/",
                    "table": "https://testaccount001.table.core.windows.net/"
                },
                "primaryLocation": "eastus2",
                "provisioningState": "Succeeded",
                "statusOfPrimary": "Available"
            },
            "tags": {},
            "type": "Microsoft.Storage/storageAccounts"
        },
}
'''

AZURE_OBJECT_CLASS = 'StorageAccount'


class AzureRMStorageAccountFacts(AzureRMModuleBase):
    def __init__(self, **kwargs):

        self.module_arg_spec = dict(
            name=dict(type='str'),
            resource_group=dict(required=True, type='str'),
        )

        super(AzureRMStorageAccountFacts, self).__init__(self.module_arg_spec,
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
            self.results['results'] = [self.get_account()]
        else:
            self.results['results'] = self.list_accounts()

        return self.results

    def get_account(self):
        self.log('Get properties for account {0}'.format(self.name))
        account = None
        account_dict = dict()

        try:
            account = self.storage_client.storage_accounts.get_properties(self.resource_group, self.name)
        except CloudError:
            pass

        if account is not None:
            account_dict = self.serialize_obj(account, AZURE_OBJECT_CLASS)

        return account_dict

    def list_accounts(self):
        self.log('List items')
        try:
            response = self.storage_client.storage_accounts.list_by_resource_group(self.resource_group)
        except Exception, exc:
            self.fail("Error listing items - {0}".format(str(exc)))

        results = []
        for item in response:
            results.append(self.serialize_obj(item, AZURE_OBJECT_CLASS))
        return results


def main():
    if '--interactive' in sys.argv:
        # import the module here so we can reset the default complex args value
        import ansible.module_utils.basic

        ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
            resource_group="rm_demo",
        ))

    AzureRMStorageAccountFacts().exec_module()

if __name__ == '__main__':
    main()
