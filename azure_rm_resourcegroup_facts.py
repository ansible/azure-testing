#!/usr/bin/python
#
# Copyright (c) 2016 Matt Davis, <mdavis@ansible.com>
#                    Chris Houseknecht, <house@redhat.com>
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

DOCUMENTATION = '''
---
module: azure_rm_resouregroup_facts

short_description: Get resource group facts.

description:
    - Get facts for a specific resource group or all resource groups.

options:
    name:
        description:
            - Only show results for a specific resource group.

extends_documentation_fragment:
    - azure

author:
    - "Chris Houseknecht (@chouseknecht)"
    - "Matt Davis (@nitzmahone)"

'''

EXAMPLES = '''
    - name: Get facts for one resource group
      azure_rm_resourcegroup_facts:
        name: Testing

    - name: Get facts for all resource groups
      azure_rm_securitygroup_facts:

'''

EXAMPLE_OUTPUT = '''
{
    "changed": false,
    "results": [
        {
            "id": "/subscriptions/3f7e29ba-24e0-42f6-8d9c-5149a14bda37/resourceGroups/Testing",
            "location": "westus",
            "name": "Testing",
            "properties": {
                "provisioningState": "Succeeded"
            },
            "tags": {
                "delete": "never",
                "testing": "testing"
            }
        }
    ]
}
'''

from ansible.module_utils.basic import *
from ansible.module_utils.azure_rm_common import *

try:
    from msrestazure.azure_exceptions import CloudError
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
except:
    # This is handled in azure_rm_common
    pass


AZURE_OBJECT_CLASS = 'ResourceGroup'


class AzureRMResourceGroupFacts(AzureRMModuleBase):

    def __init__(self, **kwargs):

        self.module_arg_spec = dict(
            name=dict(type='str'),
        )

        super(AzureRMResourceGroupFacts, self).__init__(self.module_arg_spec,
                                                        supports_tags=False,
                                                        **kwargs)
        self.results = dict(
            changed=False,
            results=[]
        )

        self.name = None

    def exec_module_impl(self, **kwargs):

        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if self.name is not None:
            self.results['results'] = self.get_item()
        else:
            self.results['results'] = self.list_items()

        return self.results

    def get_item(self):
        self.log('Get properties for {0}'.format(self.name))
        item = None
        result = []

        try:
            item = self.rm_client.resource_groups.get(self.name)
        except CloudError:
            pass

        if item:
            result = [self.serialize_obj(item, AZURE_OBJECT_CLASS)]

        return result

    def list_items(self):
        self.log('List all items')
        try:
            response = self.rm_client.resource_groups.list()
        except AzureHttpError, exc:
            self.fail("Failed to list all items - {1}".format(str(exc)))

        results = []
        for item in response:
            results.append(self.serialize_obj(item, AZURE_OBJECT_CLASS))
        return results


def main():
    if '--interactive' in sys.argv:
        # import the module here so we can reset the default complex args value
        import ansible.module_utils.basic

        ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
            name='Testing'
        ))

    AzureRMResourceGroupFacts().exec_module()

if __name__ == '__main__':
    main()

