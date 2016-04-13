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
module: azure_rm_publicip_facts

short_description: Get public IP facts.

description:
    - Get facts for a specific public IP or all public IPs within a resource group.

options:
    name:
        description:
            - Only show results for a specific Public IP.
        default: null
    resource_group:
        description:
            - Name of the resource group containing the Public IPs.
        required: true
        default: null

extends_documentation_fragment:
    - azure

author:
    - "Chris Houseknecht (@chouseknecht)"
    - "Matt Davis (@nitzmahone)"
'''

EXAMPLES = '''
    - name: Get facts for one Public IP
      azure_rm_publicip_facts:
        resource_group: Testing
        name: publicip001

    - name: Get facts for all Public IPs
      azure_rm_publicip_facts:
        resource_group: Testing

'''

EXAMPLE_OUTPUT = '''
{
    "output": {
        "changed": false,
        "check_mode": false,
        "results": [
            {
                "etag": "W/\"a31a6d7d-cb18-40a5-b16d-9f4a36c1b18a\"",
                "id": "/subscriptions/3f7e29ba-24e0-42f6-8d9c-5149a14bda37/resourceGroups/Testing/providers/Microsoft.Network/publicIPAddresses/pip2001",
                "location": "eastus2",
                "name": "pip2001",
                "properties": {
                    "idleTimeoutInMinutes": 4,
                    "provisioningState": "Succeeded",
                    "publicIPAllocationMethod": "Dynamic",
                    "resourceGuid": "29de82f4-a7da-440e-bd3d-9cabb79af95a"
                },
                "type": "Microsoft.Network/publicIPAddresses"
            }
        ]
    }
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

AZURE_OBJECT_CLASS = 'PublicIp'


class AzureRMPublicIPFacts(AzureRMModuleBase):

    def __init__(self, **kwargs):

        self.module_arg_spec = dict(
            name=dict(type='str'),
            resource_group=dict(required=True, type='str'),
        )

        super(AzureRMPublicIPFacts, self).__init__(self.module_arg_spec,
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
            self.results['results'] = self.get_item()
        else:
            self.results['results'] = self.list_items()

        return self.results

    def get_item(self):
        self.log('Get properties for {0}'.format(self.name))
        item = None
        result = []

        try:
            item = self.network_client.public_ip_addresses.get(self.resource_group, self.name)
        except CloudError:
            pass

        if item:
            result = [self.serialize_obj(item, AZURE_OBJECT_CLASS)]

        return result

    def list_items(self):
        self.log('List all items')
        try:
            response = self.network_client.public_ip_addresses.list(self.resource_group)
        except AzureHttpError, exc:
            self.fail("Error listing all items - {0}".format(str(exc)))

        results = []
        for item in response:
            results.append(self.serialize_obj(item, AZURE_OBJECT_CLASS))
        return results


def main():
    if '--interactive' in sys.argv:
        # import the module here so we can reset the default complex args value
        import ansible.module_utils.basic

        ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
            resource_group='Testing'
        ))

    AzureRMPublicIPFacts().exec_module()

if __name__ == '__main__':
    main()

