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
module: azure_rm_virtualnetwork_facts

short_description: Get virtual network facts.

description:
    - Get facts for a specific virtual network or all virtual networks within a resource group.

options:
    name:
        description:
            - Only show results for a specific security group.
    resource_group:
        description:
            - Name of a resource group.
        required: true

extends_documentation_fragment:
    - azure

authors:
    - "Chris Houseknecht house@redhat.com"
    - "Matt Davis mdavis@redhat.com"

'''

EXAMPLES = '''
    - name: Get facts for one virtual network
      azure_rm_virtualnetwork_facts:
        resource_group: Testing
        name: secgroup001

    - name: Get facts for all virtual networks
      azure_rm_virtualnetwork_facts:
        resource_group: Testing

'''

EXAMPLE_OUTPUT = '''
{
    "changed": false,
    "check_mode": false,
    "results": [
        {
            "etag": "W/\"532ba1be-ae71-40f2-9232-3b1d9cf5e37e\"",
            "id": "/subscriptions/3f7e29ba-24e0-42f6-8d9c-5149a14bda37/resourceGroups/Testing/providers/Microsoft.Network/virtualNetworks/vnet2001",
            "location": "eastus2",
            "name": "vnet2001",
            "properties": {
                "addressSpace": {
                    "addressPrefixes": [
                        "10.10.0.0/16"
                    ]
                },
                "provisioningState": "Succeeded",
                "resourceGuid": "a7ba285f-f7e7-4e17-992a-de4d39f28612",
                "subnets": []
            },
            "type": "Microsoft.Network/virtualNetworks"
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


AZURE_OBJECT_CLASS = 'VirtualNetwork'


class AzureRMNetworkInterfaceFacts(AzureRMModuleBase):

    def __init__(self, **kwargs):

        self.module_arg_spec = dict(
            name=dict(type='str'),
            resource_group=dict(required=True, type='str'),
        )

        super(AzureRMNetworkInterfaceFacts, self).__init__(self.module_arg_spec,
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
        results = []

        try:
            item = self.network_client.virtual_networks.get(self.resource_group, self.name)
        except CloudError:
            pass

        if item:
            results = [self.serialize_obj(item, AZURE_OBJECT_CLASS)]

        return results

    def list_items(self):
        self.log('List all for items')
        try:
            response = self.network_client.virtual_networks.list(self.resource_group)
        except AzureHttpError, exc:
            self.fail("Failed to list all items - {0}".format(str(exc)))

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

    AzureRMNetworkInterfaceFacts().exec_module()

if __name__ == '__main__':
    main()

