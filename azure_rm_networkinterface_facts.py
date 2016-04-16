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
module: azure_rm_networkinterface_facts

version_added: "2.1"

short_description: Get network interface facts.

description:
    - Get facts for a specific network interface or all network interfaces within a resource group.

options:
    name:
        description:
            - Only show results for a specific network interface.
        required: false
    resource_group:
        description:
            - Name of the resource group containing the network interface(s). Required when searching by name.
        required: false
    tags:
        description:
            - Limit results by providing a list of tags. Format tags as 'key' or 'key:value'.
        required: false

extends_documentation_fragment:
    - azure

author:
    - "Chris Houseknecht (@chouseknecht)"
    - "Matt Davis (@nitzmahone)"

'''

EXAMPLES = '''
    - name: Get facts for one network interface
      azure_rm_networkinterface_facts:
        resource_group: Testing
        name: nic001

    - name: Get network interfaces within a resource group
      azure_rm_networkinterface_facts:
        resource_group: Testing

    - name: Get network interfaces by tag
      azure_rm_networkinterface_facts:
        resource_group: Testing
        tags:
          - testing
          - foo:bar
'''

from ansible.module_utils.basic import *
from ansible.module_utils.azure_rm_common import *

try:
    from msrestazure.azure_exceptions import CloudError
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
except:
    # This is handled in azure_rm_common
    pass


AZURE_OBJECT_CLASS = 'NetworkInterface'


class AzureRMNetworkInterfaceFacts(AzureRMModuleBase):

    def __init__(self):

        self.module_arg_spec = dict(
            name=dict(type='str'),
            resource_group=dict(type='str'),
            tags=dict(type='list')
        )

        self.results = dict(
            changed=False,
            results=[]
        )

        self.name = None
        self.resource_group = None
        self.tags = None

        super(AzureRMNetworkInterfaceFacts, self).__init__(self.module_arg_spec,
                                                           supports_tags=False,
                                                           facts_module=True
                                                           )

    def exec_module(self, **kwargs):

        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if self.name and not self.resource_group:
            self.fail("Parameter error: resource group required when filtering by name.")

        if self.name:
            self.results['results'] = self.get_item()
        elif self.resource_group:
            self.results['results'] = self.list_resource_group()
        else:
            self.results['results'] = self.list_all()

        return self.results

    def get_item(self):
        self.log('Get properties for {0}'.format(self.name))
        result = []
        item = None
        try:
            item = self.network_client.network_interfaces.get(self.resource_group, self.name)
        except:
            pass

        if item and self.has_tags(item.tags, self.tags):
            result = [self.serialize_obj(item, AZURE_OBJECT_CLASS)]

        return result

    def list_resource_group(self):
        self.log('List for resource group')
        try:
            response = self.network_client.network_interfaces.list(self.resource_group)
        except Exception as exc:
            self.fail("Error listing by resource group {0} - {1}".format(self.resource_group, str(exc)))

        results = []
        for item in response:
            if self.has_tags(item.tags, self.tags):
                results.append(self.serialize_obj(item, AZURE_OBJECT_CLASS))
        return results

    def list_all(self):
        self.log('List all')
        try:
            response = self.network_client.network_interfaces.list_all()
        except Exception as exc:
            self.fail("Error listing all - {1}".format(self.resource_group, str(exc)))

        results = []
        for item in response:
            if self.has_tags(item.tags, self.tags):
                results.append(self.serialize_obj(item, AZURE_OBJECT_CLASS))
        return results


def main():
    AzureRMNetworkInterfaceFacts()

if __name__ == '__main__':
    main()

