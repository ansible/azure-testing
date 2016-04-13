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

short_description: Get network interface facts.

description:
    - Get facts for a specific network interface or all network interfaces within a resource group.

options:
    name:
        description:
            - Only show results for a specific network interface.
        default: null
    resource_group:
        description:
            - Name of the resource group containing the network interface(s).
        required: true
        default: null

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

    - name: Get facts for all network interfaces
      azure_rm_networkinterface_facts:
        resource_group: Testing

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

    def __init__(self, **kwargs):

        self.module_arg_spec = dict(
            name=dict(type='str'),
            resource_group=dict(required=True, type='str'),
        )

        super(AzureRMNetworkInterfaceFacts, self).__init__(self.module_arg_spec,
                                                           **kwargs)
        self.results = dict(
            changed=False,
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
        result = []
        item = None
        try:
            item = self.network_client.network_interfaces.get(self.resource_group, self.name)
        except:
            pass

        if item:
            result = [self.serialize_obj(item, AZURE_OBJECT_CLASS)]

        return result

    def list_items(self):
        self.log('List all items')
        try:
            response = self.network_client.network_interfaces.list(self.resource_group)
        except Exception, exc:
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

    AzureRMNetworkInterfaceFacts().exec_module()

if __name__ == '__main__':
    main()

