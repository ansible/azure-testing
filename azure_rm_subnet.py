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
module: azure_rm_subnet
short_description: Manage Azure subnets.

description:
    - Create, update or delete a subnet within a given virtual network. Allows setting and updating the address
      prefix CIDR, which must be valid within the context of the virtual network. Use the azure_rm_networkinterface
      module to associate interfaces with the subnet and assign specific IP addresses.

options:
    resource_group:
        description:
            - Name of resource group.
        required: true
    name:
        description:
            - Name of the subnet.
        required: true
    address_prefix_cidr:
        description:
            - CIDR defining the IPv4 address space of the subnet. Must be valid within the context of the
              virtual network.
        required: true
        aliases:
            - address_prefix
    state:
        description:
            - Assert the state of the subnet. Use 'present' to create or update a subnet and
              'absent' to delete a subnet.
        required: true
        default: present
        choices:
            - absent
            - present
    virtual_network_name:
        description:
            - Name of an existing virtual network with which the subnet is or will be associated.
        required: true
        aliases:
            - virtual_network

extends_documentation_fragment:
    - azure

author:
    - "Chris Houseknecht (@chouseknecht)"
    - "Matt Davis (@nitzmahone)"

'''

EXAMPLES = '''
    - name: Create a subnet
      azure_rm_subnet:
        name: foobar
        virtual_network_name: My_Virtual_Network
        resource_group: Testing
        address_prefix_cidr: "10.1.0.0/24"

    - name: Delete a subnet
      azure_rm_subnet:
        name: foobar
        virtual_network_name: My_Virtual_Network
        resource_group: Testing
        state: absent
'''


from ansible.module_utils.basic import *
from ansible.module_utils.azure_rm_common import *

try:
    from msrestazure.azure_exceptions import CloudError
    from azure.common import AzureMissingResourceHttpError
    from azure.mgmt.network.models import Subnet
except ImportError:
    # This is handled in azure_rm_common
    pass


NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.-_]+[a-zA-Z0-9_]$")


def subnet_to_dict(subnet):
    return dict(
        id=subnet.id,
        name=subnet.name,
        provisioning_state=subnet.provisioning_state,
        address_prefix=subnet.address_prefix)


class AzureRMSubnet(AzureRMModuleBase):

    def __init__(self, **kwargs):

        self.module_arg_spec = dict(
            resource_group=dict(required=True),
            name=dict(required=True),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            virtual_network_name=dict(type='str', required=True, aliases=['virtual_network']),
            address_prefix_cidr=dict(type='str', aliases=['address_prefix']),
        )

        required_if = [
            ('state', 'present', ['address_prefix_cidr'])
        ]

        super(AzureRMSubnet, self).__init__(self.module_arg_spec,
                                            supports_check_mode=True,
                                            required_if=required_if,
                                            **kwargs)

        self.results = dict(
            changed=False,
            check_mode=self.check_mode,
            results={}
        )

        self.resource_group = None
        self.name = None
        self.state = None
        self.virtual_etwork_name = None
        self.address_prefix_cidr = None

    def exec_module_impl(self, **kwargs):
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if not NAME_PATTERN.match(self.name):
            self.fail("Parameter error: name must begin with a letter or number, end with a letter, number "
                      "or underscore and may contain only letters, numbers, periods, underscores or hyphens.")

        if self.state == 'present' and not CIDR_PATTERN.match(self.address_prefix_cidr):
            self.fail("Invalid address_prefix_cidr value {0}".format(self.address_prefix_cidr))

        results = dict()
        changed = False

        try:
            self.log('Fetching subnet {0}'.format(self.name))
            subnet = self.network_client.subnets.get(self.resource_group,
                                                     self.virtual_network_name,
                                                     self.name)
            self.check_provisioning_state(subnet, self.state)
            if self.state == 'present':
                results = subnet_to_dict(subnet)
            elif self.state == 'absent':
                changed = True
        except CloudError:
            # the subnet does not exist
            if self.state == 'present':
                changed = True

        self.results['changed'] = changed
        self.results['results'] = results

        if self.state == 'present' and changed:
            # create new subnet
            if not self.check_mode:
                self.log('Creating subnet {0}'.format(self.name))
                self.results['results'] = self.create_or_update_subnet()
        elif self.state == 'present' and not changed:
            # update subnet
            if results['address_prefix'] != self.address_prefix_cidr:
                changed = True
                self.results['address_prefix'] = self.address_prefix_cidr
                self.results['changed'] = changed
                if not self.check_mode:
                    self.log('Updating subnet {0}'.format(self.name))
                    self.results['results'] = self.create_or_update_subnet()
        elif self.state == 'absent':
            # delete subnet
            if not self.check_mode:
                self.delete_subnet()
                # the delete does not actually return anything. if no exception, then we'll assume
                # it worked.
                self.results['results']['status'] = 'Deleted'
        return self.results

    def create_or_update_subnet(self):
        subnet = Subnet(
            address_prefix=self.address_prefix_cidr
        )
        poller = self.network_client.subnets.create_or_update(self.resource_group,
                                                              self.virtual_network_name,
                                                              self.name,
                                                              subnet)
        new_subnet = self.get_poller_result(poller)
        self.check_provisioning_state(new_subnet)
        return subnet_to_dict(new_subnet)

    def delete_subnet(self):
        self.log('Deleting subnet {0}'.format(self.name))
        try:
            poller = self.network_client.subnets.delete(self.resource_group,
                                                        self.virtual_network_name,
                                                        self.name)
        except Exception, exc:
            self.fail("Error deleting subnet {0} - {1}".format(self.name, str(exc)))

        return self.get_poller_result(poller)


def main():
    AzureRMSubnet().exec_module()

if __name__ == '__main__':
    main()

