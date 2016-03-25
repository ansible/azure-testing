#!/usr/bin/python
#
# (c) 2016 Matt Davis, <mdavis@ansible.com>
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
    from azure.common import AzureMissingResourceHttpError
    from azure.mgmt.network.models import Subnet
except ImportError:
    # This is handled in azure_rm_common
    pass


DOCUMENTATION = '''
---
module: azure_rm_subnet
short_description: Manage Azure subnets.

description:
    - Create, update and delete subnets within a given virtual network. Allows setting and updating the address
      prefix CIDR, which must be valid within the context of the virtual network. Use the azure_rm_network_interface
      module to associate interfaces with the subnet and assign specific IP addresses.
    - For authentication with Azure you can pass parameters, set environment variables or use a profile stored
      in ~/.azure/credentials. Authentication is possible using a service principal or Active Directory user.
    - To authenticate via service principal pass subscription_id, client_id, secret and tenant or set set environment
      variables AZURE_SUBSCRIPTION_ID, AZURE_CLIENT_ID, AZURE_SECRET and AZURE_TENANT.
    - To Authentication via Active Directory user pass ad_user and password, or set AZURE_AD_USER and
      AZURE_PASSWORD in the environment.
    - Alternatively, credentials can be stored in ~/.azure/credentials. This is an ini file containing
      a [default] section and the following keys: subscription_id, client_id, secret and tenant or
      ad_user and password. It is also possible to add addition profiles to this file. Specify the profile
      by passing profile or setting AZURE_PROFILE in the environment.

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
            - name of the subnet.
        required: true
        default: null
    address_prefix_cidr:
        description:
            - CIDR defining IPv4 address space of the subnet. Must be valid within the context of the
              virtual network.
        default: null
        required: true
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
        default: null
        required: true

requirements:
    - "python >= 2.7"
    - "azure >= 1.0.2"

authors:
    - "Matt Davis <mdavis@ansible.com>"
    - "Chris Houseknecht @chouseknecht"
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
            virtual_network_name=dict(type='str', required=True),
            address_prefix_cidr=dict(type='str'),
            log_file=dict(type='str', default='azure_rm_subnet.log')
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

            if subnet.provisioning_state != AZURE_SUCCESS_STATE:
                self.fail("Error subnet {0} has a provisioning state of {1}. Expecting state to be {2}.".format(
                    self.name, subnet.provisioning_state, AZURE_SUCCESS_STATE))

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

    def check_provisioning_state(self, subnet):
        if subnet.provisioning_state != AZURE_SUCCESS_STATE:
            self.fail("Error subnet {0} has a provisioning state of {1}. "
                      "Expecting state to be {2}.".format(subnet.name, subnet.provisioning_state,
                                                          AZURE_SUCCESS_STATE))

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
    if '--interactive' in sys.argv:
        # import the module here so we can reset the default complex args value
        import ansible.module_utils.basic

        ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
            resource_group='rm_demo',
            name='test-subnet-1',
            virtual_network_name='test-vnet',
            address_prefix_cidr='10.0.1.0/24',
            state='absent',
            #location='West US',
            log_mode='stderr',
        ))

    AzureRMSubnet().exec_module()


main()

