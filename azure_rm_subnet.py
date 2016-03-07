#!/usr/bin/python
#
# (c) 2015 Matt Davis, <mdavis@ansible.com>
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
'''
import sys
# normally we'd put this at the bottom to preserve line numbers, but we can't use a forward-defined base class
# without playing games with __metaclass__ or runtime base type hackery.
# TODO: figure out a better way...
from ansible.module_utils.basic import *

# Assumes running ansible from source and there is a copy or symlink for azure_rm_common
# found in local lib/ansible/module_utils
from ansible.module_utils.azure_rm_common import *

# TODO: ensure the base class errors properly on these imports failing
from azure.common import AzureMissingResourceHttpError
from azure.mgmt.network import Subnet

class AzureRMSubnet(AzureRMModuleBase):
    def __init__(self, **kwargs):
        module_arg_spec = dict(
            resource_group = dict(required=True),
            name = dict(required=True),
            state = dict(default='present', choices=['present', 'absent']),
            location = dict(required=True),
            virtual_network_name = dict(required=True),
            address_prefix_cidr = dict(required=True),
            # TODO: implement tags
            # TODO: implement object security
        )

        AzureRMModuleBase.__init__(self, derived_arg_spec=module_arg_spec, supports_check_mode=True, **kwargs)

    def exec_module_impl(self, resource_group, name, state, location, virtual_network_name, address_prefix_cidr, **kwargs):
        #TODO: add automatic Microsoft.Network provider check/registration (only on failure?)
        results = dict(changed=False)

        # TODO: validate arg shape (CIDR blocks, etc)

        try:
            self.debug('fetching subnet...')
            subnet_resp = self.network_client.subnets.get(resource_group, virtual_network_name, name)
            # TODO: check if resource_group.provisioningState != Succeeded or Deleting, equiv to 404 but blocks
            self.debug('subnet exists...')
            subnet = subnet_resp.subnet
            if state == 'present':
                results['id'] = subnet.id # store this early in case of check mode
            # TODO: validate args
                if subnet.address_prefix != address_prefix_cidr:
                    self.debug("CHANGED: subnet address range does not match")
                    results['changed'] = True
            elif state == 'absent':
                self.debug("CHANGED: subnet exists and state is 'absent'")
                results['changed'] = True
        except AzureMissingResourceHttpError:
            self.debug('subnet does not exist')
            if state == 'present':
                self.debug("CHANGED: subnet does not exist and state is 'present'")
                results['changed'] = True

        if self._module.check_mode:
            self.debug('check mode, exiting early')
            return results

        if results['changed']:
            if state == 'present':

                subnet = Subnet(
                    address_prefix=address_prefix_cidr
                )
                self.debug('creating/updating subnet...')
                subnet_resp = self.network_client.subnets.create_or_update(resource_group, virtual_network_name, name, subnet)
                # TODO: check response for success

                # TODO: optimize away in change case
                subnet_resp = self.network_client.subnets.get(resource_group, virtual_network_name, name)

                results['id'] = subnet_resp.subnet.id

            elif state == 'absent':
                self.debug('deleting subnet...')
                subnet_resp = self.network_client.subnets.delete(resource_group, virtual_network_name, name)
                # TODO: check response

        return results

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
            location='West US',
            log_mode='stderr',
            #filter_logger=False,
        ))

    AzureRMSubnet().exec_module()



main()

