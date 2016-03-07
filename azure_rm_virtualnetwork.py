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
module: azure_rm_virtualnetwork
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
from azure.mgmt.network import VirtualNetwork, AddressSpace


class AzureRMVirtualNetwork(AzureRMModuleBase):
    def __init__(self, **kwargs):
        module_arg_spec = dict(
            resource_group = dict(required=True),
            name = dict(required=True),
            state = dict(default='present', choices=['present', 'absent']),
            location = dict(required=True),
            address_prefixes_cidr = dict(type='list', required=True),
            log_path = dict(default=None)
        )

        AzureRMModuleBase.__init__(self, derived_arg_spec=module_arg_spec, supports_check_mode=True, **kwargs)


    def exec_module_impl(self, resource_group, name, state, location, address_prefixes_cidr, **kwargs):
        #TODO: add automatic Microsoft.Network provider check/registration (only on failure?)
        results = dict(changed=False)

        # TODO: validate arg shape (CIDR blocks, etc)


        try:
            self.debug('fetching vnet...')
            vnet_resp = self.network_client.virtual_networks.get(resource_group, name)
            # TODO: check if resource_group.provisioningState != Succeeded or Deleting, equiv to 404 but blocks
            self.debug('vnet exists...')
            vnet = vnet_resp.virtual_network
            if state == 'present':
                results['id'] = vnet.id # store this early in case of check mode (and only if requested state is present)
                self.debug('validating address_prefixes...')
                existing_address_prefix_set = set(vnet.address_space.address_prefixes)
                requested_address_prefix_set = set(address_prefixes_cidr)
                missing_prefixes = requested_address_prefix_set - existing_address_prefix_set
                # TODO: handle removal (best-effort?)
                if(len(missing_prefixes) > 0):
                    self.debug('CHANGED: there are missing address_prefixes')
                    results['changed'] = True
                # TODO: implement dns_servers

            elif state == 'absent':
                self.debug("CHANGED: vnet exists but requested state is 'absent'")
                results['changed'] = True
        except AzureMissingResourceHttpError:
            self.debug('vnet does not exist')
            if state == 'present':
                self.debug("CHANGED: vnet does not exist but requested state is 'present'")
                results['changed'] = True

        if self._module.check_mode:
            self.debug('check mode, exiting early')
            return results

        if results['changed']:
            if state == 'present':

                vnet = VirtualNetwork(
                    location=location,
                    address_space=AddressSpace(
                        address_prefixes=address_prefixes_cidr
                    )
                )

                self.debug('creating/updating vnet...')
                vnet_resp = self.network_client.virtual_networks.create_or_update(resource_group, name, vnet)
                # TODO: check response

                # TOOD: could optimize this away for change cases
                self.debug('fetching vnet (post create/update)...')
                vnet_resp = self.network_client.virtual_networks.get(resource_group, name)

                vnet = vnet_resp.virtual_network
                results['id'] = vnet.id

            elif state == 'absent':
                self.debug('deleting vnet...')
                vnet_resp = self.network_client.virtual_networks.delete(resource_group, name)
                # TODO: check response

        return results

def main():
    if '--interactive' in sys.argv:
        # import the module here so we can reset the default complex args value
        import ansible.module_utils.basic

        ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
            resource_group="rm_demo",
            name='test-vnet',
            state='present',
            location='West US',
            address_prefixes_cidr=['10.0.1.0/24'],
            log_mode='stderr'
        ))

    AzureRMVirtualNetwork().exec_module()



from ansible.module_utils.basic import *
main()

