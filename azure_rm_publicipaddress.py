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
module: azure_rm_publicipaddress
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
from azure.mgmt.network import PublicIpAddress

class AzureRMPublicIPAddress(AzureRMModuleBase):
    def __init__(self, **kwargs):
        module_arg_spec = dict(
            resource_group = dict(required=True),
            name = dict(required=True),
            state = dict(default='present', choices=['present', 'absent']),
            location = dict(required=True),

            # TODO: implement tags
            # TODO: implement object security
        )

        AzureRMModuleBase.__init__(self, derived_arg_spec=module_arg_spec, supports_check_mode=True, **kwargs)


    def exec_module_impl(self, resource_group, name, state, location, **kwargs):  
        #TODO: add automatic Microsoft.Network provider check/registration (only on failure?)
        results = dict(changed=False)
    
        # TODO: validate arg shape (CIDR blocks, etc)
    
        try:
            self.debug('fetching pip...')
            pip_resp = self.network_client.public_ip_addresses.get(resource_group, name)
            # TODO: check if resource_group.provisioningState != Succeeded or Deleting, equiv to 404 but blocks
            self.debug('pip exists...')
            pip = pip_resp.public_ip_address
            if state == 'present':
                # TODO: move to extract method
                results['id'] = pip.id # store these values early in case of check mode exit
                results['ip_address'] = pip.ip_address
                # TODO: validate args
                # TODO: what about ip_configuration tie to nic?
            elif state == 'absent':
                self.debug("CHANGED: pip exists but requested state is 'absent'")
                results['changed'] = True
        except AzureMissingResourceHttpError:
            self.debug('pip does not exist')
            if state == 'present':
                self.debug("CHANGED: pip does not exist but requested state is 'present'")
                results['changed'] = True
    
        if self._module.check_mode:
            self.debug('check mode, exiting early')
            return results
    
        if results['changed']:
            if state == 'present':
    
                pip = PublicIpAddress(
                    location=location,
                    # TODO: get this from an arg
                    public_ip_allocation_method='dynamic'
                )
                self.debug('creating/updating pip...')
                pip_resp = self.network_client.public_ip_addresses.create_or_update(resource_group, name, pip)
                # TODO: check response
    
                pip_resp = self.network_client.public_ip_addresses.get(resource_group, name)
                # TODO: move to extract_result method
                results['id'] = pip_resp.public_ip_address.id
                results['ip_address'] = pip_resp.public_ip_address.ip_address
    
            elif state == 'absent':
                self.debug('deleting pip...')
                pip_resp = self.network_client.public_ip_addresses.delete(resource_group, name)
                # TODO: check response
    
        return results

def main():
    if '--interactive' in sys.argv:
        # import the module here so we can reset the default complex args value
        import ansible.module_utils.basic

        ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
            resource_group = "rm_demo",
            name = "test-publicip",
            state = "present",
            location = "West US",
            log_mode='stderr',
            #filter_logger=False,
        ))

    AzureRMPublicIPAddress().exec_module()

main()

