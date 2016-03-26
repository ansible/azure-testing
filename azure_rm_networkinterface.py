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
module: azure_rm_networkinterface
'''

# normally we'd put this at the bottom to preserve line numbers, but we can't use a forward-defined base class
# without playing games with __metaclass__ or runtime base type hackery.
# TODO: figure out a better way...
from ansible.module_utils.basic import *
from ansible.module_utils.azure_rm_common import *

try:
    from azure.common import AzureMissingResourceHttpError
    from azure.mgmt.network.models import NetworkInterface, NetworkInterfaceIpConfiguration, ResourceId
    from azure.mgmt.network.models.network_management_client_enums import IPAllocationMethod
except ImportError:
    # This is handled in azure_rm_common
    pass

class AzureRMNetworkInterface(AzureRMModuleBase):
    def __init__(self, **kwargs):
        module_arg_spec = dict(
            resource_group=dict(required=True),
            name=dict(required=True),
            state=dict(default='present', choices=['present', 'absent']),
            location=dict(required=True),
            subnet_id=dict(required=True),

            # TODO: implement tags
            # TODO: implement object security
        )
    
        AzureRMModuleBase.__init__(self, derived_arg_spec=module_arg_spec, supports_check_mode=True, **kwargs)


    def exec_module_impl(self, resource_group, name, state, location, subnet_id, public_ip_id, **kwargs):
        #TODO: add automatic Microsoft.Network provider check/registration (only on failure?)
        results=dict(changed=False)
    
        # TODO: validate arg shape (CIDR blocks, etc)

        try:
            self.debug('fetching nic...')
            nic_resp = self.network_client.network_interfaces.get(resource_group, name)
            # TODO: check if resource_group.provisioningState != Succeeded or Deleting, equiv to 404 but blocks
            self.debug('nic exists...')
            nic = nic_resp.network_interface
            if state == 'present':
                results['id'] = nic.id # store this early for check mode / no changes
                # TODO: validate args
    
            elif state == 'absent':
                self.debug("CHANGED: nic exists but requested state is 'absent'")
                results['changed'] = True
        except AzureMissingResourceHttpError:
            self.debug('nic does not exist')
            if state == 'present':
                self.debug("CHANGED: nic does not exist but requested state is 'present'")
                results['changed'] = True
    
        if self._module.check_mode:
            self.debug('check mode, exiting early')
            return results
    
        if results['changed']:
            if state == 'present':
                public_ip_resourceid = ResourceId(id=public_ip_id) if public_ip_id else None
    
                nic = NetworkInterface(
                    location=location,
                    ip_configurations=[NetworkInterfaceIpConfiguration(
                        name='default',
                        public_ip_address=public_ip_resourceid,
                        private_ip_allocation_method='dynamic', # TODO: make this an arg, add user-set static IP support
                        subnet = ResourceId(
                            id=subnet_id
                        ),
                    )],
                )
    
                self.debug('creating/updating nic...')
                nic_resp = self.network_client.network_interfaces.create_or_update(resource_group, name, nic)
                # TODO: check response
                self.debug('re-fetching nic after changes...')
                nic_resp = self.network_client.network_interfaces.get(resource_group, name)
                results['id'] = nic_resp.network_interface.id
    
            elif state == 'absent':
                self.debug('deleting nic...')
                nic_resp = self.network_client.network_interfaces.delete(resource_group, name)
                # TODO: check response
    
        return results

def main():
    if '--interactive' in sys.argv:
        # import the module here so we can reset the default complex args value
        import ansible.module_utils.basic

        ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
            resource_group = "rm_demo",
            name = "test-nic",
            state = "present",
            location = "West US",
            subnet_id = "subscriptions/3f7e29ba-24e0-42f6-8d9c-5149a14bda37/resourceGroups/rm_demo/providers/Microsoft.Network/virtualNetworks/test-vnet/subnets/test-subnet-1",
            public_ip_id = None,
            #filter_logger=False,
            log_mode = "stderr"
        ))

    AzureRMNetworkInterface().exec_module()

main()

