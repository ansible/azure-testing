#!/usr/bin/python
#
# (c) 2016 Matt Davis, <mdavis@redhat.com>
#          Chris Houseknecht, <house@redhat.com>
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
    from azure.common import AzureMissingResourceHttpError
    from azure.mgmt.resource.resources.models import ResourceGroup
except ImportError:
    pass


DOCUMENTATION = '''
---
module: azure_rm_resourcegroup
'''


class AzureRMResourceGroup(AzureRMModuleBase):
    def __init__(self, **kwargs):
        module_arg_spec = dict(
            name = dict(required=True),
            state = dict(default='present', choices=['present', 'absent']),
            location = dict(required=True),

            # TODO: implement tags
            # TODO: implement object security
        )

        AzureRMModuleBase.__init__(self, derived_arg_spec=module_arg_spec, supports_check_mode=True, **kwargs)

    def exec_module_impl(self, name, state, location, **kwargs):
        results = dict(changed=False)

        resource_client = self.resource_client

        try:
            self.debug('fetching resource group...')
            rg = resource_client.resource_groups.get(name)
            # TODO: there's a weird state where this doesn't 404 for a bit after deletion (check resource_group.provisioningState != Succeeded or Deleting)
            if state == 'absent':
                self.debug("CHANGED: resource group exists but requested state is 'absent'...")
                results['changed'] = True
            elif state == 'present':
                self.debug('comparing resource group attributes...')
                # TODO: reenable this check after canonicalizing location (lowercase, remove spaces)
                # if rg.resource_group.location != location:
                #     return dict(failed=True, msg="Resource group '{0}' already exists in location '{1}' and cannot be moved.".format(name, location))
        except AzureMissingResourceHttpError:
            self.debug('resource group does not exist')
            if state == 'present':
                self.debug("CHANGED: resource group does not exist but requested state is 'present'")
                results['changed'] = True

        if self._module.check_mode:
            self.debug('check mode, exiting early...')
            return results

        if not results['changed']:
            self.debug('no changes to make, exiting...')
            return results

        if state == 'present':
            self.debug('calling create_or_update...')
            res = resource_client.resource_groups.create_or_update(
                name,
                ResourceGroup(location=location)
            )
            self.debug('finished')
            # TODO: check anything in result?

        elif state == 'absent':
            self.debug('calling delete...')
            res = resource_client.resource_groups.delete(name)
            self.debug('finished')
            # TODO: poll for actual completion- looks like deletion is slow and async (even w/o begin_deleting)...
            # TODO: check anything in result?

        return results


def main():
    if '--interactive' in sys.argv:
        # import the module here so we can reset the default complex args value
        import ansible.module_utils.basic

        ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
            name='mdavis-test-rg5',
            state='present',
            location='West US',
            log_mode='stderr',
            #filter_logger=False,
        ))

    AzureRMResourceGroup().exec_module()

main()

