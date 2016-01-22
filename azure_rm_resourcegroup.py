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
module: azure_rm_resourcegroup
'''
HAS_AZURE = True
HAS_REQUESTS = True
LOG_PATH = "azure_rm_resourcegroup.log"

try:
    from azure.common import AzureMissingResourceHttpError
    from azure.mgmt.common import SubscriptionCloudCredentials
    from azure.mgmt.resource import ResourceManagementClient, ResourceGroup
    import azure.mgmt.network
except ImportError:
    HAS_AZURE = False

try:
    import requests
except ImportError:
    HAS_REQUESTS = False

def module_impl(rm, log, name, state, location, check_mode=False):
    if not HAS_AZURE:
        raise Exception("The Azure python sdk is not installed (try 'pip install azure'")
    if not HAS_REQUESTS:
        raise Exception("The requests python module is not installed (try 'pip install requests'")

    results = dict(changed=False)

    resource_client = rm.rm_client

    try:
        log('fetching resource group...')
        rg = resource_client.resource_groups.get(name)
        # TODO: there's a weird state where this doesn't 404 for a bit after deletion (check resource_group.provisioningState != Succeeded or Deleting)
        if state == 'absent':
            log("CHANGED: resource group exists but requested state is 'absent'...")
            results['changed'] = True
        elif state == 'present':
            log('comparing resource group attributes...')
            # TODO: reenable this check after canonicalizing location (lowercase, remove spaces)
            # if rg.resource_group.location != location:
            #     return dict(failed=True, msg="Resource group '{0}' already exists in location '{1}' and cannot be moved.".format(name, location))
    except AzureMissingResourceHttpError:
        log('resource group does not exist')
        if state == 'present':
            log("CHANGED: resource group does not exist but requested state is 'present'")
            results['changed'] = True

    if check_mode:
        log('check mode, exiting early...')
        return results

    if not results['changed']:
        log('no changes to make, exiting...')
        return results

    if state == 'present':
        log('calling create_or_update...')
        res = resource_client.resource_groups.create_or_update(
            name,
            ResourceGroup(location=location)
        )
        log('finished')
        # TODO: check anything in result?

    elif state == 'absent':
        log('calling delete...')
        res = resource_client.resource_groups.delete(name)
        log('finished')
        # TODO: poll for actual completion- looks like deletion is slow and async (even w/o begin_deleting)...
        # TODO: check anything in result?

    return results

def main():
    
    module_args = dict(
        name = dict(required=True),
        state = dict(default='present', choices=['present', 'absent']),
        location = dict(required=True),
        
        # TODO: implement tags
        # TODO: implement object security
    )

    module = azure_module(
        argument_spec=module_args,
        supports_check_mode=True
    )
    
    p = module.params

    try:
        rm = AzureRM(module)
    except Exception as e:
        module.fail_json(msg=e.args[0])
    
    try:
        res = module_impl(rm, module.debug, p.get('name'), p.get('state'), p.get('location'), module.check_mode)
    except:
        raise

    module.exit_json(**res)

from ansible.module_utils.basic import *

# Assumes running ansible from source and there is a copy or symlink for azure_rm_common
# found in local lib/ansible/module_utils
from ansible.module_utils.azure_rm_common import *

main()

