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

log_path = None

def log(msg):
#    print msg

    if not log_path:
        return
    with open(log_path, "a") as logfile:
        logfile.write("{0}\n".format(msg))

def get_token_from_client_credentials(endpoint, client_id, client_secret):
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'resource': 'https://management.core.windows.net/',
    }
    response = requests.post(endpoint, data=payload).json()
    return response['access_token']

def get_rm_client(endpoint, subscription_id, client_id, client_secret):
    log('getting auth token...')

    auth_token = get_token_from_client_credentials(
        endpoint,
        client_id,
        client_secret
    )

    log('creating credential object...')

    creds = SubscriptionCloudCredentials(subscription_id, auth_token)

    log('creating ARM client...')

    resource_client = ResourceManagementClient(creds)

    return resource_client


def module_impl(name, state, location, subscription_id, auth_tenant_id, auth_endpoint, auth_client_id, auth_client_secret, check_mode=False):
    if not HAS_AZURE:
        raise Exception("The Azure python sdk is not installed (try 'pip install azure'")
    if not HAS_REQUESTS:
        raise Exception("The requests python module is not installed (try 'pip install requests'")

    results = dict(changed=False)

    resource_client = get_rm_client(auth_endpoint, subscription_id, auth_client_id, auth_client_secret)

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
    global log_path
    module = AnsibleModule(
        argument_spec = dict(
            name = dict(required=True),
            state = dict(default='present', choices=['present', 'absent']),
            location = dict(required=True),
            log_path = dict(default=None),

            # TODO: implement tags
            # TODO: implement object security

            # common/auth args
            # TODO: move to a shared definition
            subscription_id = dict(required=True), # TODO: False after .azure/env stuff is here
            auth_tenant_id = dict(required=True), # TODO: False after .azure/env stuff is here
            auth_client_id = dict(required=True, no_log=True), # TODO: False after .azure/env stuff is here
            auth_client_secret = dict(required=True, no_log=True), # TODO: False after .azure/env stuff is here
        ),
        supports_check_mode = True
    )

    p = module.params

    # allow these to come from env and .azure/credentials
    subscription_id = p['subscription_id']
    auth_tenant_id = p['auth_tenant_id']
    auth_endpoint='https://login.microsoftonline.com/{0}/oauth2/token'.format(auth_tenant_id)
    auth_client_id = p['auth_client_id']
    auth_client_secret = p['auth_client_secret']

    log_path = p['log_path']

    res = module_impl(p.get('name'), p.get('state'), p.get('location'), subscription_id, auth_tenant_id, auth_endpoint, auth_client_id, auth_client_secret, module.check_mode)

    module.exit_json(**res)

from ansible.module_utils.basic import *
main()

