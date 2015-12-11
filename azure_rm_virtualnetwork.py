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

HAS_AZURE = True
HAS_REQUESTS = True

try:
    from azure.common import AzureMissingResourceHttpError
    from azure.mgmt.common import SubscriptionCloudCredentials
    import azure.mgmt.network
except ImportError:
    HAS_AZURE = False

try:
    import requests
except ImportError:
    HAS_REQUESTS = False

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

def get_network_client(endpoint, subscription_id, client_id, client_secret):
    log('getting auth token...')

    auth_token = get_token_from_client_credentials(
        endpoint,
        client_id,
        client_secret
    )

    log('creating credential object...')

    creds = SubscriptionCloudCredentials(subscription_id, auth_token)

    log('creating ARM client...')

    network_client = azure.mgmt.network.NetworkResourceProviderClient(creds)

    return network_client


def module_impl(resource_group, name, state, location, address_prefixes, subscription_id, auth_tenant_id, auth_endpoint, auth_client_id, auth_client_secret, check_mode):
    if not HAS_AZURE:
        raise Exception("The Azure python sdk is not installed (try 'pip install azure'")
    if not HAS_REQUESTS:
        raise Exception("The requests python module is not installed (try 'pip install requests'")

    #TODO: add automatic Microsoft.Network provider check/registration (only on failure?)
    results = dict(changed=False)

    # TODO: validate arg shape (CIDR blocks, etc)

    network_client = get_network_client(auth_endpoint, subscription_id, auth_client_id, auth_client_secret)

    try:
        log('fetching vnet...')
        vnet_resp = network_client.virtual_networks.get(resource_group, name)
        # TODO: check if resource_group.provisioningState != Succeeded or Deleting, equiv to 404 but blocks
        log('vnet exists...')
        vnet = vnet_resp.virtual_network
        if state == 'present':
            results['id'] = vnet.id # store this early in case of check mode (and only if requested state is present)
            log('validating address_prefixes...')
            existing_address_prefix_set = set(vnet.address_space.address_prefixes)
            requested_address_prefix_set = set(address_prefixes)
            missing_prefixes = requested_address_prefix_set - existing_address_prefix_set
            # TODO: handle removal (best-effort?)
            if(len(missing_prefixes) > 0):
                log('CHANGED: there are missing address_prefixes')
                results['changed'] = True
            # TODO: implement dns_servers

        elif state == 'absent':
            log("CHANGED: vnet exists but requested state is 'absent'")
            results['changed'] = True
    except AzureMissingResourceHttpError:
        log('vnet does not exist')
        if state == 'present':
            log("CHANGED: vnet does not exist but requested state is 'present'")
            results['changed'] = True

    if check_mode:
        log('check mode, exiting early')
        return results

    if results['changed']:
        if state == 'present':

            vnet = azure.mgmt.network.VirtualNetwork(
                location=location,
                address_space=azure.mgmt.network.AddressSpace(
                    address_prefixes=address_prefixes
                )
            )

            log('creating/updating vnet...')
            vnet_resp = network_client.virtual_networks.create_or_update(resource_group, name, vnet)
            # TODO: check response

            # TOOD: could optimize this away for change cases
            log('fetching vnet (post create/update)...')
            vnet_resp = network_client.virtual_networks.get(resource_group, name)

            vnet = vnet_resp.virtual_network
            results['id'] = vnet.id

        elif state == 'absent':
            log('deleting vnet...')
            vnet_resp = network_client.virtual_networks.delete(resource_group, name)
            # TODO: check response

    return results

def main():
    global log_path
    module = AnsibleModule(
        argument_spec = dict(
            resource_group = dict(required=True),
            name = dict(required=True),
            state = dict(default='present', choices=['present', 'absent']),
            location = dict(required=True),
            address_prefixes_cidr = dict(type='list', required=True),
            log_path = dict(default=None),

            # TODO: implement DNS servers
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

    # TODO: dict-ify module params and splat them directly
    res = module_impl(p.get('resource_group'), p.get('name'), p.get('state'), p.get('location'), p.get('address_prefixes_cidr'), subscription_id, auth_tenant_id, auth_endpoint, auth_client_id, auth_client_secret, module.check_mode)

    module.exit_json(**res)

from ansible.module_utils.basic import *
main()

