#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2015 Chris Houseknecht, <chouse@ansible.com>
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

import ConfigParser
import os

from os.path import expanduser


DOCUMENTATION = '''
---
module: azure_rm_securitygroup
'''

HAS_AZURE = True
HAS_REQUESTS = True
LOG_PATH = "azure_rm_securitygroup.log"

try:
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
    from azure.mgmt.common import SubscriptionCloudCredentials
    from azure.mgmt.network.networkresourceprovider import NetworkSecurityGroup, SecurityRule
    import azure.mgmt.network
except ImportError:
    HAS_AZURE = False

try:
    import requests
except ImportError:
    HAS_REQUESTS = False


def log(msg):
    #    print msg
    if not LOG_PATH:
        return
    with open(LOG_PATH, "a") as logfile:
        logfile.write("{0}\n".format(msg))

def get_token_from_client_credentials(endpoint, client_id, client_secret):
    payload = {
        'grant_type': 'client_credentials',
        'client_id': client_id,
        'client_secret': client_secret,
        'resource': 'https://management.core.windows.net/',
    }
    try:
        response = requests.post(endpoint, data=payload).json()
        if 'error_description' in response:
           log('error: %s ' % response['error_description'])
           raise Exception('Failed getting OAuth token: %s' % response['error_description'])
    except Exception as e:
        raise Exception(e)

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

def get_credentials_parser():
    path = expanduser("~")    
    path += "/.azure/credentials"
    p = ConfigParser.ConfigParser()
    try:
        p.read(path)
    except:
        raise Exception("Failed to access %s. Check that the file exists and you have read access." % path)
    return p 
    

def parse_creds(profile="default"):
    parser = get_credentials_parser()
    creds = dict(
        subscription_id = "",
        client_id = "",
        client_secret = "",
        tenant_id = ""
    )
    for key in creds:
        try:
            creds[key] = parser.get(profile, key, raw=True)       
        except:
            raise Exception("Failed to get %s for profile %s in ~/.azure/credentials" % (key, profile))
    return creds

def get_env_creds():
    profile = os.environ.get('AZURE_PROFILE', None)
    subscription_id = os.environ.get('AZURE_SUBSCRIPTION_ID', None)
    client_id = os.environ.get('AZURE_CLIENT_ID', None)
    client_secret = os.environ.get('AZURE_CLIENT_SECRET', None)
    tenant_id = os.environ.get('AZURE_TENANT_ID', None)
    if profile:
        creds = parse_creds(profile)
        return creds 
    if subscription_id and client_id and client_secret and tenant_id:
        creds = dict(
            subscription_id = subscription_id,
            client_id = client_id,
            client_secret = client_secret,
            tenant_id = tenant_id
        )
        return creds
    return None

def get_credentials(params):
    # Get authentication credentials.
    # Precedence: module parameters-> environment variables-> default profile in ~/.azure/credentials.
    
    profile = params.get('profile')
    subscription_id = params.get('subscription_id')
    client_id = params.get('client_id')
    client_secret = params.get('client_id')
    tenant_id = params.get('tenant_id')

    # try module params
    if profile:
       creds = parse_creds(profile)
       return creds
    
    if subscription_id and client_id and client_secret and tenant_id:
       creds = dict(
           subscription_id = subscription_id,
           client_id = client_id,
           client_secret = client_secret,
           tenant_id = tenant_id
       )
       return creds
    
    # try environment
    env_creds = get_env_creds()
    if env_creds:
        return env_creds

    # try default profile from ~./azure/credentials
    creds = parse_creds()
    if creds:
        return creds

    return None

def validate_rule(r):
    if not r.get('name', None):
        raise Exception("rule name attribute cannot be None.")
    if not r.get('access', None):
        raise Exception("rule access attribute cannot be None.")
    if not r.get('priority', None):
        raise Exception("rule priority attribute cannot be None.")
    priority = r['priority']
    if not isinstance(priority,(int,long)):
        raise Exception("rule priority attribute must be an integer.")
    if not r.get('destination_address_prefix', None):
        raise Exception("rule destination_address_prefix attribute cannot be None.")
    if not r.get('source_address_prefix', None):
        raise Exception("rule source_address_prefix attribute cannot be None.")
    if not r.get('protocol', None):
        raise Exception("rule protocol attribute cannot be None.")
    if not r.get('direction', None):
        raise Exception("rule direction attribute cannot be None.")
    if not r.get('source_port_range', None):
        raise Exception("rule source_port_range attribute cannot be None")
    port = r['source_port_range']
    if port != '*' and not isinstance(port,(int,long)):
        raise Exception("rule source_port_range attribute must be '*' or an integer.")
    if not r.get('destination_port_range', None):
        raise Exception("rule destination_port_range attribute cannot be None")
    port = r['destination_port_range']
    if port != '*' and not isinstance(port,(int,long)):
        raise Exception("rule destination_port_range must be '*' or an integer.")


def compare_rules(r, rule):
    matched = False
    if r['name'] == rule['name']:
        matched = True
        if rule.get('description', None) != r['description']:
            matched = True
            r['description'] = rule['description']
        if rule['protocol'] != r['protocol']:
            matched = True
            r['protocol'] = rule['protocol']
        if rule['source_port_range'] != r['source_port_range']:
            matched = True
            r['source_port_range'] = rule['source_port_range']
        if rule['destination_port_range'] != r['destination_port_range']:
            matched = True
            r['destination_port_range'] = rule['destination_port_range']
        if rule['access'] != r['access']:
            matched = True
            r['access'] = rule['access']
        if rule['priority'] != r['priority']:
            matched = True
            r['priority'] = rule['priority']
        if rule['direction'] != r['direction']:
            matched = True
            r['direction'] = rule['direction']
    return matched

def create_rule_instance(rule):
    rule_instance = SecurityRule()
    rule_instance.name = rule['name']
    rule_instance.description = rule['description']
    rule_instance.protocol = rule['protocol']
    rule_instance.source_port_range = rule['source_port_range']
    rule_instance.destination_port_range = rule['destination_port_range']
    rule_instance.source_address_prefix = rule['source_address_prefix']
    rule_instance.destination_address_prefix = rule['destination_address_prefix']
    rule_instance.access = rule['access']
    rule_instance.priority = rule['priority']
    rule_instance.direction = rule['direction']
    return rule_instance


#def module_impl(resource_group, name, state, location, virtual_network_name, address_prefix_cidr, subscription_id, auth_tenant_id, auth_endpoint, auth_client_id, auth_client_secret, check_mode):
def module_impl(resource_group, nsg_name, state, location, rules, default_rules, creds, purge=False, check_mode=False):

    if not HAS_AZURE:
        raise Exception("The Azure python sdk is not installed (try 'pip install azure')")  
    if not HAS_REQUESTS:
        raise Exception("The requests python module is not installed (try 'pip install requests')")

    #TODO: add automatic Microsoft.Network provider check/registration (only on failure?)
    results = dict(changed=False)

    # TODO: validate arg shape (CIDR blocks, etc)
    
    log("client_id: %s" % creds['client_id'])
    log("client_secret: %s" % creds['client_secret'])
    log("subscripition_id: %s" % creds['subscription_id'])
    log("check_mode: %s" % check_mode)
    
    auth_endpoint = "https://login.microsoftonline.com/%s/oauth2/token" % creds['tenant_id']
    network_client = get_network_client(auth_endpoint, creds['subscription_id'], creds['client_id'], creds['client_secret'])

    if not resource_group:
        raise Exception("resource_group parameter cannot be None")
    
    if not nsg_name:
        raise Exception("name parameter cannot be None")
    
    if rules:
        try:
            for r in rules:
                validate_rule(r)
        except Exception as e:
            raise Exception("Error in rules: %s" % e.args[0])     

    if default_rules:
        try:
            for r in rules:
                validate_rule(r)       
        except Exception as e:
            raise Exception("Error in default rules: %s" % e.args[0])    
    try:
        response = network_client.network_security_groups.get(resource_group, nsg_name)
        if state == 'present':
            results['id'] = response.network_security_group.id
            results['name'] = response.network_security_group.name
            results['type'] = response.network_security_group.type
            results['location'] = response.network_security_group.location
            results['tags'] = response.network_security_group.tags
            
            results['rules'] = []
            for rule in response.network_security_group.security_rules:
                results['rules'].append(dict(
                    name = rule.name,
                    description = rule.description,
                    protocol = rule.protocol,
                    source_port_range = rule.source_port_range,
                    destination_port_range = rule.destination_port_range,
                    source_address_prefix = rule.source_address_prefix,
                    destination_address_prefix = rule.destination_address_prefix,
                    access = rule.access,
                    priority = rule.priority,
                    direction = rule.direction
                ))

            results['default_rules'] = []
            for rule in response.network_security_group.default_security_rules:
                results['default_rules'].append(dict(
                    name = rule.name,
                    description = rule.description,
                    protocol = rule.protocol,
                    source_port_range = rule.source_port_range,
                    destination_port_range = rule.destination_port_range,
                    source_address_prefix = rule.source_address_prefix,
                    destination_address_prefix = rule.destination_address_prefix,
                    access = rule.access,
                    priority = rule.priority,
                    direction = rule.direction
                ))

        elif state == 'absent':
            results['changed'] = True

    except AzureMissingResourceHttpError:
        if state == 'present':
            results['changed'] = True



    if state == 'present' and not results['changed']:
        # update the security group
        if rules:
            for rule in rules:
                matched = False
                for r in results['rules']:
                    matched = compare_rules(r, rule)
                    if matched:
                        results['changed'] = True

                if not matched:
                    results['changed'] = True
                    results['rules'].append(dict(
                        name = rule['name'],
                        description = rule.get('description', None),
                        protocol = rule['protocol'],
                        source_port_range = rule['source_port_range'],
                        destination_port_range = rule['destination_port_range'],
                        source_address_prefix = rule['source_address_prefix'],
                        destination_address_prefix = rule['destination_address_prefix'],
                        access = rule['access'],
                        priority = rule['priority'],
                        direction = rule['direction']
                    ))
        if default_rules:
            for rule in default_rules:
                matched = False
                for r in results['default_rules']:
                    matched = compare_rules(r, rule)
                    if matched:
                        results['changed'] = True
                        
                if not matched:
                    results['changed'] = True
                    results['default_rules'].append(dict(
                        name = rule['name'],
                        description = rule.get('description', None),
                        protocol = rule['protocol'],
                        source_port_range = rule['source_port_range'],
                        destination_port_range = rule['destination_port_range'],
                        source_address_prefix = rule['source_address_prefix'],
                        destination_address_prefix = rule['destination_address_prefix'],
                        access = rule['access'],
                        priority = rule['priority'],
                        direction = rule['direction']
                    ))
        
        if check_mode:
            return results

        try:
            parameters = NetworkSecurityGroup(default_security_rules=[], network_interfaces=[], security_rules=[], subnets=[], tags={})
            for rule in results['rules']:
                parameters.security_rules.append(create_rule_instance(rule))
            for rule in results['default_rules']:
                parameters.default_security_rules.append(create_rule_instance(rule))
            parameters.tags = results['tags']
            parameters.location = results['location']
            response = network_client.network_security_groups.begin_create_or_updating(resource_group, nsg_name, parameters)
        except AzureHttpError as e:
            raise Exception(e['body'])


    elif state == 'present' and results['changed']:
        # create the security group
        if not location:
            raise Exception("location cannot be None when creating a new security group.")

        results['name'] = nsg_name
        results['location'] = location
        
        if rules:
            results['rules'] = rules
        
        if default_rules:
            results['default_rules'] = default_rules

        if check_mode:
            return results

        try:
            parameters = {}
            if rules:
                parameters['security_rules'] = rules
            if default_rules:
                parameters['default_security_rules'] = default_rules

        except AzureHttpError as e:
            raise Exception(e.body)

        response = network_client.network_security_groups.begin_create_or_updating(resource_group, nsg_name, parameters)

        results[id] = response.network_security_group.id
        results[type] = response.network_security_group.type
       

    # try:
    #     log('fetching subnet...')
    #     subnet_resp = network_client.subnets.get(resource_group, virtual_network_name, name)
    #     # TODO: check if resource_group.provisioningState != Succeeded or Deleting, equiv to 404 but blocks
    #     log('subnet exists...')
    #     subnet = subnet_resp.subnet
    #     if state == 'present':
    #         results['id'] = subnet.id # store this early in case of check mode
    #     # TODO: validate args
    #         if subnet.address_prefix != address_prefix_cidr:
    #             log("CHANGED: subnet address range does not match")
    #             results['changed'] = True
    #     elif state == 'absent':
    #         log("CHANGED: subnet exists and state is 'absent'")
    #         results['changed'] = True
    # except AzureMissingResourceHttpError:
    #     log('subnet does not exist')
    #     if state == 'present':
    #         log("CHANGED: subnet does not exist and state is 'present'")
    #         results['changed'] = True

    # if check_mode:
    #     log('check mode, exiting early')
    #     return results

    # if results['changed']:
    #     if state == 'present':

    #         subnet = azure.mgmt.network.Subnet(
    #             address_prefix=address_prefix_cidr
    #         )
    #         log('creating/updating subnet...')
    #         subnet_resp = network_client.subnets.create_or_update(resource_group, virtual_network_name, name, subnet)
    #         # TODO: check response for success

    #         # TODO: optimize away in change case
    #         subnet_resp = network_client.subnets.get(resource_group, virtual_network_name, name)

    #         results['id'] = subnet_resp.subnet.id

    #     elif state == 'absent':
    #         log('deleting subnet...')
    #         subnet_resp = network_client.subnets.delete(resource_group, virtual_network_name, name)
    #         # TODO: check response

    return results

def main():
    module = AnsibleModule(
        argument_spec=dict(
            profile = dict(required=False, type='str'),
            subscription_id = dict(required=False, type='str'),
            client_id = dict(required=False, type='str'),
            client_secret = dict(required=False, type='str'),
            tenant_id = dict(required=False, type='str'),
            resource_group = dict(required=True, type='str'),
            name = dict(required=True, type='str'),
            state = dict(default='present', choices=['present', 'absent']),
            location = dict(required=False, type='str'),
            purge = dict(required=False, type='bool', default=False),
            rules = dict(required=False, type='list'),
            default_rules = dict(required=False, type='list'),
        ),
        supports_check_mode=True
    )

    resource_group = module.params.get('resource_group')
    nsg_name = module.params.get('name')
    state = module.params.get('state')
    rules = module.params.get('rules')
    default_rules = module.params.get('default_rules')
    purge = module.params.get('purge')
    location = module.params.get('location')
    check_mode = module.check_mode

    creds = get_credentials(module.params)
    if not creds:
        module.fail_json(msg="Failed to get credentials. Either pass as parameters, set environment variables, or define a profile in ~/.azure/credientials.")
    
    try:
        result = module_impl(resource_group, nsg_name, state, location, rules, default_rules, creds, purge, check_mode)
    except Exception as e:
        module.fail_json(msg=e.args[0])

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *  # noqa

if __name__ == '__main__':
    main()
