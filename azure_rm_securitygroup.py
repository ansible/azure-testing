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
import json 
import os
from os.path import expanduser
import re


DOCUMENTATION = '''
---
module: azure_rm_securitygroup
'''

HAS_AZURE = True
HAS_REQUESTS = True
LOG_PATH = "azure_rm_securitygroup.log"
NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")

try:
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
    from azure.mgmt.common import SubscriptionCloudCredentials
    from azure.mgmt.network.networkresourceprovider import NetworkSecurityGroup, SecurityRule, ResourceId
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

def validate_rule(r, type=None):
    name = r.get('name', None)
    if not name:
        raise Exception("rule name attribute cannot be None.")
    if not NAME_PATTERN.match(name):
        raise Exception("rule name must contain only word characters plus '.','-','_'")
    
    access = r.get('access', None)
    if not access:
        raise Exception("rule access attribute cannot be None.")
    if access not in ['Allow', 'Deny']:
        raise Excpetion("rule access must be one of 'Allow', 'Deny'")

    priority = r.get('priority',None)
    if not priority:
        raise Exception("rule priority attribute cannot be None.")
    if not isinstance(priority,(int,long)):
        raise Exception("rule priority attribute must be an integer.")
    if type != 'default' and (priority < 100 or priority > 4096):
        raise Exception("rule priority must be between 100 and 4096")
    
    if not r.get('destination_address_prefix', None):
        raise Exception("rule destination_address_prefix attribute cannot be None.")
    if not r.get('source_address_prefix', None):
        raise Exception("rule source_address_prefix attribute cannot be None.")
    if not r.get('protocol', None):
        raise Exception("rule protocol attribute cannot be None.")
    
    direction = r.get('direction', None)
    if not direction:
        raise Exception("rule direction attribute cannot be None.")
    if not direction in ['Inbound','Outbound']:
        raise Exception("rule direction must be one of 'Inbound', 'Outbound'")
    
    if not r.get('source_port_range', None):
        raise Exception("rule source_port_range attribute cannot be None")
    if not r.get('destination_port_range', None):
        raise Exception("rule destination_port_range attribute cannot be None")
    

def compare_rules(r, rule):
    matched = False
    changed = False
    if r['name'] == rule['name']:
        matched = True
        if rule.get('description', None) != r['description']:
            changed = True
            r['description'] = rule['description']
        if rule['protocol'] != r['protocol']:
            changed = True
            r['protocol'] = rule['protocol']
        if rule['source_port_range'] != r['source_port_range']:
            changed = True
            r['source_port_range'] = rule['source_port_range']
        if rule['destination_port_range'] != r['destination_port_range']:
            changed = True
            r['destination_port_range'] = rule['destination_port_range']
        if rule['access'] != r['access']:
            changed = True
            r['access'] = rule['access']
        if rule['priority'] != r['priority']:
            changed = True
            r['priority'] = rule['priority']
        if rule['direction'] != r['direction']:
            changed = True
            r['direction'] = rule['direction']
    return (matched, changed)

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


def module_impl(resource_group, nsg_name, state, location, rules, default_rules, subnets, network_interfaces, tags, creds, purge=False, check_mode=False):

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

    if not NAME_PATTERN.match(nsg_name):
        raise Exception("Security group name must contain only word characters plus '.','-','_'")
            
    if rules:
        try:
            for r in rules:
                validate_rule(r)
        except Exception as e:
            raise Exception("Error in rules: %s" % e.args[0])     

    if default_rules:
        try:
            for r in rules:
                validate_rule(r,'default')       
        except Exception as e:
            raise Exception("Error in default rules: %s" % e.args[0])    
    try:
        response = network_client.network_security_groups.get(resource_group, nsg_name)
        if state == 'present':
            # capture all the details now, so we can create a check_mode response
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

            results['network_interfaces'] = []
            for interface in response.network_security_group.network_interfaces:
                results['network_interfaces'].append(interface.id)
            log('%d existing network interfaces' % len(results['network_interfaces']))

            results['subnets'] = []
            for subnet in response.network_security_group.subnets:
                results['subnets'].append(subnet.id)
                log('existing subnet id: %s' % subnet.id)
            log('%d existing subnets' % len(results['subnets']))

        elif state == 'absent':
            results['changed'] = True

    except AzureMissingResourceHttpError:
        if state == 'present':
            results['changed'] = True



    if state == 'present' and not results['changed']:
        # update the security group
        log('Update security group %s' % nsg_name)
        
        if rules:
            for rule in rules:
                rule_matched = False
                for r in results['rules']:
                    match, changed = compare_rules(r, rule)
                    if changed:
                        results['changed'] = True
                    if match:
                        rule_matched = True

                if not rule_matched:
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
                rule_matched = False
                for r in results['default_rules']:
                    match, changed = compare_rules(r, rule)
                    if changed:
                        results['changed'] = True
                    if match:
                        rule_matchd = True    
                if not rule_matched:
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

        if subnets:
            for subnet in subnets:
                matched = False
                for s in results['subnets']:
                    if subnet == s:
                        matched = True
                if not matched:
                    results['subnets'].append(subnet)
                    results['changed'] = True

        if network_interfaces:
            for interface in network_interfaces:
                matched = False
                for i in results['network_interfaces']:
                    if interface == i:
                        matched = True
                if not matched:
                    results['network_interfaces'].append(interface)
                    matched = True

        if tags:
            for tag_key in tags:
                if results['tags'].get(tag_key, None):
                    if results['tags'][tag_key] != tags[tag_key]:
                        results['changed'] = True
                        results['tags'][tag_key] = tags[tag_key]
                else:
                    results['changed'] = True
                    results['tags'][tag_key] = tags[tag_key]


        if location and location != results['location']:
            results['changed'] = True
            results['location'] = location

        if check_mode:
            return results

        try:
            parameters = NetworkSecurityGroup(default_security_rules=[], network_interfaces=[], security_rules=[], subnets=[], tags={})
            for rule in results['rules']:
                rule_inst = create_rule_instance(rule)
                parameters.security_rules.append(rule_inst)
            for rule in results['default_rules']:
                rule_inst = create_rule_instance(rule)
                parameters.default_security_rules.append(rule_inst)
            for subnet in results['subnets']:
                parameters.subnets.append(ResourceId(id=subnet))
            for interface in results['network_interfaces']:
                parameters.network_interfaces.append(ResourceId(id=interface))
            parameters.tags = results['tags']
            parameters.location = results['location']
            parameters.type = results['type']
            parameters.id = results['id']
            response = network_client.network_security_groups.create_or_update(resource_group, nsg_name, parameters)
            results['status'] = response.status
        except AzureHttpError as e:
            raise Exception(str(e.message))


    elif state == 'present' and results['changed']:
        # create the security group
        log('Create security group %s' % nsg_name)
        
        if not location:
            raise Exception("location cannot be None when creating a new security group.")

        results['name'] = nsg_name
        results['location'] = location
        results['rules'] = []
        results['default_rules'] = []
        results['subnets'] = []
        results['network_interfaces'] = []
        results['tags'] = []

        if rules:
            for rule in rules:
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
        if subnets:
            results['subnets'] = subnets
        if network_interfaces:
            results['network_interfaces'] = network_interfaces
        if tags:
            results['tags'] = tags

        if check_mode:
            return results

        try:
            parameters = NetworkSecurityGroup(default_security_rules=[], network_interfaces=[], security_rules=[], subnets=[], tags={})
            for rule in results['rules']:
                rule_inst = create_rule_instance(rule)
                parameters.security_rules.append(rule_inst)
            for rule in results['default_rules']:
                rule_inst = create_rule_instance(rule)
                parameters.default_security_rules.append(rule_inst)
            for subnet in results['subnets']:
                parameters.subnets.append(ResourceId(id=subnet))
            for interface in results['network_interfaces']:
                parameters.network_interfaces.append(ResourceId(id=interface))
            parameters.tags = results['tags']
            parameters.location = results['location']
            response = network_client.network_security_groups.create_or_update(resource_group, nsg_name, parameters)
            results['status'] = response.status
        except AzureHttpError as e:
            raise Exception(str(e.message))

        try:
            # The above should create the security group, but it does not actually return the security group object.
            # Retrieve the object so that we can include the new ID in results.
            response = network_client.network_security_groups.get(resource_group, nsg_name)
            results['id'] = response.network_security_group.id
        except AzureHttpError as e:
            raise Exception(str(e.message))

    elif state == 'absent' and results['changed']:
        log('Delete security group %s' % nsg_name)
        
        if check_mode:
            return results

        try:
            response = network_client.network_security_groups.delete(resource_group, nsg_name)
            results['status'] = response.status
        except  AzureHttpError as e:
            raise Exception(str(e.message))

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
            subnets = dict(required=False, type='list'),
            network_interfaces = dict(required=False, type='list'),
            tags = dict(required=False, type='list'),
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
    subnets = module.params.get('subnets')
    network_interfaces = module.params.get('network_interfaces')
    tags = module.params.get('tags')
    check_mode = module.check_mode

    try:
        creds = get_credentials(module.params)
    except Exception as e:
        module.fail_json(msg=e.args[0])

    if not creds:
        module.fail_json(msg="Failed to get credentials. Either pass as parameters, set environment variables, or define a profile in ~/.azure/credientials.")
    
    try:
        result = module_impl(resource_group, nsg_name, state, location, rules, default_rules, subnets, network_interfaces, tags, creds, purge, check_mode)
    except Exception as e:
        module.fail_json(msg=e.args[0])

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *  # noqa

if __name__ == '__main__':
    main()
