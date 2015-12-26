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

short_description: Create, read, update, delete Azure network security groups.

description:
    - A Network security group (NSG) contains Access Control List (ACL) rules that allow\deny network traffic to subnets or individual
      network interfaces. An NSG is created with a set of default security rules and an empty set of security rules. Add rules to the
      empty set of security rules to allow or deny traffic flow.
    - Use this module to create and manage network security groups including adding security rules and modifying default rules. Add 
      and remove subnets and network interfaces. Use gather_facts to get facts for an existing group or gather_list to get facts for 
      all security groups within a resource group.
    - For authentication with Azure pass subscription_id, client_id, client_secret and tenant_id. Or, create a ~/.azure/credentials 
      file with one or more profiles. When using a credentials file, if no profile option is provided, Azure modules look for a 
      'default' profile. Each profile should include subscription_id, client_id, client_secret and tenant_id values.

options:
    profile:
        description:
            - security profile found in ~/.azure/credentials file
        required: false
        default: null
    subscription_id:
        description:
            - Azure subscription Id that owns the resource group and storage accounts.
        required: false
        default: null
    client_id:
        description:
            - Azure client_id used for authentication.
        required: false
        default: null
    client_secret:
        description:
            - Azure client_secrent used for authentication.
        required: false
        default: null
    tenant_id:
        description:
            - Azure tenant_id used for authentication.
        required: false
        default: null
    default_rules:
        description:
            - a list of default security rules. Each rule is a dictionary with the following keys: name, description, protocol, 
              source_port_range, destination_port_range, source_address_prefix, destination_address_prefix, access,
              priority and direction. See https://azure.microsoft.com/en-us/documentation/articles/virtual-networks-nsg/ for more
              details.
        required: false
        default: null
    gather_facts:
        description:
            - set to true to get information about an existing NSG.
        required: false
        default: null
    gather_list:
        description:
            - set to true to get information about all existing NSGs in a given resource group.
        required: false
        default: null
    location:
        description:
            - set to the value of an Azure region such as 'eastus'. Required when creating an NSG.
        required: false
        default: null
    name:
        description:
            - name of the NSG.
        required: true
        default: null
    network_interfaces:
        description:
            - a list of network interface Id values to associate with the NSG.
        required: false
        default: null
    purge_default_rules:
        description:
            - set to true if you want to remove all existing default security rules.
        required: true
        default: null
    purge_network_interfaces:
        description:
            - set to true if yo want to remove all existing network interfaces.
        required: true
        default: null
    purge_rules:
        description:
            - set to true if you want to remove all existing security rules.
        required: true
        default: null
    purge_subnets:
        description:
            - set to true if you want to remove all existing subnets.
        required: true
        default: null
    resource_group:
        description:
            - name of the resource group the NSG belongs to.
        required: true
        default: null
    rules:
        description:
            - a custom set of security rules. Each rule is a dictionary with the following keys: name, description, protocol, 
              source_port_range, destination_port_range, source_address_prefix, destination_address_prefix, access,
              priority and direction. See https://azure.microsoft.com/en-us/documentation/articles/virtual-networks-nsg/ for more
              details.
        required: true
        default: null
    state:
        description:
            - the state of the NSG. Set to 'present' to create or update an NSG. Set to 'absent' to remove an NSG.
        required: true
        default: null
    subnets:
        description:
            - a list of subnet Id values to associate with the NSG.
        required: false
        default: null
    tags:
        description:
            - dictionary of key/value pairs to associate with the NSG as metadata.
        required: false
        default: null

requirements:
    - "python >= 2.7"
    - "azure >= 1.0.2"

author: "Chris Houseknecht @chouseknecht"
'''

EXAMPLES = '''

# Create a security group
- azure_rm_securitygroup:
      resource_group: mygroup
      name: mysecgroup
      location: 'eastus'
      purge_rules: yes
      rules:
          - name: DenySSH
            protocol: TCP
            source_port_range: '*'
            source_address_prefix: '*'
            destination_address_prefix: '*'
            destination_port_range: 22
            access: Deny 
            priority: 100
            direction: Inbound 
          - name: 'AllowSSH'
            protocol: TCP
            source_port_range: '*' 
            source_address_prefix: '174.109.158.0/24'
            destination_address_prefix: '*'
            destination_port_range: 22
            access: Allow
            priority: 101
            direction: Inbound
      state: present

# Update rules on existing security group
- azure_rm_securitygroup:
      resource_group: mygroup
      name: mysecgroup
      location: 'eastus'
      rules:
          - name: DenySSH
            protocol: TCP
            source_port_range: '*' 
            source_address_prefix: '*'
            destination_address_prefix: '*'
            destination_port_range: 22-23
            access: Deny
            priority: 100
            direction: Inbound 
          - name: AllowSSHFromHome
            protocol: TCP
            source_port_range: '*' 
            source_address_prefix: '174.109.158.0/24'
            destination_address_prefix: '*'
            destination_port_range: 22-23
            access: Allow
            priority: 102
            direction: Inbound 
      state: present

# Delete security group
- azure_rm_securitygroup:
      resource_group: mygroup
      name: mysecgroup 
      state: absent

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

def create_rule_dict(rule):
    return dict(
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
    )

def create_rule_dict_from_obj(rule):
    return dict(
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
    )

def list_network_security_groups(resource_group, network_client):
    results = dict(
        changed = False,
        network_security_groups = []
    )
    try:
        response = network_client.network_security_groups.list(resource_group)
        for group in response.network_security_groups:
            g = dict()
            g['id'] = group.id
            g['name'] = group.name
            g['type'] = group.type
            g['location'] = group.location
            g['tags'] = group.tags
            g['rules'] = []
            for rule in group.security_rules:
                g['rules'].append(create_rule_dict_from_obj(rule))
            g['default_rules'] = []
            for rule in group.default_security_rules:
                g['default_rules'].append(create_rule_dict_from_obj(rule))
            g['network_interfaces'] = []
            for interface in group.network_interfaces:
                g['network_interfaces'].append(interface.id)
            g['subnets'] = []
            for subnet in group.subnets:
                g['subnets'].append(subnet.id)
            results['network_security_groups'].append(g)  
    except AzureHttpError as e:
            raise Exception(str(e.message))
    return results

def module_impl(rm, log, params, check_mode=False):

    if not HAS_AZURE:
        raise Exception("The Azure python sdk is not installed (try 'pip install azure')")

    if not HAS_REQUESTS:
        raise Exception("The requests python module is not installed (try 'pip install requests')")

    resource_group = params.get('resource_group')
    nsg_name = params.get('name')
    state = params.get('state')
    rules = params.get('rules')
    default_rules = params.get('default_rules')
    location = params.get('location')
    subnets = params.get('subnets')
    network_interfaces = params.get('network_interfaces')
    tags = params.get('tags')
    purge_rules = params.get('purge_rules')
    purge_default_rules = params.get('purge_default_rules')
    purge_subnets = params.get('purge_subnets')
    purge_network_interfaces = params.get('purge_network_interfaces')
    gather_facts = params.get('gather_facts')
    gather_list = params.get('gather_list')
    
    results = dict(changed=False)

    network_client = rm.get_network_client()

    if not resource_group:
        raise Exception("Parameter error: resource_group cannot be None.")
    
    if gather_list:
        # gather facts for all NSGs in a given resource group and get out
        return list_network_security_groups(resource_group, network_client)

    if not nsg_name:
        raise Exception("Parameter error: name cannot be None.")

    if not NAME_PATTERN.match(nsg_name):
        raise Exception("Parameter error: name must contain only word characters and '.','-','_'")
            
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
        if state == 'present' or gather_facts:
            # capture all the details now, so we can create a check_mode or gather_facts response
            results['id'] = response.network_security_group.id
            results['name'] = response.network_security_group.name
            results['type'] = response.network_security_group.type
            results['location'] = response.network_security_group.location
            results['tags'] = response.network_security_group.tags
            
            results['rules'] = []
            for rule in response.network_security_group.security_rules:
                results['rules'].append(create_rule_dict_from_obj(rule))

            results['default_rules'] = []
            for rule in response.network_security_group.default_security_rules:
                results['default_rules'].append(create_rule_dict_from_obj(rule))

            results['network_interfaces'] = []
            for interface in response.network_security_group.network_interfaces:
                results['network_interfaces'].append(interface.id)

            results['subnets'] = []
            for subnet in response.network_security_group.subnets:
                results['subnets'].append(subnet.id)
            
        elif state == 'absent':
            results['changed'] = True

    except AzureMissingResourceHttpError:
        if state == 'present':
            results['changed'] = True

    if gather_facts:
        results['changed'] = False
        results['status'] = 'Succeeded'
        return results

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
                    results['rules'].append(create_rule_dict(rule))
        if purge_rules:
            new_rules = []
            for rule in results['rules']:
                for r in rules:
                    if rule['name'] == r['name']:
                        new_rules.append(rule)
            results['rules'] = new_rules

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
                    results['default_rules'].append(create_rule_dict(rule))
        
        if purge_default_rules:
            new_default_rules = []
            for rule in results['default_rules']:
                for r in default_rules:
                    if rule['name'] == r['name']:
                        new_default_rules.append(rule)
            results['default_rules'] = new_default_rules


        if subnets:
            for subnet in subnets:
                matched = False
                for s in results['subnets']:
                    if subnet == s:
                        matched = True
                if not matched:
                    results['subnets'].append(subnet)
                    results['changed'] = True

        if purge_subnets:
            new_subnets = []
            for subnet in results['subnets']:
                for s in subnets:
                    if subnet == s:
                        new_subnets.append(subnet)
            results['subnets'] = new_subnets

        if network_interfaces:
            for interface in network_interfaces:
                matched = False
                for i in results['network_interfaces']:
                    if interface == i:
                        matched = True
                if not matched:
                    results['network_interfaces'].append(interface)
                    matched = True
        if purge_subnets:
            new_nics = []
            for interface in results['network_interfaces']:
                for i in network_interfaces:
                    if interface == i:
                        new_nics.append(interface)
            results['network_interfaces'] = new_nics

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
            # perform the update
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
                results['rules'].append(create_rule_dict(rule))
        if default_rules:
            for rule in default_rules:
                results['default_rules'].append(create_rule_dict(rule))
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
            results['tags'] = response.network_security_group.tags
            results['rules'] = []
            for rule in response.network_security_group.security_rules:
                results['rules'].append(create_rule_dict_from_obj(rule))
            results['default_rules'] = []
            for rule in response.network_security_group.default_security_rules:
                results['default_rules'].append(create_rule_dict_from_obj(rule))
            results['network_interfaces'] = []
            for interface in response.network_security_group.network_interfaces:
                results['network_interfaces'].append(interface.id)
            results['subnets'] = []
            for subnet in response.network_security_group.subnets:
                results['subnets'].append(subnet.id)
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
            profile = dict(type='str'),
            subscription_id = dict(type='str'),
            client_id = dict(type='str'),
            client_secret = dict(type='str'),
            tenant_id = dict(type='str'),
            default_rules = dict(type='list'),
            gather_facts = dict(type='bool', default=False),
            gather_list = dict(type='bool', default=False),
            location = dict(type='str'),
            name = dict(type='str'),
            network_interfaces = dict(type='list'),
            purge_default_rules = dict(type='bool', default=False),
            purge_network_interfaces = dict(type='bool', default=False),
            purge_rules = dict(type='bool', default=False),
            purge_subnets = dict(type='bool', default=False),
            resource_group = dict(required=True, type='str'),
            rules = dict(type='list'),
            state = dict(default='present', choices=['present', 'absent']),
            subnets = dict(type='list'),
            tags = dict(type='dict'),
        ),
        supports_check_mode=True
    )

    check_mode = module.check_mode
    debug = module.params.get('debug')

    if debug:
        log = azure_rm_log(LOG_PATH)
    else:
        log = azure_rm_log()
    
    try:
        rm = azure_rm_resources(module.params, log.log)
    except Exception as e:
        module.fail_json(msg=e.args[0])

    try:
        result = module_impl(rm, log.log, module.params, check_mode)
    except Exception as e:
        module.fail_json(msg=e.args[0])

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *

# Assumes running ansible from source and there is a copy or symlink for azure_rm_common
# found in local lib/ansible/module_utils
from ansible.module_utils.azure_rm_common import *

if __name__ == '__main__':
    main()
