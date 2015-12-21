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
module: azure_rm_storageaccount
'''

HAS_AZURE = True
HAS_REQUESTS = True
LOG_PATH = "azure_rm_storageaccount.log"
NAME_PATTERN = re.compile(r"^[a-z0-9]+$")

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


def module_impl(rm, log, params, check_mode=False):

    if not HAS_AZURE:
        raise Exception("The Azure python sdk is not installed (try 'pip install azure')")

    if not HAS_REQUESTS:
        raise Exception("The requests python module is not installed (try 'pip install requests')")

    resource_group = params.get('resource_group')
    account_name = params.get('name')
    state = params.get('state')
    gather_facts = params.get('gather_facts')
    gather_list = params.get('gather_list')
    
    results = dict(changed=False)

    storage_client = rm.get_storage_client() 
    
    if not resource_group:
        raise Exception("Parameter error: resource_group cannot be None.")
    
    #if gather_list:
        # gather facts for all NSGs in a given resource group and get out
        #return list_network_security_groups(resource_group, network_client)

    if not account_name:
        raise Exception("Parameter error: name cannot be None.")

    if not NAME_PATTERN.match(account_name):
        raise Exception("Parameter error: name must contain only word characters and '.','-','_'")
            
    try:
        if state == 'present' or gather_facts:
            response = storage_client.storage_accounts.get_properties(resource_group, account_name)
            results['id'] = response.storage_account.id
            results['name'] = response.storage_account.name
            results['location'] = response.storage_account.location
            results['type'] = response.storage_account.type
            results['account_type'] = response.storage_account.account_type
            results['provisioning_state'] = response.storage_account.provisioning_state
            results['custom_domain'] = response.storage_account.custom_domain
            #results['primary_endpoints'] = response.storage_account.primary_endpoints
            #results['primary_location'] = response.storage_account.primary_location
            #results['secondary_endpoints'] = response.storage_account.secondary_endpoints
            #results['secondary_location'] = response.storage_account.secondary_location
            #results['status_of_primary'] = response.storage_account.status_of_primary
            #results['status_of_secondary'] = response.storage_account.status_of_secondary
            results['tags'] = response.storage_account.tags
        elif state == 'absent':
            results['changed'] = True

    except AzureMissingResourceHttpError:
        if state == 'present':
            results['changed'] = True

    if gather_facts:
        results['changed'] = False
        results['status'] = 'Succeeded'
        return results

    # if state == 'present' and not results['changed']:
    #     # update the security group
    #     log('Update security group %s' % nsg_name)
        
    #     if rules:
    #         for rule in rules:
    #             rule_matched = False
    #             for r in results['rules']:
    #                 match, changed = compare_rules(r, rule)
    #                 if changed:
    #                     results['changed'] = True
    #                 if match:
    #                     rule_matched = True

    #             if not rule_matched:
    #                 results['changed'] = True
    #                 results['rules'].append(create_rule_dict(rule))
    #     if purge_rules:
    #         new_rules = []
    #         for rule in results['rules']:
    #             for r in rules:
    #                 if rule['name'] == r['name']:
    #                     new_rules.append(rule)
    #         results['rules'] = new_rules

    #     if default_rules:
    #         for rule in default_rules:
    #             rule_matched = False
    #             for r in results['default_rules']:
    #                 match, changed = compare_rules(r, rule)
    #                 if changed:
    #                     results['changed'] = True
    #                 if match:
    #                     rule_matchd = True    
    #             if not rule_matched:
    #                 results['changed'] = True
    #                 results['default_rules'].append(create_rule_dict(rule))
        
    #     if purge_default_rules:
    #         new_default_rules = []
    #         for rule in results['default_rules']:
    #             for r in default_rules:
    #                 if rule['name'] == r['name']:
    #                     new_default_rules.append(rule)
    #         results['default_rules'] = new_default_rules


    #     if subnets:
    #         for subnet in subnets:
    #             matched = False
    #             for s in results['subnets']:
    #                 if subnet == s:
    #                     matched = True
    #             if not matched:
    #                 results['subnets'].append(subnet)
    #                 results['changed'] = True

    #     if purge_subnets:
    #         new_subnets = []
    #         for subnet in results['subnets']:
    #             for s in subnets:
    #                 if subnet == s:
    #                     new_subnets.append(subnet)
    #         results['subnets'] = new_subnets

    #     if network_interfaces:
    #         for interface in network_interfaces:
    #             matched = False
    #             for i in results['network_interfaces']:
    #                 if interface == i:
    #                     matched = True
    #             if not matched:
    #                 results['network_interfaces'].append(interface)
    #                 matched = True
    #     if purge_subnets:
    #         new_nics = []
    #         for interface in results['network_interfaces']:
    #             for i in network_interfaces:
    #                 if interface == i:
    #                     new_nics.append(interface)
    #         results['network_interfaces'] = new_nics

    #     if tags:
    #         for tag_key in tags:
    #             if results['tags'].get(tag_key, None):
    #                 if results['tags'][tag_key] != tags[tag_key]:
    #                     results['changed'] = True
    #                     results['tags'][tag_key] = tags[tag_key]
    #             else:
    #                 results['changed'] = True
    #                 results['tags'][tag_key] = tags[tag_key]


    #     if location and location != results['location']:
    #         results['changed'] = True
    #         results['location'] = location

    #     if check_mode:
    #         return results

    #     try:
    #         # perform the update
    #         parameters = NetworkSecurityGroup(default_security_rules=[], network_interfaces=[], security_rules=[], subnets=[], tags={})
    #         for rule in results['rules']:
    #             rule_inst = create_rule_instance(rule)
    #             parameters.security_rules.append(rule_inst)
    #         for rule in results['default_rules']:
    #             rule_inst = create_rule_instance(rule)
    #             parameters.default_security_rules.append(rule_inst)
    #         for subnet in results['subnets']:
    #             parameters.subnets.append(ResourceId(id=subnet))
    #         for interface in results['network_interfaces']:
    #             parameters.network_interfaces.append(ResourceId(id=interface))
    #         parameters.tags = results['tags']
    #         parameters.location = results['location']
    #         parameters.type = results['type']
    #         parameters.id = results['id']
    #         response = network_client.network_security_groups.create_or_update(resource_group, nsg_name, parameters)
    #         results['status'] = response.status
    #     except AzureHttpError as e:
    #         raise Exception(str(e.message))


    # elif state == 'present' and results['changed']:
    #     # create the security group
    #     log('Create security group %s' % nsg_name)
        
    #     if not location:
    #         raise Exception("location cannot be None when creating a new security group.")

    #     results['name'] = nsg_name
    #     results['location'] = location
    #     results['rules'] = []
    #     results['default_rules'] = []
    #     results['subnets'] = []
    #     results['network_interfaces'] = []
    #     results['tags'] = []

    #     if rules:
    #         for rule in rules:
    #             results['rules'].append(create_rule_dict(rule))
    #     if default_rules:
    #         for rule in default_rules:
    #             results['default_rules'].append(create_rule_dict(rule))
    #     if subnets:
    #         results['subnets'] = subnets
    #     if network_interfaces:
    #         results['network_interfaces'] = network_interfaces
    #     if tags:
    #         results['tags'] = tags

    #     if check_mode:
    #         return results

    #     try:
    #         parameters = NetworkSecurityGroup(default_security_rules=[], network_interfaces=[], security_rules=[], subnets=[], tags={})
    #         for rule in results['rules']:
    #             rule_inst = create_rule_instance(rule)
    #             parameters.security_rules.append(rule_inst)
    #         for rule in results['default_rules']:
    #             rule_inst = create_rule_instance(rule)
    #             parameters.default_security_rules.append(rule_inst)
    #         for subnet in results['subnets']:
    #             parameters.subnets.append(ResourceId(id=subnet))
    #         for interface in results['network_interfaces']:
    #             parameters.network_interfaces.append(ResourceId(id=interface))
    #         parameters.tags = results['tags']
    #         parameters.location = results['location']
    #         response = network_client.network_security_groups.create_or_update(resource_group, nsg_name, parameters)
    #         results['status'] = response.status
    #     except AzureHttpError as e:
    #         raise Exception(str(e.message))

    #     try:
    #         # The above should create the security group, but it does not actually return the security group object.
    #         # Retrieve the object so that we can include the new ID in results.
    #         response = network_client.network_security_groups.get(resource_group, nsg_name)
    #         results['id'] = response.network_security_group.id
    #     except AzureHttpError as e:
    #         raise Exception(str(e.message))

    # elif state == 'absent' and results['changed']:
    #     log('Delete security group %s' % nsg_name)
        
    #     if check_mode:
    #         return results

    #     try:
    #         response = network_client.network_security_groups.delete(resource_group, nsg_name)
    #         results['status'] = response.status
    #     except  AzureHttpError as e:
    #         raise Exception(str(e.message))

    return results

def main():
    module = AnsibleModule(
        argument_spec=dict(
            profile = dict(type='str'),
            subscription_id = dict(type='str'),
            client_id = dict(type='str'),
            client_secret = dict(type='str'),
            tenant_id = dict(type='str'),
            resource_group = dict(required=True, type='str'),
            name = dict(type='str'),
            state = dict(default='present', choices=['present', 'absent']),
            location = dict(type='str'),
            tags = dict(type='list'),
            gather_facts = dict(type='bool', default=False),
            gather_list = dict(type='bool', default=False),
            debug = dict(type='bool', default=False)
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
