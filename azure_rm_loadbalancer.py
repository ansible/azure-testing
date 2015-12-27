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
import time

DOCUMENTATION = '''
---
module: azure_rm_loadbalancer
short_description: 
description:

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
    resource_group:
        description:
            - name of resource group.
        required: true
        default: null
    name:
        description:
            - name of the storage account.
        required: true
        default: null
    
    requirements:
        - "python >= 2.7"
        - "azure >= 1.0.2"
    author: "Chris Houseknecht @chouseknecht"
'''


HAS_AZURE = True
HAS_REQUESTS = True
LOG_PATH = "azure_rm_storageaccount.log"
NAME_PATTERN = re.compile(r"^[a-z0-9]+$")

try:
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
    from azure.mgmt.network.networkresourceprovider import FrontendIpConfiguration

except ImportError:
    HAS_AZURE = False

try:
    import requests
except ImportError:
    HAS_REQUESTS = False


def build_frontend_ip_configuration(config):
    if not config['private_ip_allocation_method'] in ('Static','Dynamic'):
        raise Exception('Parameter error: private_ip_allocation_method must be one of: Static, Dynamic')
        
    c = FrontendIpConfiguration()
    if config.get('id', None):
        c.id = config['id']
    if config.get('name', None):
        c.name = config['name']
    if config.get('etag', None):
        c.etag = config['etag']
    if config.get('provisioning_state', None):
        c.provisioning_state = config['provisioning_state']
    if 
        private_ip_address=config['private_ip_address'],
        private_ip_allocation_method=config['private_ip_allocation_method'],
        subnet = config['subnet'],
        public_ip_address = config['public_ip_address'],
        inbound_nat_rules = config['inbound_nat_rules'],
        load_balancing_rules = config['load_balancing_rules'],

        )
    return c


def module_impl(rm, log, params, check_mode=False):

    if not HAS_AZURE:
        raise Exception("The Azure python sdk is not installed (try 'pip install azure')")

    if not HAS_REQUESTS:
        raise Exception("The requests python module is not installed (try 'pip install requests')")

    resource_group = params.get('resource_group')
    lb_name = params.get('name')
    location = params.get('location')
    state = params.get('state')
    gather_facts = params.get('gather_facts')
    tags = params.get('tags')
    
    results = dict(changed=False)

    network_client = rm.get_network_client() 
    
    if not resource_group:
        raise Exception("Parameter error: resource_group cannot be None.")
    
    if not lb_name:
        raise Exception("Parameter error: name cannot be None.")
    
    results['name'] = lb_name
    results['resource_group'] = resource_group 

    try:
        if state == 'present' or gather_facts:
            # get facts
            pass
        elif state == 'absent':
            log('State absent for load balancer %s' % lb_name)
            results['changed'] = True

    except AzureMissingResourceHttpError:
        log('Load balancer %s does not exist' % lb_name)
        if state == 'present':
            results['changed'] = True

    if gather_facts:
        results['changed'] = False
        results['status'] = 'Succeeded'
        log('Stopping at gathering facts.')
        return results

    if state == 'present' and not results['changed']:
        # update the balancer

        log('Update load balancer %s.' % lb_name)

        return results
    
    elif state == 'present' and results['changed']:
        # create the load balancer

        log('Create load balancer %s.' % lb_name)

        if not location:
            raise Exception('Parameter error: location cannot be None when creating a load balancer.')
        
        results['location'] = location
        results['tags'] = {}
        if tags:
            results['tags'] = tags

        if check_mode:
            return results

        try:
            # create things
            pass
        except AzureHttpError as e:
            log('Error creating load balancer.')
            raise Exception(str(e.message))

    elif state == 'absent' and results['changed']:
        # delete

        log('Delete load balancer %s' % lb_name)
        
        if check_mode:
            return results

        try:
            # delete
            pass
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
            resource_group = dict(required=True, type='str'),
            name = dict(type='str'),
            state = dict(default='present', choices=['present', 'absent']),
            location = dict(type='str'),
            frontend_ip_configurations = dict(type='list')
            tags = dict(type='dict'),
            gather_facts = dict(type='bool', default=False),
            debug = dict(type='bool', default=False),
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
