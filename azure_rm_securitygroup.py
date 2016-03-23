#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2016 Chris Houseknecht, <chouseknecht@ansible.com>
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

import re

# normally we'd put this at the bottom to preserve line numbers, but we can't use a forward-defined base class
# without playing games with __metaclass__ or runtime base type hackery.
# TODO: figure out a better way...
from ansible.module_utils.basic import *

# Assumes running ansible from source and there is a copy or symlink for azure_rm_common
# found in local lib/ansible/module_utils
from ansible.module_utils.azure_rm_common import *

from azure.common import AzureMissingResourceHttpError, AzureHttpError
from azure.mgmt.network.models import NetworkSecurityGroup, SecurityRule, Subnet, NetworkInterface
from azure.mgmt.network.models.network_management_client_enums import (SecurityRuleAccess,
                                                                       SecurityRuleDirection,
                                                                       SecurityRuleProtocol)


DOCUMENTATION = '''
---
module: azure_rm_securitygroup

short_description: Manage Azure network security groups.

description:
    - A Network security group (NSG) contains Access Control List (ACL) rules that allow\deny network traffic to
      subnets or individual network interfaces. An NSG is created with a set of default security rules and an empty
      set of security rules. Add rules to the empty set of security rules to allow or deny traffic flow.
    - Use this module to create and manage network security groups including adding security rules and
      modifying default rules. Add and remove subnets and network interfaces.
    - For authentication with Azure pass subscription_id, client_id, client_secret and tenant_id. Or, create a
      ~/.azure/credentials file with one or more profiles. When using a credentials file, if no profile option is
      provided, Azure modules look for a 'default' profile. Each profile should include subscription_id, client_id,
      client_secret and tenant_id values.

options:
    profile:
        description:
            - security profile found in ~/.azure/credentials file
        default: null
    subscription_id:
        description:
            - Azure subscription Id that owns the resource group and storage accounts.
        default: null
    client_id:
        description:
            - Azure client_id used for authentication.
        default: null
    secret:
        description:
            - Azure client_secrent used for authentication.
        default: null
    tenant:
        description:
            - Azure tenant_id used for authentication.
        default: null
    default_rules:
        description:
            - List of default security rules where each rule is a dictionary with the following keys: name,
              description, protocol, source_port_range, destination_port_range, source_address_prefix,
              destination_address_prefix, access, priority and direction.
              See https://azure.microsoft.com/en-us/documentation/articles/virtual-networks-nsg/ for more details.
        default: null
    location:
        description:
            - set to the value of an Azure region such as 'eastus'. Required when creating an NSG.
        default: null
    name:
        description:
            - name of the NSG.
        default: null
    network_interfaces:
        description:
            - a list of network interface Id values to associate with the NSG.
        default: null
    purge_default_rules:
        description:
            - Remove existing default security rules.
        default: false
    purge_network_interfaces:
        description:
            - Remove existing network interfaces.
        default: false
    purge_rules:
        description:
            - Remove existing security rules.
        default: false
    purge_subnets:
        description:
            - Remove existing subnets.
        default: false
    resource_group:
        description:
            - Name of the resource group the NSG belongs to.
        required: true
        default: null
    rules:
        description:
            - A set of rules where each rule is a dictionary with the following keys: name, description, protocol, 
              source_port_range, destination_port_range, source_address_prefix, destination_address_prefix, access,
              priority and direction.
              See https://azure.microsoft.com/en-us/documentation/articles/virtual-networks-nsg/ for more details.
        required: true
        default: null
    state:
        description:
            - State of the NSG. Set to 'present' to create or update an NSG. Set to 'absent' to remove an NSG.
        required: true
        default: present
    subnets:
        description:
            - List of subnet Id values to associate with the NSG.
        required: false
        default: null
    tags:
        description:
            - Dictionary of key/value pairs to associate with the NSG as metadata.
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

NAME_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


def validate_rule(rule, rule_type=None):
    rule_name = rule.get('name', None)
    if not rule_name:
        raise Exception("Rule name value is required.")
    if not NAME_PATTERN.match(rule_name):
        raise Exception("Rule name must contain only word characters plus '.','-','_'")
    
    access = rule.get('access', None)
    if not access:
        raise Exception("Rule access value is required.")
    if access not in SecurityRuleAccess:
        names = [member.name for member in SecurityRuleAccess]
        raise Exception("Rule access must be one of {0}".format(','.join(names)))

    priority = rule.get('priority', None)
    if not priority:
        raise Exception("Rule priority is required.")
    if not isinstance(priority, (int, long)):
        raise Exception("Rule priority attribute must be an integer.")
    if rule_type != 'default' and (priority < 100 or priority > 4096):
        raise Exception("Rule priority must be between 100 and 4096")
    
    if not rule.get('destination_address_prefix', None):
        raise Exception("Rule destination_address_prefix value is required.")
    if not rule.get('source_address_prefix', None):
        raise Exception("Rule source_address_prefix value is required.")

    protocol = rule.get('protocol', None)
    if not protocol:
        raise Exception("Rule protocol value is required.")
    if protocol not in SecurityRuleProtocol:
        names = [member.name for member in SecurityRuleProtocol]
        raise Exception("Rule protocol must be one of {0}".format(','.join(names)))
    
    direction = rule.get('direction', None)
    if not direction:
        raise Exception("rule direction is required.")
    if direction not in SecurityRuleDirection:
        names = [member.name for member in SecurityRuleDirection]
        raise Exception("Rule direction must be one of {0}".format(','.join(names)))
    
    if not rule.get('source_port_range', None):
        raise Exception("Rule source_port_range value is required.")

    if not rule.get('destination_port_range', None):
        raise Exception("Rule destination_port_range value is required")


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
    return matched, changed


def create_rule_instance(rule):
    return SecurityRule(
        rule['protocol'],
        rule['source_address_prefix'],
        rule['destination_address_prefix'],
        rule['access'],
        rule['direction'],
        id=rule.get('id', None),
        description=rule.get('description', None),
        source_port_range=rule.get('source_port_range', None),
        destination_port_range=rule.get('destination_port_range', None),
        priority=rule.get('priority', None),
        provisioning_state=rule.get('provisioning_state', None),
        name=rule.get('name', None), 
        etag=rule.get('etag', None)
    )


def create_rule_dict_from_obj(rule):
    return dict(
        id=rule.id,
        name=rule.name,
        description=rule.description,
        protocol=rule.protocol,
        source_port_range=rule.source_port_range,
        destination_port_range=rule.destination_port_range,
        source_address_prefix=rule.source_address_prefix,
        destination_address_prefix=rule.destination_address_prefix,
        access=rule.access,
        priority=rule.priority,
        direction=rule.direction,
        provisioning_state=rule.provisioning_state,
        etag=rule.etag
    )


def create_network_security_group_dict(nsg):
    results = dict(
        id=nsg.id,
        name=nsg.name,
        type=nsg.type,
        location=nsg.location,
        tags=nsg.tags,    
    )
    results['rules'] = []
    for rule in nsg.security_rules:
        results['rules'].append(create_rule_dict_from_obj(rule))

    results['default_rules'] = []
    for rule in nsg.default_security_rules:
        results['default_rules'].append(create_rule_dict_from_obj(rule))

    results['network_interfaces'] = []
    for interface in nsg.network_interfaces:
        results['network_interfaces'].append(interface.id)

    results['subnets'] = []
    for subnet in nsg.subnets:
        results['subnets'].append(subnet.id)

    return results


class AzureRMSecurityGroup(AzureRMModuleBase):
    def __init__(self, **kwargs):
        module_arg_spec = dict(
            default_rules=dict(type='list'),
            location=dict(type='str'),
            name=dict(type='str', required=True),

            # TODO: move nic/subnet association to those resources, otherwise we can't do one-shot deletion/update

            network_interfaces=dict(type='list'),
            subnets=dict(type='list'),
            purge_network_interfaces=dict(type='bool', default=False),
            purge_subnets=dict(type='bool', default=False),
            purge_default_rules=dict(type='bool', default=False),
            purge_rules=dict(type='bool', default=False),
            resource_group=dict(required=True, type='str'),
            rules=dict(type='list'),
            state=dict(default='present', choices=['present', 'absent']),
            tags=dict(type='dict')
        )

        super(AzureRMSecurityGroup, self).__init__(derived_arg_spec=module_arg_spec,
                                                   supports_check_mode=True,
                                                   **kwargs)
        
        self.default_rules = None
        self.location = None
        self.name = None
        self.network_interfaces = None
        self.subnets = None
        self.purge_network_interfaces = None
        self.purge_default_rules = None
        self.purge_rules = None
        self.purge_subnets = None
        self.resource_group = None
        self.rules = None
        self.state = None
        self.tags = None

        self.results = dict(
            changed=False,
            results=()
        )
        
    def exec_module_impl(self, **kwargs):
        
        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        changed = False
        results = dict()

        if not NAME_PATTERN.match(name):
            raise Exception("Parameter error: name must contain only word characters and '.','-','_'")

        if self.tags:
            self.validate_tags(self.tags)

        if self.rules:
            for rule in self.rules:
                try:
                    validate_rule(rule)
                except Exception, exc:
                    self.fail("Error validating rule {0} - {1}".format(rule, str(exc)))

        if self.default_rules:
            for rule in self.default_rules:
                try:
                    validate_rule(rule, 'default')
                except Exception, exc:
                    self.fail("Error validating dfault rule {0} - {1}".format(rule, str(exc)))

        try:
            nsg = self.network_client.network_security_groups.get(resource_group, name)
            if self.state == 'present':
                results = create_network_security_group_dict(nsg)

            elif self.state == 'absent':
                changed = True
        except AzureMissingResourceHttpError:
            if self.state == 'present':
                changed = True

        if self.state == 'present' and not changed:
            # update the security group
            self.log("Update security group {0}".format(name))

            if self.rules:
                for rule in self.rules:
                    rule_matched = False
                    for r in results['rules']:
                        match, changed = compare_rules(r, rule)
                        if changed:
                            changed = True
                        if match:
                            rule_matched = True

                    if not rule_matched:
                        changed = True
                        results['rules'].append(rule)

            if self.purge_rules:
                new_rules = []
                for rule in results['rules']:
                    for r in self.rules:
                        if rule['name'] == r['name']:
                            new_rules.append(rule)
                results['rules'] = new_rules

            if self.default_rules:
                for rule in self.default_rules:
                    rule_matched = False
                    for r in results['default_rules']:
                        match, changed = compare_rules(r, rule)
                        if changed:
                            changed = True
                        if match:
                            rule_matched = True
                    if not rule_matched:
                        changed = True
                        results['default_rules'].append(rule)

            if self.purge_default_rules:
                new_default_rules = []
                for rule in results['default_rules']:
                    for r in self.default_rules:
                        if rule['name'] == r['name']:
                            new_default_rules.append(rule)
                results['default_rules'] = new_default_rules

            if self.subnets:
                for subnet in self.subnets:
                    matched = False
                    for s in results['subnets']:
                        if subnet == s:
                            matched = True
                    if not matched:
                        results['subnets'].append(subnet)
                        changed = True

            if self.purge_subnets:
                new_subnets = []
                for subnet in self.results['subnets']:
                    for s in self.subnets:
                        if subnet == s:
                            new_subnets.append(subnet)
                results['subnets'] = new_subnets

            if self.network_interfaces:
                for interface in self.network_interfaces:
                    matched = False
                    for i in results['network_interfaces']:
                        if interface == i:
                            matched = True
                    if not matched:
                        results['network_interfaces'].append(interface)
                        changed = True
            if self.purge_network_interfaces:
                new_nics = []
                for interface in results['network_interfaces']:
                    for i in self.network_interfaces:
                        if interface == i:
                            new_nics.append(interface)
                results['network_interfaces'] = new_nics

            if self.tags:
                for tag_key, tag_value in self.tags.iteritem():
                    if results['tags'].get(tag_key, None):
                        if results['tags'][tag_key] != tag_value:
                            changed = True
                            results['tags'][tag_key] = tag_value
                    else:
                        changed = True
                        results['tags'][tag_key] = tag_value

            self.results['changed'] = changed
            self.results['results'] = results
            if not self.check_mode:
                self.results['results'] = self.create_or_update(results)

        elif self.state == 'present' and changed:
            # create the security group
            self.debug("Create security group {0}".format(name))

            if not self.location:
                raise Exception("Location is required when creating a new security group.")

            results['name'] = self.name
            results['location'] = self.location
            results['rules'] = []
            results['default_rules'] = []
            results['subnets'] = []
            results['network_interfaces'] = []
            results['tags'] = []

            if self.rules:
                results['rules'] = self.rules
            if self.default_rules:
                results['default_rules'] = self.default_rules
            if self.subnets:
                results['subnets'] = self.subnets
            if self.network_interfaces:
                results['network_interfaces'] = self.network_interfaces
            if self.tags:
                results['tags'] = self.tags

            self.results['changed'] = changed
            self.results['results'] = results
            if not self._module.check_mode:
                self.results['results'] = self.create_or_update(results)

        elif self.state == 'absent' and changed:
            self.log("Delete security group {0}".format(self.name))

            self.results['changed'] = changed
            self.results['results'] = dict()
            if not self.check_mode:
                self.results['status'] = self.delete()

        return self.results

    def create_or_update(self, results):
        try:
            # perform the update
            parameters = NetworkSecurityGroup(default_security_rules=[], network_interfaces=[], security_rules=[],
                                              subnets=[], tags={})
            for rule in results['rules']:
                parameters.security_rules.append(create_rule_instance(rule))
            for rule in results['default_rules']:
                parameters.default_security_rules.append(create_rule_instance(rule))
            for subnet in results['subnets']:
                parameters.subnets.append(Subnet(subnet))
            for interface in results['network_interfaces']:
                parameters.network_interfaces.append(NetworkInterface(interface))
            parameters.tags = results['tags']
            parameters.location = results['location']
            parameters.type = results['type']
            parameters.id = results['id']
            poller = self.network_client.network_security_groups.create_or_update(self.resource_group,
                                                                                  self.name,
                                                                                  parameters)
        except AzureHttpError, exc:
            self.fail("Error updating security group {0} - {1}".format(self.name, str(exc)))

        self.log('Checking poller:')
        while not poller.done():
            delay = 20
            self.log("Waiting for {0} sec".format(delay))
            poller.wait(timeout=delay)

        return create_network_security_group_dict(poller.result())

    def delete(self):
        try:
            poller = self.network_client.network_security_groups.delete(self.resource_group, self.name)
        except AzureHttpError as e:
            raise Exception(str(e.message))

        self.log('Checking poller:')
        while not poller.done():
            delay = 20
            self.log("Waiting for {0} sec".format(delay))
            poller.wait(timeout=delay)

        return poller.result()


def main():
    if '--interactive' in sys.argv:
        # import the module here so we can reset the default complex args value
        import ansible.module_utils.basic

        ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
            resource_group='rm_demo',
            name='test-sg',
            state='absent',
            location='West US',
            rules=[
                dict(
                    name="rdp",
                    description="rdp",
                    protocol="tcp",
                    source_port_range="0-65535",
                    destination_port_range="3389",
                    source_address_prefix="0.0.0.0/0",
                    destination_address_prefix="0.0.0.0/0",
                    access="Allow",
                    priority=100,
                    direction="Inbound",
                    purge_network_interfaces=True,
                )
            ],

            log_mode='stderr',
        ))

    AzureRMSecurityGroup().exec_module()

if __name__ == '__main__':
    main()
