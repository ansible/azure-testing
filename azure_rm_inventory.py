#!/usr/bin/env python

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

'''
Azure external inventory script
===============================
Generates dynamic inventory by making API requests to Azure using the Azure
Python SDK. For instruction on installing the Azure Python SDK see
http://azure-sdk-for-python.readthedocs.org/

Authentication
--------------
The ordeder of precedence is command line arguments, environment variables,
and finally the [default] profile found in ~/.azure/credentials.

If using a credentials file, it should be an ini formatted file with one or
more sections, which we refer to as profiles. The script looks for a 
[default] section, if a profile is not specified either on the command line
or with an environment variable. The keys in a profile will match the
list of command line arguments below.

For command line arguments and environment variables specify a profile found
in your ~/.azure/credentials file, or a service principal or Active Directory
user.

Commnad line arguments:
 - profile 
 - client_id
 - secret
 - subscription_id
 - tenant
 - ad_user
 - password

Environment variables:
 - AZURE_PROFILE
 - AZURE_CLIENT_ID
 - AZURE_SECRET
 - AZURE_SUBSCRIPTION_ID
 - AZURE_TENANT
 - AZURE_AD_USER
 - AZURE_PASSWORD

inventory_hostname
------------------
The VM inventory_hostname will be the fqdn, when set on the public_ip_address
object. Otherwise, the public ip address is used. If no public ip address,
then the private ip address is used.

Run for Specific Host
-----------------------
When run for a specific host using the --host option, a resource group is 
required. For a specific host, this script returns the following variables:

{
  "ansible_host": "XXX.XXX.XXX.XXX",
  "computer_name": "computer_name2",
  "fqdn": null,
  "id": "/subscriptions/subscription-id/resourceGroups/galaxy-production/providers/Microsoft.Compute/virtualMachines/object-name",
  "image": {
    "offer": "CentOS",
    "publisher": "OpenLogic",
    "sku": "7.1",
    "version": "latest"
  },
  "location": "westus",
  "mac_address": "00-0D-3A-31-2C-EC",
  "name": "object-name",
  "network_interface": "interface-name",
  "network_interface_id": "/subscriptions/subscription-id/resourceGroups/galaxy-production/providers/Microsoft.Network/networkInterfaces/object-name1",
  "network_security_group": null,
  "network_security_group_id": null,
  "os_disk": {
    "name": "object-name",
    "operating_system_type": "Linux"
  },
  "plan": null,
  "private_ip": "172.26.3.6",
  "private_ip_alloc_method": "Static",
  "provisioning_state": "Succeeded",
  "public_ip": "XXX.XXX.XXX.XXX",
  "public_ip_alloc_method": "Static",
  "public_ip_id": "/subscriptions/subscription-id/resourceGroups/galaxy-production/providers/Microsoft.Network/publicIPAddresses/object-name",
  "public_ip_name": "object-name",
  "resource_group": "galaxy-production",
  "security_group": "object-name",
  "security_group_id": "/subscriptions/subscription-id/resourceGroups/galaxy-production/providers/Microsoft.Network/networkSecurityGroups/object-name",
  "tags": null,
  "type": "Microsoft.Compute/virtualMachines",
  "virtual_machine_size": "Standard_DS4"
}

Groups
------
When run in --list mode, instances are grouped by the following categories:
 - azure
 - location
 - resource_group
 - security_group
 - tag key

Examples:
---------
  Execute /bin/uname on all instances in the us-central1-a zone
  $ ansible -i azure_rm_inventory.py galaxy-qa -m shell -a "/bin/uname -a"

  Use the inventory script to print instance specific information
  $ contrib/inventory/azure_rm_inventory.py --host my_instance_host_name

Insecure Platform Warning
-------------------------
If you receive InsecurePlatformWarning from urllib3, install the
requests security packages:

    pip install requests[security]


Author: Chris Houseknecht chouseknecht@ansible.com
Company: RedHat | Ansible        
Version: 1.0.0
'''

import argparse
import ConfigParser
import json 
import os
from os.path import expanduser
import sys

HAS_AZURE = True
HAS_REQUESTS = True

try:
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
    from azure.common.credentials import ServicePrincipalCredentials, UserPassCredentials
    from azure.mgmt.network.network_management_client import NetworkManagementClient,\
                                                             NetworkManagementClientConfiguration
    from azure.mgmt.resource.resources.resource_management_client import ResourceManagementClient,\
                                                                         ResourceManagementClientConfiguration
    from azure.mgmt.compute.compute_management_client import ComputeManagementClient,\
                                                             ComputeManagementClientConfiguration
except ImportError:
    HAS_AZURE = False


AZURE_CREDENTIAL_ENV_MAPPING = dict(
    profile='AZURE_PROFILE',
    subscription_id='AZURE_SUBSCRIPTION_ID',
    client_id='AZURE_CLIENT_ID',
    secret='AZURE_SECRET',
    tenant='AZURE_TENANT',
    ad_user='AZURE_AD_USER',
    password='AZURE_PASSWORD'
)


class AzureRM(object):

    def __init__(self, args):
        self._args = args
        self._compute_client = None
        self._resource_client = None
        self._network_client = None

        self.debug = False
        if args.debug:
            self.debug = True

        self.credentials = self._get_credentials(args)
        if not self.credentials:
            self.fail("Failed to get credentials. Either pass as parameters, set environment variables, "
                      "or define a profile in ~/.azure/credentials.")

        if self.credentials.get('subscription_id', None) is None:
            self.fail("Credentials did not include a subscription_id value.")
        self.log("setting subscription_id")
        self.subscription_id = self.credentials['subscription_id']

        if self.credentials.get('client_id') is not None and \
           self.credentials.get('secret') is not None and \
           self.credentials.get('tenant') is not None:
            self.azure_credentials = ServicePrincipalCredentials(client_id=self.credentials['client_id'],
                                                                 secret=self.credentials['secret'],
                                                                 tenant=self.credentials['tenant'])
        elif self.credentials.get('ad_user') is not None and self.credentials.get('password') is not None:
            self.azure_credentials = UserPassCredentials(self.credentials['ad_user'], self.credentials['password'])
        else:
            self.fail("Failed to authenticate with provided credentials. Some attributes were missing. "
                      "Credentials must include client_id, secret and tenant or ad_user and password.")

    def log(self, msg):
        if self.debug:
            print msg + u'\n'

    def fail(self, msg):
        raise Exception(msg)

    def _get_profile(self, profile="default"):
        path = expanduser("~")
        path += "/.azure/credentials"
        try:
            config = ConfigParser.ConfigParser()
            config.read(path)
        except Exception, exc:
            self.fail("Failed to access {0}. Check that the file exists and you have read "
                      "access. {1}".format(path, str(exc)))
        credentials = dict()
        for key in AZURE_CREDENTIAL_ENV_MAPPING:
            try:
                credentials[key] = config.get(profile, key, raw=True)
            except:
                pass

        if credentials.get('client_id') is not None or credentials.get('ad_user') is not None:
            return credentials

        return None

    def _get_env_credentials(self):
        env_credentials = dict()
        for attribute, env_variable in AZURE_CREDENTIAL_ENV_MAPPING.iteritems():
            env_credentials[attribute] = os.environ.get(env_variable, None)

        if env_credentials['profile'] is not None:
            credentials = self._get_profile(env_credentials['profile'])
            return credentials

        if env_credentials['client_id'] is not None:
            return env_credentials

        return None

    def _get_credentials(self, params):
        # Get authentication credentials.
        # Precedence: cmd line parameters-> environment variables-> default profile in ~/.azure/credentials.

        self.log('Getting credentials')

        arg_credentials = dict()
        for attribute, env_variable in AZURE_CREDENTIAL_ENV_MAPPING.iteritems():
            arg_credentials[attribute] = getattr(params, attribute)

        # try module params
        if arg_credentials['profile'] is not None:
            self.log('Retrieving credentials with profile parameter.')
            credentials = self._get_profile(arg_credentials['profile'])
            return credentials

        if arg_credentials['client_id'] is not None:
            self.log('Received credentials from parameters.')
            return arg_credentials

        # try environment
        env_credentials = self._get_env_credentials()
        if env_credentials:
            self.log('Received credentials from env.')
            return env_credentials

        # try default profile from ~./azure/credentials
        default_credentials = self._get_profile()
        if default_credentials:
            self.log('Retrieved default profile credentials from ~/.azure/credentials.')
            return default_credentials

        return None

    @property
    def network_client(self):
        self.log('Getting network client')
        if not self._network_client:
            self._network_client = NetworkManagementClient(
                NetworkManagementClientConfiguration(self.azure_credentials, self.subscription_id))
        return self._network_client

    @property
    def rm_client(self):
        self.log('Getting resource manager client')
        if not self._resource_client:
            self._resource_client = ResourceManagementClient(
                ResourceManagementClientConfiguration(self.azure_credentials, self.subscription_id))
        return self._resource_client

    @property
    def compute_client(self):
        self.log('Getting compute client')
        if not self._compute_client:
            self._compute_client = ComputeManagementClient(
                ComputeManagementClientConfiguration(self.azure_credentials, self.subscription_id))
        return self._compute_client


class AzureInventory(object):

    def __init__(self):

        self._args = self._parse_cli_args()

        try:
            rm = AzureRM(self._args)
        except Exception, e:
            sys.exit("{0}".format(str(e)))

        self._compute_client = rm.compute_client
        self._network_client = rm.network_client
        self._resource_client = rm.rm_client
        self._security_groups = None

        self._inventory = dict(
            _meta=dict(
                hostvars=dict()
            ),
            azure=[]
        )

        if self._args.host and not self._args.resource_group:
            sys.exit("Error: cannot retrieve host without a resource group.")

        self.get_inventory()
        print(self._json_format_dict(pretty=self._args.pretty))
        sys.exit(0)

    def _parse_cli_args(self):
        # Parse command line arguments
        parser = argparse.ArgumentParser(
                description='Produce an Ansible Inventory file for an Azure subscription')
        parser.add_argument('--list', action='store_true', default=True,
                           help='List instances (default: True)')
        parser.add_argument('--debug', action='store_true', default=False,
                           help='Show debug messages')
        parser.add_argument('--host', action='store',
                           help='Get all information about an instance')
        parser.add_argument('--pretty', action='store_true', default=False,
                           help='Pretty print JSON output(default: False)')
        parser.add_argument('--profile', action='store',
                            help='Azure profile contained in ~/.azure/credentials')
        parser.add_argument('--subscription_id', action='store',
                            help='Azure Subscription Id')
        parser.add_argument('--client_id', action='store',
                            help='Azure Client Id ')
        parser.add_argument('--secret', action='store',
                            help='Azure Client Secret')
        parser.add_argument('--tenant', action='store',
                            help='Azure Tenant Id')
        parser.add_argument('--ad-user', action='store',
                            help='Active Directory User')
        parser.add_argument('--password', action='store',
                            help='password')
        parser.add_argument('--resource-group', action='store',
                            help='Return inventory for a given Azure resource group')
        return parser.parse_args()

    def get_inventory(self):
        if self._args.host and self._args.resource_group:
            try:
                virtual_machine = self._compute_client.virtual_machines.get(self._args.resource_group,
                                                                            self._args.host)
                self._get_security_groups(self._args.resource_group)
                self._load_machines([virtual_machine], self._args.resource_group)
            except AzureMissingResourceHttpError, e:
                sys.exie("{0}".format(json.loads(e.message)['error']['message']))
        elif self._args.resource_group:
            try:
                virtual_machines = self._compute_client.virtual_machines.list(self._args.resource_group)
                self._get_security_groups(self._args.resource_group)
                self._load_machines(virtual_machines, self._args.resource_group)
            except AzureMissingResourceHttpError, e:
                sys.exit("{0}".format(json.loads(e.message)['error']['message']))
        else:
            # get all VMs in all resource groups
            try:
                resource_groups = self._resource_client.resource_groups.list(None)
                for resource_group in resource_groups:
                    virtual_machines = self._compute_client.virtual_machines.list(resource_group.name)
                    self._get_security_groups(resource_group.name)
                    self._load_machines(virtual_machines, resource_group.name)
            except AzureHttpError, e:
                sys.exit("{0}".format(json.loads(e.message)['error']['message']))

    def _load_machines(self, machines, resource_group):
        for machine in machines:
            host_vars = dict(
                ansible_host=None,
                private_ip=None,
                private_ip_alloc_method=None,
                public_ip=None,
                public_ip_name=None,
                public_ip_id=None,
                public_ip_alloc_method=None,
                fqdn=None,
                location=machine.location,
                name=machine.name,
                type=machine.type,
                id=machine.id,
                tags=machine.tags,
                network_interface_id=None,
                network_interface=None,
                network_security_group=None,
                network_security_group_id=None,
                resource_group=resource_group,
                mac_address=None,
                plan=(machine.plan.name if machine.plan else None),
                virtual_machine_size=machine.hardware_profile.vm_size.value,
                computer_name=machine.os_profile.computer_name,
                provisioning_state=machine.provisioning_state,
            )

            host_vars['os_disk'] = dict(
                name=machine.storage_profile.os_disk.name,
                operating_system_type=machine.storage_profile.os_disk.os_type.value
            )

            if machine.storage_profile.image_reference:
                host_vars['image'] = dict(
                    offer=machine.storage_profile.image_reference.offer,
                    publisher=machine.storage_profile.image_reference.publisher,
                    sku=machine.storage_profile.image_reference.sku,
                    version=machine.storage_profile.image_reference.version
                )

            for interface in machine.network_profile.network_interfaces:
                interface_reference = self._parse_ref_id(interface.id)
                network_interface = self._network_client.network_interfaces.get(
                    interface_reference['resourceGroups'],
                    interface_reference['networkInterfaces'])
                if network_interface.primary:
                    if self._security_groups.get(network_interface.id, None):
                        host_vars['security_group'] = self._security_groups[network_interface.id]['name']
                        host_vars['security_group_id'] = self._security_groups[network_interface.id]['id']
                    host_vars['network_interface'] = network_interface.name
                    host_vars['network_interface_id'] = network_interface.id
                    host_vars['mac_address'] = network_interface.mac_address
                    for ip_config in network_interface.ip_configurations:
                        host_vars['private_ip'] = ip_config.private_ip_address
                        host_vars['private_ip_alloc_method'] = ip_config.private_ip_allocation_method.value
                        if ip_config.public_ip_address:
                            public_ip_reference = self._parse_ref_id(ip_config.public_ip_address.id)
                            public_ip_address = self._network_client.public_ip_addresses.get(
                                public_ip_reference['resourceGroups'],
                                public_ip_reference['publicIPAddresses'])
                            host_vars['ansible_host'] = public_ip_address.ip_address
                            host_vars['public_ip'] = public_ip_address.ip_address
                            host_vars['public_ip_name'] = public_ip_address.name
                            host_vars['public_ip_alloc_method'] = public_ip_address.public_ip_allocation_method.value
                            host_vars['public_ip_id'] = public_ip_address.id
                            if public_ip_address.dns_settings:
                                host_vars['fqdn'] = public_ip_address.dns_settings.fqdn

            if self._args.host:
                self._inventory = host_vars
            else:
                self._add_host(host_vars, resource_group)

    def _get_security_groups(self, resource_group):
        self._security_groups = dict()
        for group in self._network_client.network_security_groups.list(resource_group):
            if group.network_interfaces:
                for interface in group.network_interfaces:
                    self._security_groups[interface.id] = dict(
                        name=group.name,
                        id=group.id
                    )

    def _add_host(self, vars, resource_group):
        if not self._inventory.get(resource_group):
            self._inventory[resource_group] = []

        if not self._inventory.get(vars['location']):
            self._inventory[vars['location']] = []

        if vars.get('security_group') and self._inventory.get(vars['security_group']) is None:
            self._inventory[vars['security_group']] = []

        host_name = vars['name']
        self._inventory[vars['location']].append(host_name)
        self._inventory['_meta']['hostvars'][host_name] = vars
        self._inventory[resource_group].append(host_name)
        self._inventory['azure'].append(host_name)

        if vars.get('security_group'):
            self._inventory[vars['security_group']].append(host_name)

        if vars.get('tags', None) is not None:
            for key in vars['tags']:
                if not self._inventory.get(key):
                    self._inventory[key] = []
                self._inventory[key].append(host_name)

    def _parse_ref_id(self, reference):
        response = {}
        keys = reference.strip('/').split('/')
        for index in range(len(keys)):
            if index < len(keys) - 1 and index % 2 == 0:
                response[keys[index]] = keys[index + 1]
        return response

    def _json_format_dict(self, pretty=False):
        # convert inventory to json
        if pretty:
            return json.dumps(self._inventory, sort_keys=True, indent=2)
        else:
            return json.dumps(self._inventory)


def main():
    if not HAS_AZURE:
        sys.exit("The Azure python sdk is not installed (try 'pip install azure')")

    if not HAS_REQUESTS:
        sys.exit("The requests python module is not installed (try 'pip install requests')")

    AzureInventory()

if __name__ == '__main__':
    main()
