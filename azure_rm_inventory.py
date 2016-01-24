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


'''
Azure external inventory script
===============================
Generates dynamic inventory by making API requests to Azure using the Azure
Python SDK. For instruction on installing the Azure Python SDK see
http://azure-sdk-for-python.readthedocs.org/

To run for a specific host a resource group is required.

The VM inventory_hostname will be the fqdn, when set on the public_ip_address object.
Otherwise, the public ip address is used. If no public ip address, then the private
ip address is used.

When run against a specific host, this script returns the following variables:
 - computer_name
 - fqdn
 - id
 - image (dictionary: offer, publisher, sku, version)
 - location
 - mac address
 - name
 - network_interface
 - network_security_group
 - os_disk (dictionary: name, operating_system_type)
 - private_ip_address
 - provisioning_state
 - public_ip_address
 - public_ip_address_name
 - resource_group
 - tags (dictionary of key, value pairs)
 - type
 - virtual_machine_size

When run in --list mode, instances are grouped by the following categories:
 - azure
 - location
 - resource_group
 - tag key

Examples:
  Execute uname on all instances in the us-central1-a zone
  $ ansible -i azure_rm_inventory.py galaxy-qa -m shell -a "/bin/uname -a"

  Use the GCE inventory script to print out instance specific information
  $ contrib/inventory/azure_rm_inventory.py --host my_instance

Author: Chris Houseknecht chouseknecht@ansible.com
Version: 1.0.0


NOTE: If you receive InsecurePlatformWarning from urllib3, install the requests security packages:
      pip install requests[security]

'''

import argparse
import ConfigParser
import json 
import os
from os.path import expanduser
import re
import sys

HAS_AZURE = True
HAS_REQUESTS = True

try:
    from azure.mgmt.common import SubscriptionCloudCredentials
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.network import NetworkResourceProviderClient
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
except ImportError:
    HAS_AZURE = False

try:
    import requests
except ImportError:
    HAS_REQUESTS = False


class AzureRM(object):

    def __init__(self, args):
        self._args = args
        self._compute_client = None
        self._resource_client = None
        self._network_client = None

        self._credentials = self.__get_credentials()
        if not self._credentials:
            raise Exception("Failed to get credentials. Either pass as parameters, set environment variables, or define " +
                "a profile in ~/.azure/credientials.")

        self._auth_endpoint = "https://login.microsoftonline.com/%s/oauth2/token" % self._credentials['tenant_id']
        auth_token = self.__get_token_from_client_credentials()
        self._creds = SubscriptionCloudCredentials(self._credentials['subscription_id'], auth_token)

    def __get_credentials_parser(self):
        path = expanduser("~")
        path += "/.azure/credentials"
        p = ConfigParser.ConfigParser()
        try:
            p.read(path)
            return p
        except Exception:
            raise Exception("Failed to access %s. Check that the file exists and you have read access." % path)

    def __parse_creds(self, profile="default"):
        parser = self.__get_credentials_parser()
        creds = dict(
            subscription_id = "",
            client_id = "",
            client_secret = "",
            tenant_id = ""
        )
        for key in creds:
            try:
                creds[key] = parser.get(profile, key, raw=True)
            except Exception:
                raise Exception("Failed to get %s for profile %s in ~/.azure/credentials" % (key, profile))
        return creds

    def __get_env_creds(self):
        profile = os.environ.get('AZURE_PROFILE', None)
        subscription_id = os.environ.get('AZURE_SUBSCRIPTION_ID', None)
        client_id = os.environ.get('AZURE_CLIENT_ID', None)
        client_secret = os.environ.get('AZURE_CLIENT_SECRET', None)
        tenant_id = os.environ.get('AZURE_TENANT_ID', None)
        if profile:
            creds = self.__parse_creds(profile)
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

    def __get_credentials(self):
        # Get authentication credentials.
        # Precedence: command line args-> environment variables-> default profile in ~/.azure/credentials.

        profile = self._args.profile
        subscription_id = self._args.subscription_id
        client_id = self._args.client_id
        client_secret = self._args.client_secret
        tenant_id = self._args.tenant_id

        # try module params
        if profile:
           creds = self.__parse_creds(profile)
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
        env_creds = self.__get_env_creds()
        if env_creds:
            return env_creds

        # try default profile from ~./azure/credentials
        def_creds = self.__parse_creds()
        if def_creds:
            return def_creds

        return None

    def __get_token_from_client_credentials(self):
        payload = {
            'grant_type': 'client_credentials',
            'client_id': self._credentials['client_id'],
            'client_secret': self._credentials['client_secret'],
            'resource': 'https://management.core.windows.net/',
        }

        response = requests.post(self._auth_endpoint, data=payload).json()
        if 'error_description' in response:
           raise Exception(msg='Failed getting OAuth token: %s' % response['error_description'])
        return response['access_token']

    @property
    def compute_client(self):
        if not self._compute_client:
            self._compute_client = ComputeManagementClient(self._creds)
        if not self._resource_client:
            self._resource_client = ResourceManagementClient(self._creds)
        self._resource_client.providers.register('Microsoft.Compute')
        return self._compute_client

    @property
    def network_client(self):
        if not self._network_client:
            self._network_client = NetworkResourceProviderClient(self._creds)
        return self._network_client

    @property
    def rm_client(self):
        if not self._resource_client:
            self._resource_client = ResourceManagementClient(self._creds)
        return self._resource_client


class AzureInventory(object):

    def __init__(self):

        self._args = self.__parse_cli_args()

        try:
            rm = AzureRM(self._args)
        except Exception, e:
            print "{0}".format(e.args[0])
            sys.exit(1)

        self._compute_client = rm.compute_client
        self._network_client = rm.network_client
        self._resource_client = rm.rm_client

        self._inventory = dict(
            _meta=dict(
                hostvars=dict()
            ),
            azure=[]
        )

        if self._args.host and not self._args.resource_group:
            print("Error: cannot retrieve host without a resource group.")
            sys.exit(1)

        self.get_inventory()
        print(self._json_format_dict(pretty=self._args.pretty))
        sys.exit(0)

    def __parse_cli_args(self):
        # Parse command line arguments
        parser = argparse.ArgumentParser(
                description='Produce an Ansible Inventory file an Azure subscription')
        parser.add_argument('--list', action='store_true', default=True,
                           help='List instances (default: True)')
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
        parser.add_argument('--client_secret', action='store',
                            help='Azure Client Secret')
        parser.add_argument('--tenant_id', action='store',
                            help='Azure Tenant Id')
        parser.add_argument('--resource_group', action='store',
                            help='Return inventory for a given Azure resource group')
        return parser.parse_args()

    def get_inventory(self):
        if self._args.host and self._args.resource_group:
            try:
                response = self._compute_client.virtual_machines.get(self._args.resource_group,
                                                                     self._args.host)
                self._load_machines([response.virtual_machine], self._args.resource_group)
            except AzureMissingResourceHttpError, e:
                print "{0}".format(json.loads(e.message)['error']['message'])
                sys.exit(1)
        elif self._args.resource_group:
            try:
                list = self._compute_client.virtual_machines.list(self._args.resource_group)
                self._load_machines(list.virtual_machines, self._args.resource_group)
            except AzureMissingResourceHttpError, e:
                print "{0}".format(json.loads(e.message)['error']['message'])
                sys.exit(1)
        else:
            # get all VMs in all resource groups
            try:
                response = self._resource_client.resource_groups.list(None)
                print "next: %s" % response.next_link
                for resource_group in response.resource_groups:
                    list = self._compute_client.virtual_machines.list(resource_group.name)
                    self._load_machines(list.virtual_machines, resource_group.name)
            except AzureHttpError, e:
                print "{0}".format(json.loads(e.message)['error']['message'])
                sys.exit(1)

    def _load_machines(self, machines, resource_group):
        for machine in machines:
            host_vars = dict(
                private_ip_address=None,
                public_ip_address=None,
                public_ip_address_name=None,
                fqdn=None,
                location=machine.location,
                name=machine.name,
                type=machine.type,
                id=machine.id,
                tags=machine.tags,
                network_interface=None,
                network_security_group=None,
                resource_group=resource_group,
                mac_address=None,
            )

            host_vars['virtual_machine_size'] = machine.hardware_profile.virtual_machine_size
            host_vars['os_disk'] = dict(
                    name=machine.storage_profile.os_disk.name,
                    operating_system_type=machine.storage_profile.os_disk.operating_system_type
            )
            host_vars['computer_name'] = machine.os_profile.computer_name
            host_vars['provisioning_state'] = machine.provisioning_state

            if machine.storage_profile.image_reference:
                host_vars['image'] = dict(
                    offer=machine.storage_profile.image_reference.offer,
                    publisher=machine.storage_profile.image_reference.publisher,
                    sku=machine.storage_profile.image_reference.sku,
                    version=machine.storage_profile.image_reference.version
                )

            # For now assuming that there is only a single network interface. The primary attribute
            # does not seem to be set, otherwise we could find and use the primary only.
            interface_reference = self._parse_ref_id(machine.network_profile.network_interfaces[0].reference_uri)
            interface_response = self._network_client.network_interfaces.get(interface_reference['resourceGroups'],
                                                                   interface_reference['networkInterfaces'])
            network_interface = interface_response.network_interface
            host_vars['network_interface'] = network_interface.name
            host_vars['mac_address'] = network_interface.mac_address
            network_sec_group_reference = self._parse_ref_id(network_interface.network_security_group.id)
            host_vars['network_security_group'] = network_sec_group_reference['networkSecurityGroups']

            for ip_config in network_interface.ip_configurations:
                host_vars['private_ip_address'] = ip_config.private_ip_address
                if ip_config.public_ip_address:
                    public_ip_reference = self._parse_ref_id(ip_config.public_ip_address.id)
                    public_ip_response = self._network_client.public_ip_addresses.get(
                                             public_ip_reference['resourceGroups'],
                                             public_ip_reference['publicIPAddresses'])
                    public_ip_address = public_ip_response.public_ip_address
                    host_vars['public_ip_address'] = public_ip_address.ip_address
                    host_vars['public_ip_address_name'] = public_ip_address.name
                    if public_ip_address.dns_settings:
                        host_vars['fqdn'] = public_ip_address.dns_settings.fqdn

            if self._args.host:
                self._inventory = host_vars
            else:
                self._add_host(host_vars, resource_group)

    def _add_host(self, vars, resource_group):
        if not self._inventory.get(resource_group):
            self._inventory[resource_group] = []

        if not self._inventory.get(vars['location']):
           self._inventory[vars['location']] = []

        if vars['fqdn']:
            host_name = vars['fqdn']
        elif vars['public_ip_address']:
            host_name = vars['public_ip_address']
        else:
            host_name = vars['private_ip_address']

        self._inventory[vars['location']].append(host_name)
        self._inventory['_meta']['hostvars'][host_name] = vars
        self._inventory[resource_group].append(host_name)
        self._inventory['azure'].append(host_name)

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
        print "The Azure python sdk is not installed (try 'pip install azure')"
        sys.exit(1)

    if not HAS_REQUESTS:
        print "The requests python module is not installed (try 'pip install requests')"
        sys.exit(1)

    AzureInventory()

if __name__ == '__main__':
    main()
