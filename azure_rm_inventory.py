#!/usr/bin/env python
#
# (c) 2016 Matt Davis, <mdavis@redhat.com>
#          Chris Houseknecht, <house@redhat.com>
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
Azure External Inventory Script
===============================
Generates dynamic inventory by making API requests to Azure using the Azure
Python SDK. For instruction on installing the Azure Python SDK see
http://azure-sdk-for-python.readthedocs.org/

Authentication
--------------
The order of precedence is command line arguments, environment variables,
and finally the [default] profile found in ~/.azure/credentials.

If using a credentials file, it should be an ini formatted file with one or
more sections, which we refer to as profiles. The script looks for a 
[default] section, if a profile is not specified either on the command line
or with an environment variable. The keys in a profile will match the
list of command line arguments below.

For command line arguments and environment variables specify a profile found
in your ~/.azure/credentials file, or a service principal or Active Directory
user.

Command line arguments:
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
  "powerstate": "running",
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

Control groups using azure.ini or set environment variables:

AZURE_GROUP_BY_RESOURCE_GROUP=yes
AZURE_GROUP_BY_LOCATION=yes
AZURE_GROUP_BY_SECURITY_GROUP=yes
AZURE_GROUP_BY_TAG=yes

Control resource groups by assigning a comma separated list to:

AZURE_RESOURCE_GROUPS=resource_group_a,resource_group_b

If no list is provided, all resource groups will be included.

Powerstate:
-----------
The powerstate attribute indicates whether or not a host is running. If the value is 'running', the machine is
up. If the value is anything other than 'running', the machine is down, and will be unreachable.

Examples:
---------
  Execute /bin/uname on all instances in the galaxy-qa resource group
  $ ansible -i azure_rm_inventory.py galaxy-qa -m shell -a "/bin/uname -a"

  Use the inventory script to print instance specific information
  $ contrib/inventory/azure_rm_inventory.py --host my_instance_host_name --resource-groups=my_resource_group

Insecure Platform Warning
-------------------------
If you receive InsecurePlatformWarning from urllib3, install the
requests security packages:

    pip install requests[security]


Author: Matt Davis, <mdavis@redhat.com>
        Chris Houseknecht, <house@redhat.com>

Company: Red Hat | Ansible

Version: 1.0.0
'''

import argparse
import ConfigParser
import json 
import os
from os.path import expanduser
import sys

HAS_AZURE = True

try:
    from msrestazure.azure_exceptions import CloudError
    from azure.mgmt.compute import __version__ as azure_compute_version
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

AZURE_CONFIG_SETTINGS = dict(
    resource_groups='AZURE_RESOURCE_GROUPS',
    group_by_resource_group='AZURE_GROUP_BY_RESOURCE_GROUP',
    group_by_location='AZURE_GROUP_BY_LOCATION',
    group_by_security_group='AZURE_GROUP_BY_SECURITY_GROUP',
    group_by_tag='AZURE_GROUP_BY_TAG'
)

AZURE_MIN_VERSION = "2016-03-30"


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

        self.resource_groups = []
        self.group_by_resource_group = True
        self.group_by_location = True
        self.group_by_security_group = True
        self.group_by_tag = True

        self._inventory = dict(
            _meta=dict(
                hostvars=dict()
            ),
            azure=[]
        )

        self._get_settings()

        if self._args.resource_groups:
            values = self._args.resource_groups.split(',')
            self.resource_groups = values

        if self._args.host and len(self.resource_groups) == 0:
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
                           help='Send debug messages to STDOUT')
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
        parser.add_argument('--resource-groups', action='store',
                            help='Return inventory for a given Azure resource group')
        return parser.parse_args()

    def get_inventory(self):
        if self._args.host:
            try:
                for resource_group in self.resource_groups:
                    virtual_machine = self._compute_client.virtual_machines.get(resource_group,
                                                                                self._args.host,
                                                                                expand='instanceview')
                    self._get_security_groups(resource_group)
                    self._load_machines([virtual_machine], resource_group)
            except AzureMissingResourceHttpError, e:
                sys.exit("{0}".format(json.loads(e.message)['error']['message']))
            except CloudError, e:
                sys.exit("{0}".format(str(e)))

        elif len(self.resource_groups) > 0:
            try:
                for resource_group in self.resource_groups:
                    virtual_machines = self._compute_client.virtual_machines.list(resource_group)
                    self._get_security_groups(resource_group)
                    self._load_machines(virtual_machines, resource_group)
            except AzureMissingResourceHttpError, e:
                sys.exit("{0}".format(json.loads(e.message)['error']['message']))
            except CloudError, e:
                sys.exit("{0}".format(str(e)))
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
            except CloudError, e:
                sys.exit("{0}".format(str(e)))

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
                powerstate=None
            )

            host_vars['os_disk'] = dict(
                name=machine.storage_profile.os_disk.name,
                operating_system_type=machine.storage_profile.os_disk.os_type.value
            )

            if machine.instance_view:
                host_vars['powerstate'] = next((s.code.replace('PowerState/', '')
                                               for s in machine.instance_view.statuses
                                               if s.code.startswith('PowerState')), None)
            else:
                # Machine instance coming from a list view do not include 'instanceview'. We need an instanceview
                # in order to resolve the power state.
                try:
                    vm = self._compute_client.virtual_machines.get(resource_group,
                                                                   machine.name,
                                                                   expand='instanceview')
                    host_vars['powerstate'] = next((s.code.replace('PowerState/', '')
                                                   for s in vm.instance_view.statuses
                                                   if s.code.startswith('PowerState')),
                                                   None)
                except Exception, exc:
                    sys.exit("Error: failed to get instance view for host {0} - {1}".format(machine.name, str(exc)))

            if machine.storage_profile.image_reference:
                host_vars['image'] = dict(
                    offer=machine.storage_profile.image_reference.offer,
                    publisher=machine.storage_profile.image_reference.publisher,
                    sku=machine.storage_profile.image_reference.sku,
                    version=machine.storage_profile.image_reference.version
                )

            # Add windows details
            if machine.os_profile.windows_configuration is not None:
                host_vars['windows_auto_updates_enabled'] = \
                    machine.os_profile.windows_configuration.enable_automatic_updates
                host_vars['windows_timezone'] = machine.os_profile.windows_configuration.time_zone
                host_vars['windows_rm'] = None
                if machine.os_profile.windows_configuration.win_rm is not None:
                    host_vars['windows_rm'] = dict(listeners=None)
                    if machine.os_profile.windows_configuration.win_rm.listeners is not None:
                        host_vars['windows_rm']['listeners'] = []
                        for listener in machine.os_profile.windows_configuration.win_rm.listeners:
                            host_vars['windows_rm']['listeners'].append(dict(protocol=listener.protocol,
                                                                             certificate_url=listener.certificate_url))

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
        if self.group_by_resource_group and self._inventory.get(resource_group) is None:
            self._inventory[resource_group] = []

        if self.group_by_location and self._inventory.get(vars['location']) is None:
            self._inventory[vars['location']] = []

        if self.group_by_security_group and vars.get('security_group') and \
           self._inventory.get(vars['security_group']) is None:
            self._inventory[vars['security_group']] = []

        host_name = vars['name']

        if self.group_by_location:
            self._inventory[vars['location']].append(host_name)
        if self.group_by_resource_group:
            self._inventory[resource_group].append(host_name)
        if self.group_by_security_group and vars.get('security_group'):
            self._inventory[vars['security_group']].append(host_name)

        self._inventory['_meta']['hostvars'][host_name] = vars
        self._inventory['azure'].append(host_name)

        if self.group_by_tag and vars.get('tags', None) is not None:
            for key in vars['tags']:
                if not self._inventory.get(key):
                    self._inventory[key] = []
                self._inventory[key].append(host_name)

    def _json_format_dict(self, pretty=False):
        # convert inventory to json
        if pretty:
            return json.dumps(self._inventory, sort_keys=True, indent=2)
        else:
            return json.dumps(self._inventory)

    def _get_settings(self):
        # Load settings from azure.ini, if it exists. Otherwise,
        # look for environment values.
        file_settings = self._load_settings()
        if file_settings:
            for key in AZURE_CONFIG_SETTINGS:
                if key == 'resource_groups' and file_settings.get(key, None) is not None:
                    values = file_settings.get(key).split(',')
                    if len(values) > 0:
                        self.resource_groups = values
                elif file_settings.get(key, None) is not None:
                    val = self._to_boolean(file_settings[key])
                    setattr(self, key, val)
        else:
            env_settings = self._get_env_settings()
            for key in AZURE_CONFIG_SETTINGS:
                if key == 'resource_groups' and env_settings.get(key, None) is not None:
                    values = env_settings.get(key).split(',')
                    if len(values) > 0:
                        self.resource_groups = values
                elif env_settings.get(key, None) is not None:
                    val = self._to_boolean(env_settings[key])
                    setattr(self, key, val)

    def _parse_ref_id(self, reference):
        response = {}
        keys = reference.strip('/').split('/')
        for index in range(len(keys)):
            if index < len(keys) - 1 and index % 2 == 0:
                response[keys[index]] = keys[index + 1]
        return response

    def _to_boolean(self, value):
        if value in ['Yes', 'yes', 1, 'True', 'true', True]:
            result = True
        elif value in ['No', 'no', 0, 'False', 'false', False]:
            result = False
        else:
            result = True
        return result

    def _get_env_settings(self):
        env_settings = dict()
        for attribute, env_variable in AZURE_CONFIG_SETTINGS.iteritems():
            env_settings[attribute] = os.environ.get(env_variable, None)
        return env_settings

    def _load_settings(self):
        path = "./azure.ini"
        config = None
        settings = None
        try:
            config = ConfigParser.ConfigParser()
            config.read(path)
        except:
            pass

        if config is not None:
            settings = dict()
            for key in AZURE_CONFIG_SETTINGS:
                try:
                    settings[key] = config.get('azure', key, raw=True)
                except:
                    pass

        return settings


def main():
    if not HAS_AZURE:
        sys.exit("The Azure python sdk is not installed (try 'pip install azure')")

    if azure_compute_version < AZURE_MIN_VERSION:
        sys.exit("Expecting azure.mgmt.compute.__version__ to be >= {0}. Found version {1} "
                 "Do you have Azure >= 2.0.0rc2 installed?".format(AZURE_MIN_VERSION, azure_compute_version))

    AzureInventory()

if __name__ == '__main__':
    main()
