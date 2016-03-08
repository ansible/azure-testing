
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

import ConfigParser
import os
import sys
import logging

from os.path import expanduser


AZURE_COMMON_ARGS = dict(
    profile=dict(type='str'),
    subscription_id=dict(type='str'),
    client_id=dict(type='str'),
    secret=dict(type='str'),
    tenant=dict(type='str'),
    log_path=dict(type='str'),
    log_mode=dict(type='str', choices=['stderr','file','syslog'], default='syslog'),
    filter_logger=dict(type='bool', default=True),
    debug=dict(type='bool', default=False),
)

AZURE_CREDENTIAL_ENV_MAPPING = dict(
    profile='AZURE_PROFILE',
    subscription_id='AZURE_SUBSCRIPTION_ID',
    client_id='AZURE_CLIENT_ID',
    secret='AZURE_SECRET',
    tenant='AZURE_TENANT',
    ad_user='AZURE_AD_USER',
    password='AZURE_PASSWORD'
)

AZURE_COMMON_REQUIRED_IF = [
    ('log_mode', 'file', ['log_path'])
]

HAS_AZURE = True
HAS_REQUESTS = True

try:
    from azure.common.credentials import ServicePrincipalCredentials, UserPassCredentials
    from azure.mgmt.network import NetworkResourceProviderClient, NetworkManagementClientConfiguration
    from azure.mgmt.resource import ResourceManagementClient, ResourceManagementClientConfiguration
    from azure.mgmt.storage import StorageManagementClient, StorageManagementClientConfiguration
    from azure.mgmt.compute import ComputeManagementClient, ComputeManagementClientConfiguration
except ImportError:
    HAS_AZURE = False


class AzureRMModuleBase(object):

    def __init__(self, derived_arg_spec, supports_check_mode=False):
        self._logger =  logging.getLogger(self.__class__.__name__)

        merged_arg_spec = dict()
        merged_arg_spec.update(AZURE_COMMON_ARGS)
        if derived_arg_spec:
            merged_arg_spec.update(derived_arg_spec)

        # TODO: support merging required_if, others from derived classes
        self.module = AnsibleModule(argument_spec=merged_arg_spec, supports_check_mode=supports_check_mode, required_if=AZURE_COMMON_REQUIRED_IF)

        if not HAS_AZURE:
            self.fail("The Azure python sdk is not installed (try 'pip install azure')")

        if not HAS_REQUESTS:
            self.fail("The requests python module is not installed (try 'pip install requests')")

        self._network_client = None
        self._storage_client = None
        self._resource_client = None
        self._compute_client = None

        self._log_mode = self.module.params.get('log_mode')
        self._filter_logger = self.module.params.get('filter_logger')
        self.debug = self._logger.debug

        if self._log_mode == 'syslog':
            # TODO: bridge this to module.debug() with a logger handler
            pass
        elif self._log_mode == 'file':
            self._log_path = self.module.params.get('log_path')
            logging.basicConfig(level=logging.DEBUG, filename=self._log_path)
        elif self._log_mode == 'stderr':
            logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)

        if self._filter_logger:
            for h in logging.root.handlers:
                h.addFilter(logging.Filter(name=self._logger.name))

        self.credentials = self._get_credentials(module.params)
        if not self.credentials:
            self.fail("Failed to get credentials. Either pass as parameters, set environment variables, "
                      "or define a profile in ~/.azure/credentials.")

        if self.credentials.get('subscription_id') is None:
            self.fail("Credentials did not include a subscription_id value.")
        else:
            self.subscription_id = self.credentials['subscription_id']

        if self.credentials.get('client_id') is not None and \
           self.credentials.get('secret') is not None and self.credentials.get('tenant') is not None:
            self.azure_credentials = ServicePrincipalCredentials(client_id=self.credentials['client_id'],
                                                                 secret=self.credentials['secret'],
                                                                 tenant=self.credentials['tenant'])
        elif self.credentials.get('ad_user') is not None and self.credentials.get('password') is not None:
            self.azure_credentials = UserPassCredentials(self.credentials['ad_user'], self.credentials['password'])
        else:
            self.fail('Failed to authenticate with provided credentials. Some attributes were missing. '
                       'Credentials must include client_id, secret and tenant or ad_user and password.')
    
    def fail(self, msg):
        self.module.fail_json(msg=msg)

    def log(self, msg):
        self._logger.debug(msg)

    def _parse_credentials(self, profile="default"):
        path = expanduser("~")
        path += "/.azure/credentials"
        p = ConfigParser.ConfigParser()
        try:
            parser = p.read(path)
        except Exception, exc:
            self.fail(msg="Failed to access {0}. Check that the file exists and you have read "
                       "access. {1}".format(path, exc))
        credentials = dict()
        for key in AZURE_CREDENTIAL_ENV_MAPPING.iteritems():
            try:
                credentials[key] = parser.get(profile, key, raw=True)
            except:
                pass

        if credentials['client_id'] is not None or credentials['ad_user'] is not None:
            return credentials

        return None

    def _get_env_credentials(self):
        env_credentials = dict()
        for attribute, env_variable in AZURE_CREDENTIAL_ENV_MAPPING.iteritems():
            env_credentials[attribute] = os.environ.get(env_variable, None)

        if env_credentials['profile'] is not None:
            credentials = self._parse_credentials(env_values['profile'])
            return credentials

        if env_credentials['client_id'] is not None:
            return env_credentials

        return None

    def _get_credentials(self, params):
        # Get authentication credentials.
        # Precedence: module parameters-> environment variables-> default profile in ~/.azure/credentials.
        
        self.log('Getting credentials')

        arg_credentials = dict()
        for attribute, env_variable in AZURE_CREDENTIAL_ENV_MAPPING.iteritems():
            arg_credentials[attribute] = params.get(env_variable, None)

        # try module params
        if arg_credentials['profile'] is not None:
            self.log('Retrieving credentials with profile parameter.')
            credentials = self._parse_creds(arg_credentials['profile'])
            return credentials
        
        if arg_credentials['subscription_id'] is not None:
            self.log('Received credentials from parameters.')
            return arg_credentials
        
        # try environment
        env_credentials = self._get_env_credentials()
        if env_credentials:
            self.log('Received credentials from env.')
            return env_credentials

        # try default profile from ~./azure/credentials
        default_credentials = self._parse_credentials()
        if default_credentials:
            self.log('Retrieved default profile credentials from ~/.azure/credentials.')
            return default_credentials

        return None

    @property
    def storage_client(self):
        self.log('Creating ARM client...')
        if not self._storage_client:
            self._storage_client = StorageManagementClient(
                StorageManagementClientConfiguration(self.azure_credentials, self.subscription_id))

        # TODO: only attempt to register provider on a well-known unregistered provider error
        #try:
        #    if not self._resource_client:
        #        self._resource_client = ResourceManagementClient(
        #            ResourceManagementClientConfiguration(self.azure_credentials, self.subscription_id))
        #        self._resource_client.providers.register('Microsoft.Storage')
        #except:
            # fail

        return self._storage_client

    @property
    def network_client(self):
        self.log('Getting network client')
        if not self._network_client:
            self._network_client = NetworkResourceProviderClient(
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
        # TODO: only attempt to register provider on a well-known unregistered provider error
        # if not self._resource_client:
        #    self._resource_client = ResourceManagementClient(
        #        ResourceManagementClientConfiguration(self.azure_credentials, self.subscription_id))
        # self._resource_client.providers.register('Microsoft.Compute')
        return self._compute_client
