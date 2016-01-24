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
from os.path import expanduser


AZURE_COMMON_ARGS = dict(
    profile=dict(type='str'),
    subscription_id=dict(type='str'),
    client_id=dict(type='str'),
    client_secret=dict(type='str'),
    tenant_id=dict(type='str'),
    debug=dict(type='bool', default=False),
)

HAS_AZURE = True
HAS_REQUESTS = True

try:
    from azure.mgmt.common import SubscriptionCloudCredentials
    from azure.mgmt.network import NetworkResourceProviderClient
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.compute import ComputeManagementClient
except ImportError:
    HAS_AZURE = False

try:
    import requests
except ImportError:
    HAS_REQUESTS = False


class AzureRM(object):

    def __init__(self, module):
        if not HAS_AZURE:
            raise Exception("The Azure python sdk is not installed (try 'pip install azure')")

        if not HAS_REQUESTS:
            raise Exception("The requests python module is not installed (try 'pip install requests')")

        self._module = module
        self._network_client = None
        self._storage_client = None
        self._resource_client = None
        self._compute_client = None
        self._debug = self._module.params.get('debug')
        self.log = module.debug

        self._credentials = self.__get_credentials(module.params)
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
            self._module.fail_json(msg="Failed to access %s. Check that the file exists and you have read access." % path)

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
                self._module.fail_json(msg="Failed to get %s for profile %s in ~/.azure/credentials" % (key, profile))
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

    def __get_credentials(self, params):
        # Get authentication credentials.
        # Precedence: module parameters-> environment variables-> default profile in ~/.azure/credentials.
        
        self.log('Getting credentials')

        profile = params.get('profile')
        subscription_id = params.get('subscription_id')
        client_id = params.get('client_id')
        client_secret = params.get('client_secret')
        tenant_id = params.get('tenant_id')

        # try module params
        if profile:
           self.log('Retrieving credentials with profile parameter.')
           creds = self.__parse_creds(profile)
           return creds
        
        if subscription_id and client_id and client_secret and tenant_id:
           self.log('Received credentials from parameters.')
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
            self.log('Received credentials from env.')
            return env_creds

        # try default profile from ~./azure/credentials
        def_creds = self.__parse_creds()
        if def_creds:
            self.log('Retrieved default profile credentials from ~/.azure/credentials.')
            return def_creds

        return None

    def __get_token_from_client_credentials(self):
        self.log('Getting auth token...')
        payload = {
            'grant_type': 'client_credentials',
            'client_id': self._credentials['client_id'],
            'client_secret': self._credentials['client_secret'],
            'resource': 'https://management.core.windows.net/',
        }
       
        response = requests.post(self._auth_endpoint, data=payload).json()
        if 'error_description' in response:
           self.log('error: %s ' % response['error_description'])
           self._module.fail_json(msg='Failed getting OAuth token: %s' % response['error_description'])
        return response['access_token']

    @property
    def storage_client(self):
        self.log('Creating ARM client...')
        if not self._storage_client:
            self._storage_client = StorageManagementClient(self._creds)
        if not self._resource_client:
            self._resource_client = ResourceManagementClient(self._creds)
        self._resource_client.providers.register('Microsoft.Storage')
        return self._storage_client

    @property
    def network_client(self):
        self.log('Getting network client')
        if not self._network_client:
            self._network_client = NetworkResourceProviderClient(self._creds)
        return self._network_client

    @property
    def rm_client(self):
        self.log('Getting resource manager client')
        if not self._resource_client:
            self._resource_client = ResourceManagementClient(self._creds)
        return self._resource_client

    @property
    def compute_client(self):
        self.log('Getting compute client')
        if not self._compute_client:
            self._compute_client = ComputeManagementClient(self._creds)
        if not self._resource_client:
            self._resource_client = ResourceManagementClient(self._creds)
        self._resource_client.providers.register('Microsoft.Compute')
        return self._compute_client

def azure_module(**kwargs):
    # Append the common args to the argument_spec
    argument_spec = dict()
    argument_spec.update(AZURE_COMMON_ARGS)
    if kwargs.get('argument_spec'):
        argument_spec.update(kwargs['argument_spec'])
    kwargs['argument_spec'] = argument_spec
    module = AnsibleModule(**kwargs)
    return module

