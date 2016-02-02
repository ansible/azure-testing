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
import json

from os.path import expanduser

AZURE_COMMON_ARGS = dict(
    profile=dict(type='str'),
    subscription_id=dict(type='str'),
    client_id=dict(type='str'),
    client_secret=dict(type='str'),
    tenant_id=dict(type='str'),
    log_path=dict(type='str'),
    log_mode=dict(type='str', choices=['stderr','file','syslog'], default='syslog'),
    filter_logger=dict(type='bool', default=True),
    debug=dict(type='bool', default=False),
)

AZURE_COMMON_REQUIRED_IF = [
    ('log_mode', 'file', ['log_path'])
]

try:
    from azure.mgmt.common import SubscriptionCloudCredentials
    from azure.mgmt.network import NetworkResourceProviderClient
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.storage import StorageManagementClient
    from azure.mgmt.compute import ComputeManagementClient
    from azure.mgmt.compute import ComputeManagementClient
except ImportError:
    # TODO: use pretty JSON fail, but fail EARLY so derived imports don't need to check
    raise Exception("The Azure python sdk is not installed (try 'pip install azure')")

try:
    import requests
except ImportError:
    # TODO: use pretty JSON fail, but fail EARLY so derived imports don't need to check
    raise Exception("The requests python module is not installed (try 'pip install requests')")

# if we're being run as a Python module, import module_utils/basic stuff
if __name__ != '__main__':
    from ansible.module_utils.basic import *

class AzureRMModuleBase(object):

    def __init__(self, derived_arg_spec, supports_check_mode=False):
        self._logger =  logging.getLogger(self.__class__.__name__)

        merged_arg_spec = dict()
        merged_arg_spec.update(AZURE_COMMON_ARGS)
        if derived_arg_spec:
            merged_arg_spec.update(derived_arg_spec)

        # TODO: support merging required_if, others from derived classes
        self._module = AnsibleModule(argument_spec=merged_arg_spec, supports_check_mode=supports_check_mode, required_if=AZURE_COMMON_REQUIRED_IF)

        self._network_client = None
        self._storage_client = None
        self._resource_client = None
        self._compute_client = None

        self._log_mode = self._module.params.get('log_mode')
        self._filter_logger = self._module.params.get('filter_logger')

        self.debug = self._logger.debug

        if self._log_mode == 'syslog':
            # TODO: bridge this to module.debug() with a logger handler
            pass
        elif self._log_mode == 'file':
            self._log_path = self._module.params.get('log_path')
            logging.basicConfig(level=logging.DEBUG, filename=self._log_path)
        elif self._log_mode == 'stderr':
            logging.basicConfig(level=logging.DEBUG, stream=sys.stderr)

        if self._filter_logger:
            for h in logging.root.handlers:
                h.addFilter(logging.Filter(name=self._logger.name))

        self._credentials = self.__get_credentials(self._module.params)
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
        
        self.debug('Getting credentials')

        profile = params.get('profile')
        subscription_id = params.get('subscription_id')
        client_id = params.get('client_id')
        client_secret = params.get('client_secret')
        tenant_id = params.get('tenant_id')

        # try module params
        if profile:
           self.debug('Retrieving credentials with profile parameter.')
           creds = self.__parse_creds(profile)
           return creds
        
        if subscription_id and client_id and client_secret and tenant_id:
           self.debug('Received credentials from parameters.')
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
            self.debug('Received credentials from env.')
            return env_creds

        # try default profile from ~./azure/credentials
        def_creds = self.__parse_creds()
        if def_creds:
            self.debug('Retrieved default profile credentials from ~/.azure/credentials.')
            return def_creds

        return None

    def __get_token_from_client_credentials(self):
        self.debug('Getting auth token...')
        payload = {
            'grant_type': 'client_credentials',
            'client_id': self._credentials['client_id'],
            'client_secret': self._credentials['client_secret'],
            'resource': 'https://management.core.windows.net/',
        }
       
        response = requests.post(self._auth_endpoint, data=payload).json()
        if 'error_description' in response:
           self.debug('error: %s ' % response['error_description'])
           self._module.fail_json(msg='Failed getting OAuth token: %s' % response['error_description'])
        return response['access_token']

    def exec_module(self):
        res = self.exec_module_impl(**self._module.params)

        self._module.exit_json(**res)

    @property
    def compute_client(self):
        self.debug('Getting compute client')

        # TODO: store lazy-init credentials on AzureRM object so we only do this once

        auth_token = self.__get_token_from_client_credentials()

        self.debug('Creating credential object...')

        creds = SubscriptionCloudCredentials(self.credentials['subscription_id'], auth_token)

        self.debug('Creating ARM client...')

        compute_client = ComputeManagementClient(creds)
        #resource_client = ResourceManagementClient(creds)

        # TODO: only attempt to register provider on a well-known unregistered provider error
        #
        # try:
        #     # registering is supposed to be a one-time thing. How do we know if it has already been done?
        #     resource_client.providers.register('Microsoft.Compute')
        # except Exception as e:
        #     self.debug(str(e.args[0]))

        return compute_client

    @property
    def storage_client(self):
        self.debug('Getting storage client')
        # TODO: store lazy-init credentials on AzureRM object so we only do this once

        self.debug('Creating ARM client...')
        if not self._storage_client:
            self._storage_client = StorageManagementClient(self._creds)
        if not self._resource_client:
            self._resource_client = ResourceManagementClient(self._creds)
        self._resource_client.providers.register('Microsoft.Storage')
        return self._storage_client

    @property
    def network_client(self):
        # except Exception as e:
        #     self.debug(str(e.args[0]))
        #
        self.debug('Getting network client')
        if not self._network_client:
            self._network_client = NetworkResourceProviderClient(self._creds)
        return self._network_client

    @property
    def resource_client(self):

        #resource_client = ResourceManagementClient(creds)

        # TODO: only attempt to register provider on a well-known unregistered provider error
        # try:
        #     # registering is supposed to be a one-time thing. How do we know if it has already been done?
        #     resource_client.providers.register('Microsoft.Network')
        # except Exception as e:
        #     self.debug(str(e.args[0]))
        #
        self.debug('Getting resource manager client')
        if not self._resource_client:
            self._resource_client = ResourceManagementClient(self._creds)
        return self._resource_client

    @property
    def compute_client(self):
        self.debug('Getting compute client')
        if not self._compute_client:
            self._compute_client = ComputeManagementClient(self._creds)
        if not self._resource_client:
            self._resource_client = ResourceManagementClient(self._creds)
        self._resource_client.providers.register('Microsoft.Compute')
        return self._compute_client


