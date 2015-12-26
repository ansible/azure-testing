#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2015 Chris Houseknecht, <chouseknechtansible.com>
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

HAS_AZURE = True
HAS_REQUESTS = True

try:
    from azure.mgmt.common import SubscriptionCloudCredentials
    import azure.mgmt.network
    from azure.mgmt.resource import ResourceManagementClient
    from azure.mgmt.storage import StorageManagementClient
except ImportError:
    HAS_AZURE = False

try:
    import requests
except ImportError:
    HAS_REQUESTS = False



class azure_rm_log(object):
    def __init__(self, log_path=None):
        self.log_path = log_path

    def log(self, msg):
        #    print msg
        if not self.log_path:
            return
        with open(self.log_path, "a") as logfile:
            logfile.write("{0}\n".format(msg))


class azure_rm_resources(object):

    def __init__(self, params, log):
        if not HAS_AZURE:
            raise Exception("The Azure python sdk is not installed (try 'pip install azure')")

        if not HAS_REQUESTS:
            raise Exception("The requests python module is not installed (try 'pip install requests')")
        
        self.log = log
        
        self.credentials = self.__get_credentials(params)
        if not self.credentials:
            raise Exception("Failed to get credentials. Either pass as parameters, set environment variables, or define " +
                "a profile in ~/.azure/credientials.")
        self.auth_endpoint = "https://login.microsoftonline.com/%s/oauth2/token" % self.credentials['tenant_id']

    def __get_credentials_parser(self):
        path = expanduser("~")    
        path += "/.azure/credentials"
        p = ConfigParser.ConfigParser()
        try:
            p.read(path)
        except:
            raise Exception("Failed to access %s. Check that the file exists and you have read access." % path)
        return p 
    

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
            except:
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

    def __get_credentials(self, params):
        # Get authentication credentials.
        # Precedence: module parameters-> environment variables-> default profile in ~/.azure/credentials.
        
        self.log('Getting credentials')

        profile = params.get('profile')
        subscription_id = params.get('subscription_id')
        client_id = params.get('client_id')
        client_secret = params.get('client_id')
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
            'client_id': self.credentials['client_id'],
            'client_secret': self.credentials['client_secret'],
            'resource': 'https://management.core.windows.net/',
        }
       
        try:
            response = requests.post(self.auth_endpoint, data=payload).json()
            if 'error_description' in response:
               self.log('error: %s ' % response['error_description'])
               raise Exception('Failed getting OAuth token: %s' % response['error_description'])
        except Exception as e:
            raise Exception(e)

        return response['access_token']

    def get_storage_client(self):

        self.log('Getting storage client')
        
        auth_token = self.__get_token_from_client_credentials()

        self.log('Creating credential object...')

        creds = SubscriptionCloudCredentials(self.credentials['subscription_id'], auth_token)

        self.log('Creating ARM client...')

        storage_client = StorageManagementClient(creds)
        resource_client = ResourceManagementClient(creds)
        try:
            # registering is supposed to be a one-time thing. How do we know if it has already been done?
            resource_client.providers.register('Microsoft.Storage')
        except Exception as e:
            self.log(str(e.args[0]))

        return storage_client

    def get_network_client(self):
        
        self.log('Getting network client')

        auth_token = self.__get_token_from_client_credentials()

        self.log('Creating credential object...')

        creds = SubscriptionCloudCredentials(self.credentials['subscription_id'], auth_token)

        self.log('Creating ARM client...')

        network_client = azure.mgmt.network.NetworkResourceProviderClient(creds)

        return network_client

