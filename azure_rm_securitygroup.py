#!/usr/bin/python
# -*- coding: utf-8 -*-
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

import ConfigParser
import os

from os.path import expanduser


def get_credentials_parser(module):
    path = expanduser("~")    
    path += "/.azure/credentials"
    p = ConfigParser.ConfigParser()
    try:
        p.read(path)
    except:
        module.fail_json(msg="Failed to access %s. Check that the file exists and you have read access." % path)
    return p 
    

def parse_creds(module, parser, profile="default"):
    creds = dict(
        subscription_id = "",
        client_id = "",
        client_secret = ""
    )
    for key in creds:
        try:
            creds[key] = parser.get(profile, key, raw=True)       
        except:
            module.fail_json(msg="Failed to retrieve %s for profile %s in ~/.azure credentials" % (key, profile))
    return creds

def get_env_creds(module):
    profile = os.environ.get('AZURE_PROFILE', None)
    subscription_id = os.environ.get('AZURE_SUBSCRIPTION_ID', None)
    client_id = os.environ.get('AZURE_CLIENT_ID', None)
    client_secret = os.environ.get('AZURE_CLIENT_SECRET', None)

    if profile:
        p = get_credentials_parser(module)
        creds = parse_creds(module, p, profile)
        return creds 

    if subscription_id and client_id and client_secret:
        creds = dict(
            subscription_id = subscription_id,
            client_id = client_id,
            client_secret = client_secret
        )
        return creds

    return None


def get_credentials(module):
    profile = module.params.get('profile')
    subscription_id = module.params.get('subscription_id')
    client_id = module.params.get('client_id')
    client_secret = module.params.get('client_id') 

    # try module params
    if profile:
       p = get_credentials_parser(module)
       creds = parse_creds(module, p, profile)
       return creds
    
    if subscription_id and client_id and client_secret:
       creds = dict(
           subscription_id = subscription_id,
           client_id = client_id,
           client_secret = client_secret
       )
       return creds
    
    # try environment
    env_creds = get_env_creds(module)
    if env_creds:
        return env_creds

    # try default profile from ~./azure/credentials
    p = get_credentials_parser(module)
    creds = parse_creds(module, p)
    if creds:
        return creds

    return None
    

def main():
    module = AnsibleModule(
        argument_spec=dict(
            profile=dict(required=False, type='str'),
            subscription_id=dict(required=False, type='str'),
            client_id=dict(required=False, type='str'),
            client_secret=dict(required=False, type='str'),
            debug=dict(required=False, type='bool', default=False)
        ),
        supports_check_mode=False 
    )

    creds = get_credentials(module)
    if not creds:
        module.fail_json(msg="Failed to get credentials.")

    module.exit_json(changed=True, rc=0, credentials=creds)

# import module snippets
from ansible.module_utils.basic import *  # noqa

if __name__ == '__main__':
    main()
