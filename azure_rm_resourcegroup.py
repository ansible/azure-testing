#!/usr/bin/python
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

# normally we'd put this at the bottom to preserve line numbers, but we can't use a forward-defined base class
# without playing games with __metaclass__ or runtime base type hackery.
# TODO: figure out a better way...
from ansible.module_utils.basic import *
from ansible.module_utils.azure_rm_common import *


try:
    from msrestazure.azure_exceptions import CloudError
    from azure.common import AzureMissingResourceHttpError
    from azure.mgmt.resource.resources.models import ResourceGroup
except ImportError:
    pass


DOCUMENTATION = '''
---
module: azure_rm_resourcegroup
short_description: Manage Azure resource groups.

description:
    - Create, update and delete resource groups. Allows setting and updating resource group tags. Use the other
      Azure modules to associate resource with a resource group.
    - For authentication with Azure you can pass parameters, set environment variables or use a profile stored
      in ~/.azure/credentials. Authentication is possible using a service principal or Active Directory user.
    - To authenticate via service principal pass subscription_id, client_id, secret and tenant or set set environment
      variables AZURE_SUBSCRIPTION_ID, AZURE_CLIENT_ID, AZURE_SECRET and AZURE_TENANT.
    - To Authentication via Active Directory user pass ad_user and password, or set AZURE_AD_USER and
      AZURE_PASSWORD in the environment.
    - Alternatively, credentials can be stored in ~/.azure/credentials. This is an ini file containing
      a [default] section and the following keys: subscription_id, client_id, secret and tenant or
      ad_user and password. It is also possible to add addition profiles to this file. Specify the profile
      by passing profile or setting AZURE_PROFILE in the environment.

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
    secret:
        description:
            - Azure client_secrent used for authentication.
        required: false
        default: null
    tenant:
        description:
            - Azure tenant_id used for authentication.
        required: false
        default: null
    force:
        description:
            - When state is absent, force the deletion of a resource group that contains resources. When force
              is true the resource group and all related resource will be removed.
        default: false
    location:
        description:
            - Azure location for the resource group. Required when creating a new resource group. Cannot
              be changed once resource group is created.
        default: null
    name:
        description:
            - Name of the resource group.
        required: true
        default: null
    state:
        description:
            - Assert the state of the resource group. Use 'present' to create or update and
              'absent' to delete.
        required: true
        default: present
        choices:
            - absent
            - present
    tags:
        description:
            - Dictionary of string:string pairs to assign as metadata to the object. Metadata tags on the object
              will be updated with any provided values. To remove tags use the purge_tags option.
        required: false
        default: null
    purge_tags:
        description:
            - Use to remove tags from an object. Any tags not found in the tags parameter will be removed from
              the object's metadata.
        default: false

requirements:
    - "python >= 2.7"
    - "azure >= 2.0.0"

authors:
    - "Matt Davis <mdavis@ansible.com>"
    - "Chris Houseknecht @chouseknecht"
'''

EXAMPLES = '''
    - name: Create a resource group
      azure_rm_resourcegroup:
        name: Testing
        location: westus
        tags:
            testing: testing
            delete: never

    - name: Delete a resource group
      azure_rm_resourcegroup:
        name: Testing
        state: absent
'''


def resource_group_to_dict(rg):
    return dict(
        id=rg.id,
        name=rg.name,
        location=rg.location,
        tags=rg.tags,
        provisioning_state=rg.properties.provisioning_state
    )


class AzureRMResourceGroup(AzureRMModuleBase):
    
    def __init__(self, **kwargs):
        self.module_arg_spec = dict(
            name=dict(type='str', required=True),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            location=dict(type='str'),
            log_path=dict(type='str', default='azure_rm_resourcegroup.log'),
            force=dict(type='bool', default=False)
        )
        super(AzureRMResourceGroup, self).__init__(self.module_arg_spec,
                                                   supports_check_mode=True,
                                                   supports_tags=True,
                                                   **kwargs)

        self.name = None
        self.state = None
        self.location = None
        self.tags = None
        self.force = None

        self.results = dict(
            changed=False,
            contains_resources=False,
            check_mode=self.check_mode,
            results=dict()
        )

    def exec_module_impl(self, **kwargs):

        for key in self.module_arg_spec.keys() + ['tags']:
            setattr(self, key, kwargs[key])

        results = dict()
        changed = False
        rg = None
        contains_resources = False

        self.log('args:')
        self.log(json.dumps(self.module.params), pretty_print=True)
        try:
            self.log('Fetching resource group {0}'.format(self.name))
            rg = self.rm_client.resource_groups.get(self.name)
            self.check_provisioning_state(rg)
            contains_resources = self.resources_exist()

            results = resource_group_to_dict(rg)
            if self.state == 'absent':
                self.log("CHANGED: resource group {0} exists but requested state is 'absent'".format(self.name))
                changed = True
            elif self.state == 'present':
                update_tags, results['tags'] = self.update_tags(results['tags'])
                if update_tags:
                    changed = True

                if self.location and self.location != results['location']:
                    self.fail("Resource group '{0}' already exists in location '{1}' and cannot be "
                              "moved.".format(self.name, results['location']))
        except CloudError:
            self.log('Resource group {0} does not exist'.format(self.name))
            if self.state == 'present':
                self.log("CHANGED: resource group {0} does not exist but requested state is "
                         "'present'".format(self.name))
                changed = True

        self.results['changed'] = changed
        self.results['results'] = results
        self.results['contains_resources'] = contains_resources

        if self.check_mode:
            return self.results

        if changed:
            if self.state == 'present':
                if not rg:
                    # Create resource group
                    self.log("Creating resource group {0}".format(self.name))
                    if not self.location:
                        self.fail("Parameter error: location is required when creating a resource "
                                  "group.".format(self.name))
                    if self.name_exists():
                        self.fail("Error: a resource group with the name {0} already exists in your subscription."
                                  .format(self.name))
                    params = ResourceGroup(
                        location=self.location,
                        tags=self.tags
                    )
                else:
                    # Update resource group
                    params = ResourceGroup(
                        location=results['location'],
                        tags=results['tags']
                    )
                self.results['results'] = self.create_or_update_resource_group(params)
            elif self.state == 'absent':
                if contains_resources and not self.force:
                    self.fail("Error removing resource group {0}. Resources exist within the group.".format(self.name))
                self.delete_resource_group()

        return self.results

    def create_or_update_resource_group(self, params):
        try:
            result = self.rm_client.resource_groups.create_or_update(self.name, params)
        except Exception, exc:
            self.fail("Error creating or updating resource group {0} - {1}".format(self.name, str(exc)))
        return resource_group_to_dict(result)

    def delete_resource_group(self):
        try:
            poller = self.rm_client.resource_groups.delete(self.name)
        except Exception, exc:
            self.fail("Error delete resource group {0} - {1}".format(self.name, str(exc)))

        self.get_poller_result(poller)
        # The delete operation doesn't return anything.
        # If we got here, assume all is good
        self.results['results'] = 'Deleted'
        return True

    def resources_exist(self):
        found = False
        try:
            response = self.rm_client.resource_groups.list_resources(self.name)
        except Exception, exc:
            self.fail("Error checking for resource existence in {0} - {1}".format(self.name, str(exc)))
        for item in response:
            found = True
            break
        return found

    def name_exists(self):
        try:
            exists = self.rm_client.resource_groups.check_existence(self.name)
        except Exception, exc:
            self.fail("Error checking for existence of name {0}".format(self.name))
        return exists


def main():
    if '--interactive' in sys.argv:
        # import the module here so we can reset the default complex args value
        import ansible.module_utils.basic

        ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
            name='mdavis-test-rg5',
            state='present',
            location='West US',
            log_mode='stderr'
        ))

    AzureRMResourceGroup().exec_module()

main()

