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
    from azure.mgmt.network.models import PublicIPAddress, PublicIPAddressDnsSettings
    from azure.mgmt.network.models.network_management_client_enums import IPAllocationMethod
except ImportError:
    # This is handled in azure_rm_common
    pass


DOCUMENTATION = '''
---
module: azure_rm_publicipaddress

short_description: Manage Azure Public IP Addresses.

description:
    - Create, update and delete Public IPs. Allows setting and updating the address allocation method and domain
      name label prefix CIDR, which must be valid within the context of the virtual network. Use the
      azure_rm_networkinterface module to associate an interface with the public IP address.
    - For authentication with Azure you can pass parameters, set environment variables or use a profile stored
      in ~/.azure/credentials. Authentication is possible using a service principal or Active Directory user.
    - To authenticate via service principal pass subscription_id, client_id, secret and tenant or set set environment
      variables AZURE_SUBSCRIPTION_ID, AZURE_CLIENT_ID, AZURE_SECRET and AZURE_TENANT.
    - To Authentication via Active Directory user pass ad_user and password, or set AZURE_AD_USER and
      AZURE_PASSWORD in the environment.
    - Alternatively, credentials can be stored in ~/.azure/credentials. This is an ini file containing
      a [default] section and the following keys: subscription_id, client_id, secret and tenant or
      ad_user and password. It is also possible to add additional profiles. Specify the profile
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
    resource_group:
        description:
            - name of resource group.
        required: true
        default: null
    name:
        description:
            - name of the subnet.
        required: true
        default: null
    state:
        description:
            - Assert the state of the subnet. Use 'present' to create or update a subnet and
              'absent' to delete a subnet.
        required: true
        default: present
        choices:
            - absent
            - present
    location:
        description:
            - Valid azure location. Defaults to location of the resource group.
        default: resource_group location
    tags:
        description:
            - Dictionary of string:string pairs to assign as metadata to the object. Treated as the explicit metadata
              for the object. In other words, existing metadata will be replaced with provided values. If no values
              provided, existing metadata will be removed.
        required: false
        default: null
    allocation_method:
        description:
            - Set to 'static' or 'dynamic' to control whether the assigned IP is permanent or ephemeral.
        choices:
            - Dyanmic
            - Static
        default: Dynamic
    domain_name_label:
        description:
            - The customizable portion of the FQDN assigned to public IP address. This is an explicit setting. If
              no value is provided, any existing value will be removed on an existing public IP.
        default: null
        aliases:
            - domain_name_label

requirements:
    - "python >= 2.7"
    - "azure >= 1.0.2"

authors:
    - "Matt Davis <mdavis@ansible.com>"
    - "Chris Houseknecht @chouseknecht"
'''

EXAMPLES = '''
    - name: Create a public ip address
      azure_rm_publicipaddress:
        resource_group: testing
        location: eastus
        name: my_public_ip
        allocation_method: static
        domain_name: foobar

    - name: Delete public ip
      azure_rm_publicipaddress:
        resource_group: testing
        name: my_public_ip
        state: absent
'''


NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]{1,61}[a-z0-9]$")


def pip_to_dict(pip):
    result = dict(
        name=pip.name,
        type=pip.type,
        location=pip.location,
        tags=pip.tags,
        public_ip_allocation_method=pip.public_ip_allocation_method.value,
        dns_settings=dict(),
        ip_address=pip.ip_address,
        idle_timeout_in_minutes=pip.idle_timeout_in_minutes,
        provisioning_state=pip.provisioning_state,
        etag=pip.etag
    )
    if pip.dns_settings:
        result['dns_settings']['domain_name_label'] = pip.dns_settings.domain_name_label
        result['dns_settings']['fqdn'] = pip.dns_settings.fqdn
        result['dns_settings']['reverse_fqdn'] = pip.dns_settings.reverse_fqdn
    return result


class AzureRMPublicIPAddress(AzureRMModuleBase):

    def __init__(self, **kwargs):

        self.module_arg_spec = dict(
            resource_group=dict(required=True),
            name=dict(required=True),
            state=dict(default='present', choices=['present', 'absent']),
            location=dict(type='str'),
            tags=dict(type='dict'),
            allocation_method=dict(type='str', default='Dynamic', choices=['Dynamic', 'Static']),
            domain_name=dict(type='str', aliases=['domain_name_label']),
            log_path=dict(type='str', default='azure_rm_publicipaddress.log')
        )

        super(AzureRMPublicIPAddress, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                     supports_check_mode=True, **kwargs)

        self.resource_group = None
        self.name = None
        self.location = None
        self.state = None
        self.tags = None
        self.allocation_method = None
        self.domain_name = None

        self.results = dict(
            changed=False,
            check_mode=self.check_mode,
            results={}
        )

    def exec_module_impl(self, **kwargs):

        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        results = dict()
        changed = False
        pip = None

        resource_group = self.get_resource_group(self.resource_group)
        if not self.location:
            # Set default location
            self.location = resource_group.location

        if not NAME_PATTERN.match(self.name):
            self.fail("Parameter error: name must begin with a letter or number, end with a letter or number "
                      "and contain at least one number.")

        try:
            self.log("Fetch public ip {0}".format(self.name))
            pip = self.network_client.public_ip_addresses.get(self.resource_group, self.name)
            self.check_provisioning_state(pip)
            self.log("PIP {0} exists".format(self.name))
            if self.state == 'present':
                results = pip_to_dict(pip)
                if self.domain_name != results['dns_settings'].get('domain_name_label'):
                    self.log('CHANGED: domain_name_label')
                    changed = True
                    results['dns_settings']['domain_name_label'] =self.domain_name

                if self.allocation_method != results['public_ip_allocation_method']:
                    self.log("CHANGED: allocation_method")
                    changed = True
                    results['public_ip_allocation_method'] = self.allocation_method

                if self.tags != results['tags']:
                    self.log("CHANGED: tags")
                    changed = True
                    results['tags'] = self.tags

            elif self.state == 'absent':
                self.log("CHANGED: public ip {0} exists but requested state is 'absent'".format(self.name))
                changed = True
        except CloudError:
            self.log('Public ip {0} does not exist'.format(self.name))
            if self.state == 'present':
                self.log("CHANGED: pip {0} does not exist but requested state is 'present'".format(self.name))
                changed = True

        self.results['results'] = results
        self.results['changed'] = changed

        if self.check_mode:
            return results
    
        if changed:
            if self.state == 'present':
                if not pip:
                    self.log("Create new Public IP {0}".format(self.name))
                    pip = PublicIPAddress(
                        location=self.location,
                        public_ip_allocation_method=self.allocation_method,
                    )
                    if self.tags:
                        pip.tags = self.tags
                    if self.domain_name:
                        pip.dns_settings = PublicIPAddressDnsSettings(
                            domain_name_label=self.domain_name
                        )
                else:
                    self.log("Update Public IP {0}".format(self.name))
                    pip = PublicIPAddress(
                        location=result['location'],
                        public_ip_allocation_method=results['public_ip_allocation_method'],
                        tags=results['tags']
                    )
                    if self.domain_name:
                        pip.dns_settings = PublicIPAddressDnsSettings(
                            domain_name_label=self.domain_name
                        )
                self.results['results'] = self.create_or_update_pip(pip)
            elif self.state == 'absent':
                self.log('Delete public ip {0}'.format(self.name))
                self.delete_pip()

        return self.results

    def create_or_update_pip(self, pip):
        try:
            poller = self.network_client.public_ip_addresses.create_or_update(self.resource_group, self.name, pip)
        except Exception, exc:
            self.fail("Error creating or updating {0} - {1}".format(self.name, str(exc)))
        pip = self.get_poller_result(poller)
        return pip_to_dict(pip)

    def delete_pip(self):
        try:
            poller = self.network_client.public_ip_addresses.delete(self.resource_group, self.name)
        except Exception, exc:
            self.fail("Error deleting {0} - {1}".format(self.name, str(exc)))
        self.get_poller_result(poller)
        # Delete returns nada. If we get here, assume that all is well.
        self.results['results']['status'] = 'Deleted'
        return True


def main():
    if '--interactive' in sys.argv:
        # import the module here so we can reset the default complex args value
        import ansible.module_utils.basic

        ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
            resource_group = "rm_demo",
            name = "test-publicip",
            state = "present",
            location = "West US",
            log_mode='stderr',
            #filter_logger=False,
        ))

    AzureRMPublicIPAddress().exec_module()

main()

