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
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
except:
    # This is handled in azure_rm_common
    pass


DOCUMENTATION = '''
---
module: azure_rm_virtualmachineimage_facts

short_description: Get virtual machine image facts.

description:
    - Get facts for.

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
    name:
        description:
            - Only show results for a specific security group.
        default: null
    resource_group:
        description:
            - Name of a resource group. List publishers available to a particular resource group.
        required: true
        default: null

    location:
        description:
            - Azure location value. Defaults to the location of the resource group.
        default: null
    publisher:
        description:
            - Name of an image publisher. List image offerings associated with a particular publisher.
        default: null
    offer:
        description:
            - Name of an image offering. Combine with sku to see a list of available image versions.
        default:
    sku:
        description:
            - Image offering SKU. Combine with offer to see a list of available versions.
        default: null
    version:
        description:
            - Specific version number of an image.
        default: null

requirements:
    - "python >= 2.7"
    - "azure >= 2.0.0"

authors:
    - "Chris Houseknecht house@redhat.com"
    - "Matt Davis mdavis@redhat.com"
'''

EXAMPLES = '''
    - name: Get facts for a specific image
      azure_rm_virtualmachineimage_facts:
        resource_group: Testing
        publisher: OpenLogic
        offer: CentOS
        sku: '7.1'
        version: '7.1.20160308'

    - name: List available versions
      azure_rm_virtualmachineimage_facts:
        resource_group: Testing
        publisher: OpenLogic
        offer: CentOS
        sku: '7.1'

    - name: List available offers
      azure_rm_virtualmachineimage_facts:
        resource_group: Testing
        publisher: OpenLogic

    - name: List available publishers
      azure_rm_virtualmachineimage_facts:
        resource_group: Testing

'''

RETURNS = '''

'''


class AzureRMVirtualMachineImageFacts(AzureRMModuleBase):

    def __init__(self, **kwargs):

        self.module_arg_spec = dict(
            resource_group=dict(type='str'),
            location=dict(type='str'),
            publisher=dict(type='str'),
            offer=dict(type='str'),
            sku=dict(type='str'),
            version=dict(type='str')
        )

        super(AzureRMVirtualMachineImageFacts, self).__init__(self.module_arg_spec, **kwargs)

        self.results = dict(
            changed=False,
            results=[]
        )

        self.resource_group=None
        self.location = None
        self.publisher = None
        self.offer = None
        self.sku = None
        self.version = None

    def exec_module_impl(self, **kwargs):

        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        resource_group = self.get_resource_group(self.resource_group)
        if not self.location:
            # Set default location
            self.location = resource_group.location

        if self.location and self.publisher and self.offer and self.sku and self.version:
            self.results['results'] = [self.get_item()]
        elif self.location and self.publisher and self.offer and self.sku:
            self.results['results'] = self.list_images()
        elif self.location and self.publisher:
            self.results['results'] = self.list_offers()
        elif self.location:
            self.results['results'] = self.list_publishers()

        return self.results

    def get_item(self):
        item = None
        item_dict = dict()

        try:
            item = self.compute_client.virtual_machine_images.get(self.location,
                                                                  self.publisher,
                                                                  self.offer,
                                                                  self.sku,
                                                                  self.version)
        except CloudError:
            pass

        if item:
            item_dict = self.serialize_obj(item, 'VirtualMachineImage')

        return item_dict

    def list_images(self):
        response = None
        results = []
        try:
            response = self.compute_client.virtual_machine_images.list(self.location,
                                                                       self.publisher,
                                                                       self.offer,
                                                                       self.sku,)
        except CloudError:
            pass
        except Exception, exc:
            self.fail("Failed to list images: {0}".format(str(exc)))

        if response:
            for item in response:
                results.append(self.serialize_obj(item, 'VirtualMachineImageResource'))
        return results

    def list_offers(self):
        response = None
        results = []
        try:
            response = self.compute_client.virtual_machine_images.list_offers(self.location,
                                                                              self.publisher)
        except CloudError:
            pass
        except Exception, exc:
            self.fail("Failed to list offers: {0}".format(str(exc)))

        if response:
            for item in response:
                results.append(self.serialize_obj(item, 'VirtualMachineImageResource'))
        return results

    def list_publishers(self):
        response = None
        results = []
        try:
            response = self.compute_client.virtual_machine_images.list_publishers(self.location)
        except CloudError:
            pass
        except Exception, exc:
            self.fail("Failed to list publishers: {0}".format(str(exc)))

        if response:
            for item in response:
                results.append(self.serialize_obj(item, 'VirtualMachineImageResource'))
        return results


def main():
    if '--interactive' in sys.argv:
        # import the module here so we can reset the default complex args value
        import ansible.module_utils.basic

        ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
            resource_group='Testing',
            publisher='OpenLogic',
            offer='CentOS',
            sku='7.1'
        ))

    AzureRMVirtualMachineImageFacts().exec_module()

if __name__ == '__main__':
    main()

