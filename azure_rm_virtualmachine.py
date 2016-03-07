#!/usr/bin/python
#
# (c) 2015 Matt Davis, <mdavis@ansible.com>
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

DOCUMENTATION = '''
---
module: azure_rm_virtualmachine
'''



import re
from collections import namedtuple
import sys
# normally we'd put this at the bottom to preserve line numbers, but we can't use a forward-defined base class
# without playing games with __metaclass__ or runtime base type hackery.
# TODO: figure out a better way...
from ansible.module_utils.basic import *

# Assumes running ansible from source and there is a copy or symlink for azure_rm_common
# found in local lib/ansible/module_utils
from ansible.module_utils.azure_rm_common import *


from azure.common import AzureMissingResourceHttpError
from azure.mgmt.common import SubscriptionCloudCredentials
from azure.storage.blob import BlobService
import azure.mgmt.compute


class AzureRMVirtualMachine(AzureRMModuleBase):   
    def __init__(self, **kwargs):
        module_arg_spec = dict(
            # TODO: configure arg validation
            resource_group=dict(required=True),
            name=dict(required=True),
            state=dict(choices=['present','absent'], type='str'),
            location=dict(required=True),
            short_hostname=dict(),
            vm_size=dict(),
            admin_username=dict(),
            admin_password=dict(),
            image_publisher=dict(),
            image_offer=dict(),
            image_sku=dict(),
            image_version=dict(),
            os_disk_storage_account_name=dict(),
            os_disk_storage_container_name=dict(),
            os_disk_storage_blob_name=dict(),
            os_type=dict(),
            nic_ids=dict(type='list'),
            delete_nics=dict(type='bool'),
            delete_vhds=dict(type='bool'),
            delete_public_ips=dict(type='bool'),

            # TODO: implement tags
            # TODO: implement object security
        )

        AzureRMModuleBase.__init__(self, derived_arg_spec=module_arg_spec, supports_check_mode=True, **kwargs)

    

    def _extract_names_from_uri_id(self, uri_id):
        self.debug("extracting names from resource id uri '%s'" % uri_id)
        # HACK: ditch this once python SDK supports get by URI
        m = re.match('^/subscriptions/[\da-fA-F\-]+/resourceGroups/(?P<rg_name>[^/]+)/providers/[^/]+/[^/]+/(?P<name>[^/]+)', uri_id)
        if not m:
            raise Exception("unable to parse uri_id '%s'" % uri_id)

        extracted_names = m.groupdict()

        self.debug("extracted names: %s" % str(extracted_names))

        return extracted_names


    def _extract_names_from_blob_uri(self, blob_uri):
        self.debug("extracting blob info from uri '%s'" % blob_uri)
        # HACK: ditch this once python SDK supports get by URI
        m = re.match('^https://(?P<accountname>[^\.]+)\.blob\.core\.windows\.net/(?P<containername>[^/]+)/(?P<blobname>.+)$', blob_uri)
        if not m:
            raise Exception("unable to parse blob uri '%s'" % blob_uri)

        extracted_names = m.groupdict()

        self.debug("extracted names: %s" % str(extracted_names))

        return extracted_names

    # HACK: since the storage client won't take a URI, we have to list all in the subscription,
    # reverse the name from the blob uri and find it in the list, then reverse the resource group
    # from the id so we can get the keys. Yuck!
    def _get_info_from_blob_uri(self, blob_uri):
        self.debug("getting info from blob uri '%s'" % blob_uri)
        blob_parts = self._extract_names_from_blob_uri(blob_uri)
        storage_account_name = blob_parts['accountname']
        container_name = blob_parts['containername']
        blob_name = blob_parts['blobname']

        self.debug("finding storage account named '%s'" % storage_account_name)
        list_resp = self.storage_client.storage_accounts.list().storage_accounts
        rg_names = [self._extract_names_from_uri_id(sa.id)['rg_name'] for sa in list_resp if sa.name == storage_account_name]

        if len(rg_names) != 1:
            raise Exception("couldn't find storage account in subscription for blob uri '%s'" % blob_uri)

        BlobInfo = namedtuple('BlobInfo', ['resource_group_name', 'storage_account_name', 'container_name', 'blob_name'])

        blob_info = BlobInfo(resource_group_name=rg_names[0], storage_account_name=storage_account_name, container_name=container_name, blob_name=blob_name)

        self.debug('blob info: %s' % str(blob_info))

        return blob_info

    def _delete_blob(self, blob_uri):
        self.debug("deleting blob '%s'" % blob_uri)
        blobinfo = self._get_info_from_blob_uri(blob_uri)

        self.debug("finding storage account keys for account '%s'" % blobinfo.storage_account_name)
        keys = self.storage_client.storage_accounts.list_keys(blobinfo.resource_group_name, blobinfo.storage_account_name)

        bs = BlobService(account_name=blobinfo.storage_account_name, account_key=keys.storage_account_keys.key1)

        # TODO: check lease status, break if necessary

        self.debug("deleting blob {0} from container {1} in storage account {2}".format(blobinfo.blob_name, blobinfo.container_name, blobinfo.storage_account_name))
        res = bs.delete_blob(container_name=blobinfo.container_name, blob_name=blobinfo.blob_name)
        self.debug("delete successful")

    def _delete_nic(self, nic_uri):
        self.debug("deleting nic '%s'" % nic_uri)
        nicinfo = self._extract_names_from_uri_id(nic_uri)
        del_resp = self.network_client.network_interfaces.delete(nicinfo['rg_name'], nicinfo['name'])

        if del_resp.error:
            raise Exception("error deleting nic '{0}': {1}".format(nic_uri, del_resp.error.message))

        self.debug('delete successful')

    def _delete_public_ip(self, public_ip_uri):
        # TODO: this is failing...
        self.debug("deleting public ip '%s'" % public_ip_uri)
        pipinfo = self._extract_names_from_uri_id(public_ip_uri)
        del_resp = self.network_client.public_ip_addresses.delete(pipinfo['rg_name'], pipinfo['name'])

        if del_resp.error:
            raise Exception("error deleting public ip'{0}': {1}".format(public_ip_uri, del_resp.error.message))

        self.debug('delete successful')

    def exec_module_impl(self,
                    resource_group,
                    name,
                    state,
                    location,
                    short_hostname=None,
                    vm_size=None,
                    admin_username=None,
                    admin_password=None,
                    image_publisher=None,
                    image_offer=None,
                    image_sku=None,
                    image_version=None,
                    os_disk_storage_account_name=None,
                    os_disk_storage_container_name='vhds',
                    os_disk_storage_blob_name=None,
                    os_type=None,
                    nic_ids=[],
                    delete_nics=True,
                    delete_vhds=True,
                    delete_public_ips=True,
                    **kwargs):

        result = dict(changed=False)
        vm_exists = False

        try:
            self.debug('fetching vm...')
            vm_resp = self.compute_client.virtual_machines.get(resource_group, name)
            # TODO: check if resource_group.provisioningState != Succeeded or Deleting, equiv to 404 but blocks
            # TODO: attempt to delete/rebuild provisioning state 'Failed'?
            vm_exists = True
            self.debug('vm exists...')
            vm = vm_resp.virtual_machine

            if state == 'present':
                self.debug('validating vm attributes against args...')
                # TODO: validate attributes (name, tags, what else?)

            elif state == 'absent':
                # TODO: plug vm_exists checks here for "needs deletion" or non-standard error
                self.debug("CHANGED: vhd exists and requested state is 'absent'")
                result['changed'] = True # we should hit the exception handler below if the vm doesn't exist, so we know it does

                if delete_vhds:
                    # store the attached vhd info so we can nuke it after the VM is gone
                    self.debug('storing vhd uris for later deletion...')
                    vhd_uris = [vm.storage_profile.os_disk.virtual_hard_disk.uri]
                    self.debug("vhd uris to delete are '%s'" % vhd_uris)
                    result['deleted_vhd_uris'] = vhd_uris
                    # TODO: add support for deleting data disk vhds

                if delete_nics:
                    # store the attached nic info so we can nuke them after the VM is gone
                    self.debug('storing nic uris for later deletion...')
                    nic_uris = [n.reference_uri for n in vm.network_profile.network_interfaces]
                    if delete_public_ips:
                        # also store each nic's attached public IPs and delete after the NIC is gone
                        public_ip_uris = []
                        for nic_uri in nic_uris:
                            nic_info = self._extract_names_from_uri_id(nic_uri)
                            nic = self.network_client.network_interfaces.get(nic_info['rg_name'], nic_info['name']).network_interface
                            public_ip_uris.extend([ipc.public_ip_address for ipc in nic.ip_configurations if ipc.public_ip_address])
                    self.debug('nic uris to delete are %s' % nic_uris)
                    result['deleted_nic_uris'] = nic_uris
                    self.debug('public ips to delete are %s' % public_ip_uris)
                    result['deleted_public_ips'] = public_ip_uris

                if self._module.check_mode:
                    return result

                del_resp = self.compute_client.virtual_machines.delete(resource_group, name)
                if del_resp.status != 'Succeeded':
                    raise Exception("Delete failed with status '%s'" % del_resp.status)

                # TODO: parallelize nic, vhd, and public ip deletions with begin_deleting
                # TODO: best-effort to keep deleting other linked resources if we encounter an error
                if delete_vhds:
                    self.debug('deleting vhds...')
                    for blob_uri in vhd_uris:
                        self._delete_blob(blob_uri)
                    self.debug('done deleting vhds...')

                if delete_nics:
                    self.debug('deleting nics...')
                    for nic_uri in nic_uris:
                        self._delete_nic(nic_uri)
                    self.debug('done deleting nics...')

                if delete_public_ips:
                    self.debug('deleting public ips...')
                    for public_ip_uri in public_ip_uris:
                        self._delete_public_ip(public_ip_uri)
                    self.debug('deleting public ips...')

                return result

        except AzureMissingResourceHttpError:
            self.debug('vm does not exist')
            if state == 'present':
                result['changed'] = True

        if state == 'present':
            if not vm_exists:
            # TODO: add this back in once we're ready to create a default nic
            # # ensure nic/pip exist
            # try:
            #     log('fetching nic...')
            #     nic_resp = network_client.network_interfaces.get(resource_group, network.get('virtual_nic_name'))
            #     nic_id = nic_resp.network_interface.id
            # except AzureMissingResourceHttpError:
            #     log('nic does not exist...')
            #     # TODO: create nic
            #     raise Exception('nic does not exist')

                if not isinstance(nic_ids, list):
                    nic_ids = [ nic_ids ]

                network_interfaces = [azure.mgmt.compute.NetworkInterfaceReference(reference_uri=x) for x in nic_ids]

                if not os_disk_storage_blob_name:
                    os_disk_storage_blob_name = name + '.vhd'

                vm_resource = azure.mgmt.compute.VirtualMachine(
                    location=location,
                    name=name,
                    os_profile=azure.mgmt.compute.OSProfile(
                        admin_username=admin_username,
                        admin_password=admin_password,
                        computer_name=short_hostname,
                    ),
                    hardware_profile=azure.mgmt.compute.HardwareProfile(
                        virtual_machine_size=vm_size
                    ),
                    storage_profile=azure.mgmt.compute.StorageProfile(
                        os_disk=azure.mgmt.compute.OSDisk(
                            # TODO: as arg
                            caching=azure.mgmt.compute.CachingTypes.read_only,
                            # TODO: support attach/empty
                            create_option=azure.mgmt.compute.DiskCreateOptionTypes.from_image,
                            name=os_disk_storage_blob_name,
                            virtual_hard_disk=azure.mgmt.compute.VirtualHardDisk(
                                uri='https://{0}.blob.core.windows.net/{1}/{2}.vhd'.format(
                                    os_disk_storage_account_name,
                                    os_disk_storage_container_name or 'vhds',
                                    os_disk_storage_blob_name,
                                ),
                            ),
                        ),
                        image_reference = azure.mgmt.compute.ImageReference(
                            publisher=image_publisher,
                            offer=image_offer,
                            sku=image_sku,
                            version=image_version,
                        ),
                    ),
                    network_profile = azure.mgmt.compute.NetworkProfile(
                        network_interfaces=network_interfaces
                    ),
                )
                self.debug('creating vm...')
                vm_resp = self.compute_client.virtual_machines.create_or_update(resource_group, vm_resource)

                # TODO: improve error-handling
                if vm_resp.error:
                    raise Exception('provisioning failed: %s' % vm_resp.error.message)

                # TODO: check vm_resp for success or long-running response (that we need to poll on)
                # TODO: use begin_create_or_update so our async pattern is clean

                self.debug('fetching vm post-create...')
                vm_resp = self.compute_client.virtual_machines.get(resource_group, name)
                vm = vm_resp.virtual_machine


            # TODO: reuse this code section for check mode

            for nic_ref in vm.network_profile.network_interfaces:
                nic_values = self._extract_names_from_uri_id(nic_ref.reference_uri)
                nic_resp = self.network_client.network_interfaces.get(nic_values.get('rg_name'), nic_values.get('name'))
                nic = nic_resp.network_interface
                is_primary = nic.primary
                # TODO: can there be more than one?

                if is_primary:
                    ip_cfg = nic.ip_configurations[0]
                    result['primary_private_ip'] = ip_cfg.private_ip_address
                    public_ip_ref = ip_cfg.public_ip_address
                    if public_ip_ref: # look up the public ip object to get the address
                        pip_values = self._extract_names_from_uri_id(public_ip_ref.id)
                        pip_resp = self.network_client.public_ip_addresses.get(pip_values.get('rg_name'), pip_values.get('name'))
                        result['primary_public_ip'] = pip_resp.public_ip_address.ip_address

        return result


def main():
    # standalone debug setup
    if '--interactive' in sys.argv:
        # early import the module and reset the complex args
        import ansible.module_utils.basic

        ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
            resource_group='rm_demo',
            name='mdavis-test1-vm',
            state='present',
            location='West US',
            short_hostname='mdavis-test1-vm',
            vm_size='Standard_A1',
            admin_username='mdavis',
            admin_password='R00tpassword#',
            image_publisher='MicrosoftWindowsServer',
            image_offer='WindowsServer',
            image_sku='2012-R2-Datacenter',
            image_version='4.0.20151214',
            os_disk_storage_account_name='test',
            os_disk_storage_container_name='vhds',
            os_disk_storage_blob_name='mdavis-test1-vm',
            os_type='windows',
            delete_nics=True,
            delete_vhds=True,
            delete_public_ips=True,
            nic_ids=['/subscriptions/3f7e29ba-24e0-42f6-8d9c-5149a14bda37/resourceGroups/rm_demo/providers/Microsoft.Network/networkInterfaces/test-nic'],
            log_mode="stderr"
        ))

    AzureRMVirtualMachine().exec_module()

main()

