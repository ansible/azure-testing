#!/usr/bin/python
#
# (c) 2016 Matt Davis, <mdavis@redhat.com>
#          Chris Houseknecht, <chouseknecht@redhat.com>
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
    from azure.mgmt.compute.models import NetworkInterfaceReference, VirtualMachine, HardwareProfile, \
        StorageProfile, OSProfile, OSDisk, VirtualHardDisk, ImageReference, NetworkProfile, LinuxConfiguration, \
        SshConfiguration, SshPublicKey
    from azure.mgmt.network.models import PublicIPAddress, NetworkSecurityGroup, SecurityRule, NetworkInterface, \
        NetworkInterfaceIPConfiguration, Subnet
    from azure.mgmt.storage.models import AccountType, AccountStatus, StorageAccountCreateParameters
    from azure.mgmt.compute.models.compute_management_client_enums import CachingTypes, DiskCreateOptionTypes, \
        VirtualMachineSizeTypes
except ImportError:
    # This is handled in azure_rm_common
    pass


DOCUMENTATION = '''
---
module: azure_rm_virtualmachine
'''

RETURNS = '''
{
    "changed": true,
    "check_mode": false,
    "differences": [],
    "powerstate_change": "poweron",
    "results": {
        "id": "/subscriptions/3f7e29ba-24e0-42f6-8d9c-5149a14bda37/resourceGroups/Testing/providers/Microsoft.Compute/virtualMachines/testvm10",
        "location": "eastus",
        "name": "testvm10",
        "power_state": "running",
        "properties": {
            "hardwareProfile": {
                "vmSize": "Standard_D1"
            },
            "instanceView": {
                "disks": [
                    {
                        "name": "testvm10.vhd",
                        "statuses": [
                            {
                                "code": "ProvisioningState/succeeded",
                                "displayStatus": "Provisioning succeeded",
                                "level": "Info",
                                "time": "2016-03-30T07:11:16.187272Z"
                            }
                        ]
                    }
                ],
                "statuses": [
                    {
                        "code": "ProvisioningState/succeeded",
                        "displayStatus": "Provisioning succeeded",
                        "level": "Info",
                        "time": "2016-03-30T19:47:11.096516Z"
                    },
                    {
                        "code": "PowerState/running",
                        "displayStatus": "VM running",
                        "level": "Info"
                    }
                ],
                "vmAgent": {
                    "statuses": [
                        {
                            "code": "ProvisioningState/Unavailable",
                            "displayStatus": "Not Ready",
                            "level": "Warning",
                            "message": "VM Agent is unresponsive.",
                            "time": "2016-03-30T19:47:14.000Z"
                        }
                    ],
                    "vmAgentVersion": "Unknown"
                }
            },
            "networkProfile": {
                "networkInterfaces": [
                    {
                        "id": "/subscriptions/3f7e29ba-24e0-42f6-8d9c-5149a14bda37/resourceGroups/Testing/providers/Microsoft.Network/networkInterfaces/testvm10_NIC01"
                    }
                ]
            },
            "osProfile": {
                "adminUsername": "chouseknecht",
                "computerName": "test10",
                "linuxConfiguration": {
                    "disablePasswordAuthentication": false
                },
                "secrets": []
            },
            "provisioningState": "Succeeded",
            "storageProfile": {
                "dataDisks": [],
                "imageReference": {
                    "offer": "CentOS",
                    "publisher": "OpenLogic",
                    "sku": "7.1",
                    "version": "7.1.20160308"
                },
                "osDisk": {
                    "caching": "ReadOnly",
                    "createOption": "fromImage",
                    "name": "testvm10.vhd",
                    "osType": "Linux",
                    "vhd": {
                        "uri": "https://testvm10sa1.blob.core.windows.net/vhds/testvm10.vhd"
                    }
                }
            }
        },
        "type": "Microsoft.Compute/virtualMachines"
    }
}
'''

AZURE_OBJECT_CLASS = 'VirtualMachine'

def extract_names_from_blob_uri(self, blob_uri):
    # HACK: ditch this once python SDK supports get by URI
    m = re.match('^https://(?P<accountname>[^\.]+)\.blob\.core\.windows\.net/(?P<containername>[^/]+)/(?P<blobname>.+)$', blob_uri)
    if not m:
        raise Exception("unable to parse blob uri '%s'" % blob_uri)
    extracted_names = m.groupdict()
    return extracted_names


class AzureRMVirtualMachine(AzureRMModuleBase):   

    def __init__(self, **kwargs):

        self.module_arg_spec = dict(
            resource_group=dict(type='str', required=True),
            name=dict(type='str', required=True),
            state=dict(choices=['present', 'absent', 'started', 'stopped'], default='started', type='str'),
            location=dict(type='str'),
            short_hostname=dict(type='str'),
            vm_size=dict(type='str', choices=[], default='Standard_D1'),
            force=dict(type='bool', default=False),
            admin_username=dict(type='str'),
            admin_password=dict(type='str', ),
            ssh_password=dict(type='bool', aliases=['ssh_password_enabled'], default=True),
            ssh_public_keys=dict(type='list'),
            image_publisher=dict(type='str'),
            image_offer=dict(type='str'),
            image_sku=dict(type='str'),
            image_version=dict(type='str', default='latest'),
            storage_account_name=dict(type='str', aliases=['storage_account']),
            storage_container_name=dict(type='str', aliases=['storage_container'], default='vhds'),
            storage_blob_name=dict(type='str', aliases=['storage_blob']),
            os_disk_caching=dict(type='str', aliases=['disk_caching'], choices=['ReadOnly', 'ReadWrite'],
                                 default='ReadOnly'),
            os_type=dict(type='str', choices=['Linux', 'Windows'], default='Linux'),
            public_ip_allocation_method=dict(type='str', choices=['Dynamic', 'Static'], default='Static',
                                             aliases=['public_ip_allocation']),
            ssh_port=dict(type='int', default=22),
            rdp_port=dict(type='int', default=3389),
            network_interface_names=dict(type='list', aliases=['network_interfaces']),
            delete_network_interfaces=dict(type='bool', default=False, aliases=['delete_nics']),
            delete_virtual_storage=dict(type='bool', default=False, aliases=['delete_vhds']),
            delete_public_ips=dict(type='bool', default=False),
            tags=dict(type='dict'),
            log_path=dict(type='str', default='azure_rm_virtualmachine.log'),
        )

        for key in VirtualMachineSizeTypes:
            self.module_arg_spec['vm_size']['choices'].append(getattr(key, 'value'))

        super(AzureRMVirtualMachine, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                    supports_check_mode=True,
                                                    **kwargs)

        self.resource_group = None
        self.name = None
        self.state = None
        self.location = None
        self.short_hostname = None
        self.vm_size = None
        self.admin_username = None
        self.admin_password = None
        self.ssh_password = None
        self.ssh_public_keys = None
        self.image_publisher = None
        self.image_offer = None
        self.image_sku = None
        self.image_version = None
        self.storage_account_name = None
        self.storage_container_name = None
        self.storage_blob_name = None
        self.os_type = None
        self.os_disk_caching = None
        self.network_interface_names = None
        self.delete_network_interfaces = None
        self.delete_virtual_storage = None
        self.delete_public_ips = None
        self.tags = None
        self.force = None
        self.public_ip_allocation_method = None
        self.rdp_port = None
        self.ssh_port = None

        self.results = dict(
            changed=False,
            check_mode=self.check_mode,
            actions=[],
            differences=None,
            powerstate_change=None,
            results={}
        )

    def exec_module_impl(self, **kwargs):

        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        changed = False
        powerstate_change = None
        results = dict()
        vm = None
        network_interfaces = []
        image_version = None
        requested_vhd_uri = None
        disable_ssh_password = None
        vm_dict = None
        
        resource_group = self.get_resource_group(self.resource_group)
        if not self.location:
            # Set default location
            self.location = resource_group.location

        if self.state in ('present', 'started', 'stopped'):
            # Verify parameters and resolve any defaults
            self.vm_size_is_valid()

            if self.network_interface_names:
                for name in self.network_interface_names:
                    nic = self.get_network_interface(name)
                    network_interfaces.append(nic.id)

            if self.image_publisher and self.image_offer and self.image_sku:
                image_version = self.get_image_version()
                if self.image_version == 'latest':
                    self.image_version = image_version.name
                    self.log("Using image version {0}".format(self.image_version))

            if not self.storage_blob_name:
                    self.storage_blob_name = self.name + '.vhd'

            if self.storage_account_name:
                self.get_storage_account()

                requested_vhd_uri = 'https://{0}.blob.core.windows.net/{1}/{2}'.format(self.storage_account_name,
                                                                                       self.storage_container_name,
                                                                                       self.storage_blob_name)

            disable_ssh_password = not self.ssh_password

        try:
            self.log("Fetching virtual machine {0}".format(self.name))
            vm = self.compute_client.virtual_machines.get(self.resource_group, self.name, expand='instanceview')
            self.check_provisioning_state(vm, self.state)
            vm_dict = self.serialize_vm(vm)

            if self.state in ('present', 'started', 'stopped'):
                differences = []
                current_nics = []
                results = vm_dict

                # Try to determine if the VM needs to be updated
                if self.network_interface_names:
                    for nic in vm_dict['properties']['networkProfile']['networkInterfaces']:
                        current_nics.append(nic['id'])

                    if set(current_nics) != set(network_interfaces):
                        self.log('CHANGED: virtual machine {0} - network interfaces are different.'.format(self.name))
                        differences.append('Network Interfaces')
                        updated_nics = [dict(id=id) for id in network_interfaces]
                        vm_dict['properties']['networkProfile']['networkInterfaces'] = updated_nics
                        changed = True

                if self.vm_size and self.vm_size != vm_dict['properties']['hardwareProfile']['vmSize']:
                    self.log('CHANGED: virtual machine {0} - vm size is different.'.format(self.name))
                    differences.append('VM Size')
                    vm_dict['properties']['hardwareProfile']['vmSize'] = self.vm_size
                    changed = True

                if self.image_publisher:
                    if self.image_publisher != \
                       vm_dict['properties']['storageProfile']['imageReference']['publisher'] or \
                       self.image_offer != vm_dict['properties']['storageProfile']['imageReference']['offer'] or \
                       self.image_sku != vm_dict['properties']['storageProfile']['imageReference']['sku']:
                        self.log('CHANGED: virtual machine {0} - image is different.'.format(self.name))
                        differences.append('Image')
                        vm_dict['properties']['storageProfile']['imageReference']['publisher'] = self.image_publisher
                        vm_dict['properties']['storageProfile']['imageReference']['offer'] = self.image_offer
                        vm_dict['properties']['storageProfile']['imageReference']['sku'] = self.image_sku
                        changed = True

                    if self.image_version != 'latest' and \
                       self.image_version != vm_dict['properties']['storageProfile']['imageReference']['version']:
                        self.log('CHANGED: virtual machine {0} - image version is different.'.format(self.name))
                        differences.append('Image versions')
                        vm_dict['properties']['storageProfile']['imageReference']['version'] = self.image_version
                        changed = True

                    if self.image_version == 'latest' and \
                       image_version != vm_dict['properties']['storageProfile']['imageReference']['version']:
                        self.log('CHANGED: virtual machine {0} - image not at latest version.'.format(self.name))
                        differences.append('Image version not at latest')
                        vm_dict['properties']['storageProfile']['imageReference']['version'] = image_version
                        changed = True

                if self.os_disk_caching and \
                   self.os_disk_caching != vm_dict['properties']['storageProfile']['osDisk']['caching']:
                    self.log('CHANGED: virtual machine {0} - OS disk caching'.format(self.name))
                    differences.append('OS Disk caching')
                    changed = True
                    vm_dict['properties']['storageProfile']['osDisk']['caching'] = self.os_disk_caching

                if self.storage_account_name:
                    if requested_vhd_uri != vm_dict['properties']['storageProfile']['osDisk']['vhd']['uri']:
                        self.log('CHANGED: virtual machine {0} - OS disk VHD uri'.format(self.name))
                        differences.append('OS Disk VHD uri')
                        changed = True
                        vm_dict['properties']['storageProfile']['osDisk']['vhd']['uri'] = requested_vhd_uri

                if self.tags != vm_dict.get('tags'):
                    self.log('CHANGED: virtual machine {0} - Tags'.format(self.name))
                    differences.append('Tags')
                    vm_dict['tags'] = self.tags
                    changed = True

                if self.admin_username and self.admin_username != vm_dict['properties']['osProfile']['adminUsername']:
                    self.log('CHANGED: virtual machine {0} - admin username'.format(self.name))
                    differences.append('Admin Username')
                    vm_dict['properties']['osProfile']['adminUsername'] = self.admin_username
                    changed = True
                    if self.admin_password:
                        vm_dict['properties']['osProfile']['adminPassword'] = self.admin_password

                if self.short_hostname and self.short_hostname != vm_dict['properties']['osProfile']['computerName']:
                    self.log('CHANGED: virtual machine {0} - short hostname'.format(self.name))
                    differences.append('Short Hostname')
                    changed = True
                    vm_dict['properties']['osProfile']['computerName'] = self.short_hostname

                # We can't tell if the ssh_password value was changed by user. We may be looking at the default state.
                # if self.ssh_password is not None:
                #     if vm_dict['properties']['osProfile'].get('linuxConfigurtion'):
                #         # linux host
                #         if vm_dict['properties']['osProfile']['linuxConfigurtion']['disablePasswordAuthentication'] != \
                #            disable_ssh_password:
                #             self.log('CHANGED: virtual machine {0} - ssh password disable'.format(self.name))
                #             differences.append('Disable SSH Password')
                #             changed = True
                #             vm_dict['properties']['osProfile']['linuxConfigurtion']['disablePasswordAuthentication'] = \
                #                 disable_ssh_password

                self.results['differences'] = differences

                if self.state == 'started' and vm_dict['power_state'] != 'running':
                    self.log("CHANGED: virtual machine {0} not running and requested state 'running'".format(self.name))
                    changed = True
                    powerstate_change = 'poweron'

                elif self.state == 'stopped' and vm_dict['power_state'] == 'running':
                    self.log("CHANGED: virtual machine {0} running and requested state 'stopped'".format(self.name))
                    changed = True
                    powerstate_change = 'poweroff'

            elif self.state == 'absent':
                self.log("CHANGED: virtual machine {0} exists and requested state is 'absent'".format(self.name))
                results = dict()
                changed = True

        except CloudError:
            self.log('Virtual machine {0} does not exist'.format(self.name))
            if self.state in ('present', 'started', 'stopped'):
                self.log("CHANGED: virtual machine does not exist but state in ('present','started','stopped')" \
                    .format(self.name))
                changed = True

        self.results['changed'] = changed
        self.results['results'] = results
        self.results['powerstate_change'] = powerstate_change

        if self.check_mode:
            return self.results

        if changed:
             if self.state in ('present','started','stopped'):
                if not vm:
                    # Create the VM
                    self.log("Create virtual machine {0}".format(self.name))
                    self.results['actions'].append('Created VM {0}'.format(self.name))

                    # Validate parameters
                    if not self.admin_username:
                        self.fail("Parameter error: admin_username required when creating a virtual machine.")

                    if self.os_type == 'Linux':
                        if disable_ssh_password and not self.ssh_public_keys:
                            self.fail("Parameter error: ssh_public_keys required when disabling SSH password.")

                    if not self.image_publisher or not self.image_offer or not self.image_sku:
                        self.fail("Parameter error: specify an image when creating a virtual machine. "
                                  "Expecting values for image_publisher, image_offer and image_sku.")

                    if self.ssh_public_keys:
                        for key in self.ssh_public_keys:
                            if not key['path'] or not key['key_data']:
                                self.fail("Parameter error: expecting SSH key to be of type dictionary with "
                                          "path and key_data keys.")

                    # Get defaults
                    if not self.network_interface_names:
                        default_nic = self.create_default_nic()
                        network_interfaces = [default_nic.id]

                    if not self.storage_account_name:
                        storage_account = self.create_default_storage_account()
                        requested_vhd_uri = 'https://{0}.blob.core.windows.net/{1}/{2}'.format(
                            storage_account.name,
                            self.storage_container_name,
                            self.storage_blob_name)
                    
                    nics = [NetworkInterfaceReference(id=id) for id in network_interfaces]
                    vhd = VirtualHardDisk(uri=requested_vhd_uri)
                    vm_resource = VirtualMachine(
                        location=self.location,
                        name=self.name,
                        tags=self.tags,
                        os_profile=OSProfile(
                            admin_username=self.admin_username,
                            computer_name=self.short_hostname,
                        ),
                        hardware_profile=HardwareProfile(
                            vm_size=self.vm_size
                        ),
                        storage_profile=StorageProfile(
                            os_disk=OSDisk(
                                self.storage_blob_name,
                                vhd,
                                DiskCreateOptionTypes.from_image,
                                caching=self.os_disk_caching,
                            ),
                            image_reference=ImageReference(
                                publisher=self.image_publisher,
                                offer=self.image_offer,
                                sku=self.image_sku,
                                version=self.image_version,
                            ),
                        ),
                        network_profile=NetworkProfile(
                            network_interfaces=nics
                        ),
                    )

                    if self.admin_password:
                        vm_resource.os_profile.admin_password = self.admin_password

                    if self.os_type == 'Linux':
                        vm_resource.os_proifle.linux_configuration = LinuxConfiguration(
                            disable_password_authentication=disable_ssh_password
                        )
                    if self.ssh_public_keys:
                        ssh_config = SshConfiguration()
                        ssh_config.public_keys = \
                            [SshPublicKey(path=key.path, key_data=key.key_data) for key in self.ssh_public_keys]
                        vm_resource.os_profile.linux_configuration.ssh = ssh_config

                    self.log("Create virtual machine with parameters:")
                    self.log(self.serialize_obj(vm_resource, 'VirtualMachine'), pretty_print=True)
                    self.results['results'] = self.create_or_update_vm(vm_resource)

                elif self.results['differences'] is not None:
                    # Update the VM based on detected config differences

                    self.log("Update virtual machine {0}".format(self.name))
                    self.results['actions'].append('Updated VM {0}'.format(self.name))

                    nics = [NetworkInterfaceReference(id=interface['id'])
                            for interface in vm_dict['properties']['networkProfile']['networkInterfaces']]
                    vhd = VirtualHardDisk(uri=vm_dict['properties']['storageProfile']['osDisk']['vhd']['uri'])
                    vm_resource = VirtualMachine(
                        id=vm_dict['id'],
                        location=vm_dict['location'],
                        name=vm_dict['name'],
                        type=vm_dict['type'],
                        os_profile=OSProfile(
                            admin_username=vm_dict['properties']['osProfile']['adminUsername'],
                            computer_name=vm_dict['properties']['osProfile']['computerName']
                        ),
                        hardware_profile=HardwareProfile(
                            vm_size=vm_dict['properties']['hardwareProfile']['vmSize']
                        ),
                        storage_profile=StorageProfile(
                            os_disk=OSDisk(
                                vm_dict['properties']['storageProfile']['osDisk']['name'],
                                vhd,
                                vm_dict['properties']['storageProfile']['osDisk']['createOption'],
                                os_type=vm_dict['properties']['storageProfile']['osDisk']['osType'],
                                caching=vm_dict['properties']['storageProfile']['osDisk']['caching']
                            ),
                            image_reference=ImageReference(
                                publisher=vm_dict['properties']['storageProfile']['imageReference']['publisher'],
                                offer=vm_dict['properties']['storageProfile']['imageReference']['offer'],
                                sku=vm_dict['properties']['storageProfile']['imageReference']['sku'],
                                version=vm_dict['properties']['storageProfile']['imageReference']['version']
                            ),
                        ),
                        network_profile=NetworkProfile(
                            network_interfaces=nics
                        ),
                    )

                    if vm_dict.get('tags'):
                        vm_resource.tags = vm_dict['tags']

                    # Add admin password, if one provided
                    if vm_dict['properties']['osProfile'].get('adminPassword'):
                        vm_resource.os_profile.admin_password = vm_dict['properties']['osProfile']['adminPassword']

                    # Add linux configuration, if applicable
                    linux_config = vm_dict['properties']['osProfile'].get('linuxConfiguration')
                    if linux_config:
                        ssh_config = linux_config.get('ssh', None)
                        vm_resource.os_profile.linux_configuration = LinuxConfiguration(
                            disable_password_authentication=linux_config.get('disablePasswordAuthentication', False)
                        )
                        if ssh_config:
                            public_keys = ssh_config.get('publicKeys')
                            if public_keys:
                                vm_resource.os_profile.linux_configuration.ssh = SshConfiguration(public_keys=[])
                                for key in public_keys:
                                    vm_resource.os_profile.linux_configuration.ssh.public_keys.append(
                                        SshConfiguration(
                                            path=key['path'],
                                            key_data=key['keyData']
                                        )
                                    )
                    self.log("Update virtual machine with parameters:")
                    self.log(self.serialize_obj(vm_resource, 'VirtualMachine'), pretty_print=True)
                    self.results['results'] = self.create_or_update_vm(vm_resource)

                # Make sure we leave the machine in requested power state
                if powerstate_change == 'poweron' and self.results['results']['power_state'] != 'running':
                    # Attempt to power on the machine
                    self.power_on_vm()
                    self.results['results'] = self.serialize_vm(self.get_vm())

                elif powerstate_change == 'poweroff' and self.results['results']['power_state'] == 'running':
                    # Attempt to power off the machine
                    self.power_off_vm()
                    self.results['results'] = self.serialize_vm(self.get_vm())

             elif self.state == 'absent':
                 # delete the VM
                 self.results['actions'].append('Removed VM {0}'.format(self.name))
                 self.log("Delete virtual machine {0}".format(self.name))
                 self.delete_vm()

        return self.results

    def get_vm(self):
        '''
        Get the VM with expanded instanceView

        :return: VirtualMachine object
        '''
        try:
            vm = self.compute_client.virtual_machines.get(self.resource_group, self.name, expand='instanceview')
            return vm
        except Exception, exc:
            self.fail("Error getting virtual machine (0) - {1}".format(self.name, str(exc)))

    def serialize_vm(self, vm):
        '''
        Convert a VirtualMachine object to dict.

        :param vm: VirtualMachine object
        :return: dict
        '''
        result = self.serialize_obj(vm, AZURE_OBJECT_CLASS)
        result['power_state'] = next((s.code.replace('PowerState/', '') for s in vm.instance_view.statuses if s.code.startswith('PowerState')), None)
        self.log(result, pretty_print=True)
        if not result['power_state']:
            self.fail("Failed to determine PowerState of virtual machine {0}".format(self.name))
        return result

    def power_off_vm(self):
        self.log("Powered off virtual machine {0}".format(self.name))
        self.results['actions'].append("Powered off virtual machine {0}".format(self.name))
        try:
            poller = self.compute_client.virtual_machines.power_off(self.resource_group, self.name)
        except Exception, exc:
            self.fail("Error powering off virtual machine {0} - {1}".format(self.name, str(exc)))
        self.get_poller_result(poller)
        return True

    def power_on_vm(self):
        self.results['actions'].append("Powered on virtual machine {0}".format(self.name))
        self.log("Power on virtual machine {0}".format(self.name))
        try:
            poller = self.compute_client.virtual_machines.start(self.resource_group, self.name)
        except Exception, exc:
            self.fail("Error powering on virtual machine {0} - {1}".format(self.name, str(exc)))
        self.get_poller_result(poller)
        return True

    def delete_vm(self):
        vhd_uris = []
        nic_names = []
        pip_names = []

        if self.delete_virtual_storage:
            # store the attached vhd info so we can nuke it after the VM is gone
            self.log('Storing VHD URI for deletion')
            vhd_uris.append(vm.storage_profile.os_disk.virtual_hard_disk.uri)
            self.log("VHD URIs to delete: {0}".format(', '.join(vhd_uris)))
            self.results['deleted_vhd_uris'] = vhd_uris

        if self.delete_network_interfaces:
            # store the attached nic info so we can nuke them after the VM is gone
            self.log('Storing NIC names for deletion.')
            for interface_id in vm.network_profile.network_interfaces:
                id_dict = azure_id_to_dict(interface_id)
                nic_names.append(id_dict['networkInterfaces'])
            self.log('NIC names to delete {0}'.format(', '.join(nic_names)))
            self.results['deleted_network_interfaces'] = nic_names
            if self.delete_public_ips:
                # also store each nic's attached public IPs and delete after the NIC is gone
                for name in nic_names:
                    nic = self.get_network_interface(name)
                    for ipc in nic.ip_configurations:
                        if ipc.public_ip_address:
                            pip_dict = azure_id_to_dict(ipc.public_ip_address.id)
                            pip_names.append(pip_dict['publicIPAddresses'])
                self.log('Public IPs to  delete are {0}'.format(', '.join(pip_names)))
                self.results['deleted_public_ips'] = pip_names

        self.log("Deleting virtual machine {0}".format(self.name))
        self.results['actions'].append("Deleted virtual machine {0}".format(self.name))
        try:
            self.compute_client.virtual_machines.delete(self.resource_group, self.name)
        except Exception, exc:
            self.fail("Error deleting virtual machine {0} - {1}".format(self.name, str(exc)))

        # TODO: parallelize nic, vhd, and public ip deletions with begin_deleting
        # TODO: best-effort to keep deleting other linked resources if we encounter an error
        if self.delete_virtual_storage:
            self.log('Deleting virtual storage')
            self.delete_virtual_storage(vhd_uris)

        if self.delete_network_interfaces:
            self.log('Deleting network interfaces')
            for name in nic_names:
                self.delete_nic(name)

        if self.delete_public_ips:
            self.log('Deleting public IPs')
            for name in pip_names:
                self.delete_pip(name)
        return True

    def get_network_interface(self, name):
        try:
            nic = self.network_client.network_interfaces.get(self.resource_group, name)
            return nic
        except Exception, exc:
            self.fail("Error fetching network interface {0} - {1}".format(name, str(exc)))

    def delete_nic(self, name):
        self.log("Deleting network interface {0}".format(name))
        self.results['actions'].append("Deleted network interface {0}".format(name))
        try:
            poller = self.network_client.network_interfaces.delete(self.resource_group, name)
        except Exception, exc:
            self.fail("Error deleting network interface {0} - {1}".format(name, str(exc)))
        self.get_poller_result(poller)
        # Delete doesn't return anything. If we get this far, assume success
        return True

    def delete_pip(self, name):
        self.results['actions'].append("Deleted public IP {0}".format(name))
        try:
            poller = self.network_client.public_ip_addresses.delete(self.resource_group, name)
        except Exception, exc:
            self.fail("Error deleting {0} - {1}".format(name, str(exc)))
        self.get_poller_result(poller)
        # Delete returns nada. If we get here, assume that all is well.
        return True

    def delete_virtual_storage(self, vhd_uris):
        for uri in vhd_uris:
            self.log("Extracting info from blob uri '{0}'".format(uri))
            blob_parts = extract_names_from_blob_uri(uri)
            storage_account_name = blob_parts['accountname']
            container_name = blob_parts['containername']
            blob_name = blob_parts['blobname']

            blob_client = self.get_blob_client(self.resource_group, storage_account_name)

            self.log("Delete blob {0}:{1}".format(container_name, blob_name))
            self.results['actions'].append("Deleted blob {0}:{1}".format(container_name, blob_name))
            try:
                blob_client.delete_blob(container_name, blob_name)
            except Exception, exc:
                self.fail("Error deleting blob {0}:{1} - {2}".format(container_name, blob_name, str(exc)))

    def get_image_version(self):
        try:
            versions = self.compute_client.virtual_machine_images.list(self.location,
                                                                       self.image_publisher,
                                                                       self.image_offer,
                                                                       self.image_sku)
        except Exception, exc:
            self.fail("Error fetching image {0} {1} {2} - {4}".format(self.image_publisher,
                                                                      self.image_offer,
                                                                      self.image_sku,
                                                                      str(exc)))
        if versions and len(versions) > 0:
            if self.image_version == 'latest':
                return versions[len(versions) - 1]
            for version in versions:
                if version.name == self.image_version:
                    return version

        self.fail("Error could not find image {0} {1} {2} {3}".format(self.image_publisher,
                                                                      self.image_offer,
                                                                      self.image_sku,
                                                                      self.image_version))

    def get_storage_account(self):
        try:
            account = self.storage_client.storage_accounts.get_properties(self.resource_group,
                                                                          self.storage_account_name)
            return account
        except Exception, exc:
            self.fail("Error fetching storage account {0} - {1}".format(self.storage_account_name, str(exc)))

    def create_or_update_vm(self, params):
        try:
            poller = self.compute_client.virtual_machines.create_or_update(self.resource_group, self.name, params)
        except Exception, exc:
            self.fail("Error creating or updating virtual machine {0} - {1}".format(self.name, str(exc)))
        # The poller does not return the expanded result set containing instanceView. Ignore it and
        # call get_vm()
        self.get_poller_result(poller)
        return self.serialize_vm(self.get_vm())

    def vm_size_is_valid(self):
        '''
        Validate self.vm_size against the list of virtual machine sizes available for the account and location.

        :return: boolean
        '''
        try:
            sizes = self.compute_client.virtual_machine_sizes.list(self.location)
        except Exception, exc:
            self.fail("Error retrieving available machine sizes - {0}".format(str(exc)))
        for size in sizes:
            if size.name == self.vm_size:
                return True
        return False

    def create_default_storage_account(self):
        '''
        Create a default storage account <vm name>sa1. If <vm name>sa1 exists, use it.
        Otherwise, create one.

        :return: storage account object
        '''
        storage_account_name = self.name + 'sa1'
        account = None

        try:
            account = self.storage_client.storage_accounts.get_properties(self.resource_group, storage_account_name)
        except CloudError, exc:
            pass

        if account:
            self.log("Storage account {0} found.".format(storage_account_name))
            self.check_provisioning_state(account)
            return account

        parameters = StorageAccountCreateParameters(account_type='Standard_LRS', location=self.location)
        self.log("Creating storage account {0}".format(storage_account_name))
        self.results['actions'].append("Created storage account {0}".format(storage_account_name))
        try:
            poller = self.storage_client.storage_accounts.create(self.resource_group, storage_account_name, parameters)
        except Exception, exc:
            self.fail("Failed to create storage account: {0} - {1}".format(storage_account_name, str(exc)))

        return self.get_poller_result(poller)

    def create_default_nic(self):
        '''
        Create a default Network Interface <vm name>_NIC01. Requires an existing virtual network
        with one subnet. If NIC <vm name>_NIC01 exists, use it. Otherwise, create one.

        :return: NIC object
        '''

        network_interface_name = self.name + '_NIC01'
        nic = None

        self.log("Create default NIC {0}".format(network_interface_name))
        self.log("Check to see if NIC {0} exists".format(network_interface_name))
        try:
            nic = self.network_client.network_interfaces.get(self.resource_group, network_interface_name)
        except CloudError:
            pass

        if nic:
            self.log("NIC {0} found.".format(network_interface_name))
            self.check_provisioning_state(nic)
            return nic

        self.log("NIC {0} does not exist.".format(network_interface_name))

        # Find a virtual network
        no_vnets_msg = "Error: unable to find virtual network in resource group {0}. A virtual network " \
                       "with at least one subnet must exist in order to create a NIC for the virtual " \
                       "machine.".format(self.resource_group)

        virtual_network_name = None
        try:
            vnets = self.network_client.virtual_networks.list(self.resource_group)
        except CloudError:
            self.log('cloud error!')
            self.fail(no_vnets_msg)

        for vnet in vnets:
            virtual_network_name = vnet.name
            self.log('vnet name: {0}'.format(vnet.name))
            break

        if not virtual_network_name:
            self.fail(no_vnets_msg)

        no_subnets_msg = "Error: unable to find a subnet in virtual network {0}. A virtual network " \
                         "with at least one subnet must exist in order to create a NIC for the virtual " \
                         "machine.".format(virtual_network_name)

        subnet_id = None
        try:
            subnets = self.network_client.subnets.list(self.resource_group, virtual_network_name)
        except CloudError:
            self.fail(no_subnets_msg)

        for subnet in subnets:
            subnet_id = subnet.id
            self.log('subnet id: {0}'.format(subnet_id))
            break

        if not subnet_id:
            self.fail(no_subnets_msg)

        pip = self.create_default_pip()
        group = self.create_default_securitygroup()

        parameters = NetworkInterface(
            location=self.location,
            name=network_interface_name,
            ip_configurations=[
                NetworkInterfaceIPConfiguration(
                    name='default',
                    private_ip_allocation_method='Dynamic',
                )
            ]
        )
        parameters.ip_configurations[0].subnet = Subnet(id=subnet_id)
        parameters.network_security_group = NetworkSecurityGroup(id=group.id,
                                                                 name=group.name,
                                                                 location=group.location,
                                                                 resource_guid=group.resource_guid)
        parameters.ip_configurations[0].public_ip_address = PublicIPAddress(id=pip.id,
                                                                            name=pip.name,
                                                                            location=pip.location,
                                                                            resource_guid=pip.resource_guid)

        self.log("Creating NIC {0}".format(network_interface_name))
        self.log(self.serialize_obj(parameters, 'NetworkInterface'), pretty_print=True)
        self.results['actions'].append("Created NIC {0}".format(network_interface_name))
        try:
            poller = self.network_client.network_interfaces.create_or_update(self.resource_group,
                                                                             network_interface_name,
                                                                             parameters)
        except Exception, exc:
            self.fail("Error creating network interface {0} - {1}".format(network_interface_name, str(exc)))
        return self.get_poller_result(poller)

    def create_default_pip(self):
        '''
        Create a default public IP address <vm_name>_PIP01 to associate with the default NIC.
        If a PIP address matching <vm name>_PIP01 exists, use it. Otherwise, create one.

        :return: PIP object
        '''
        public_ip_name = self.name + '_PIP01'
        pip = None

        self.log("Create public IP {0}".format(public_ip_name))
        self.log("Check to see if public IP {0} exists".format(public_ip_name))
        try:
            pip = self.network_client.public_ip_addresses.get(self.resource_group, public_ip_name)
        except CloudError:
            pass

        if pip:
            self.log("Public ip {0} found.".format(public_ip_name))
            self.check_provisioning_state(pip)
            return pip

        params = PublicIPAddress(
            location=self.location,
            public_ip_allocation_method=self.public_ip_allocation_method,
        )
        self.log('Creating default public IP {0}'.format(public_ip_name))
        self.results['actions'].append('Creating default public IP {0}'.format(public_ip_name))
        try:
            poller = self.network_client.public_ip_addresses.create_or_update(self.resource_group, public_ip_name, params)
        except Exception, exc:
            self.fail("Error creating {0} - {1}".format(public_ip_name, str(exc)))

        return self.get_poller_result(poller)

    def create_default_securitygroup(self):
        '''
        Create a default security group <vm_name>_SG01 to associate with the default NIC.
        If a security group matching <vm name>_SG01 exists, use it. Otherwise, create one.

        :return: security_group object
        '''
        security_group_name = self.name + '_SG01'
        group = None

        self.log("Create security group {0}".format(security_group_name))
        self.log("Check to see if security group {0} exists".format(security_group_name))
        try:
            group = self.network_client.network_security_groups.get(self.resource_group, security_group_name)
        except CloudError:
            pass

        if group:
            self.log("Security group {0} found.".format(security_group_name))
            self.check_provisioning_state(group)
            return group

        parameters = NetworkSecurityGroup()
        if self.os_type == 'Linux':
            # add an inbound SSH rule
            parameters.security_rules=[
                SecurityRule('Tcp', '*', '*', 'Allow', 'Inbound', desription='Allow SSH Access',
                             source_port_range='*', destination_port_range=self.ssh_port, priority=100, name='SSH')
            ]
            parameters.location = self.location
        else:
            # for windows add an inbound RDP rule
            parameters.security_rules=[
                SecurityRule('Tcp', '*', '*', 'Allow', 'Inbound', desription='Allow RDP Access',
                             soruce_port_range='*', destination_port_range=self.rdp_port, priority=100, name='RDP')
            ]
            parameters.location = self.location

        self.log('Creating default security group {0}'.format(security_group_name))
        self.results['actions'].append('Created default security group {0}'.format(security_group_name))
        try:
            poller = self.network_client.network_security_groups.create_or_update(self.resource_group,
                                                                                  security_group_name,
                                                                                  parameters)
        except Exception, exc:
            self.fail("Error creating default security rule {0} - {1}".format(security_group_name, str(exc)))

        return self.get_poller_result(poller)

    def get_deployment_status(self):
        self.log("Getting resource using filter {0}".format('None'))
        try:
            resources = self.rm_client.deployments.list(self.resource_group)
        except Exception, exc:
            self.fail("Error getting resources for filter {0} - {1}".format('None', str(exc)))

        return resources


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

