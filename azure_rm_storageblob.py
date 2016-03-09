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

import datetime
import hashlib
import os

# normally we'd put this at the bottom to preserve line numbers, but we can't use a forward-defined base class
# without playing games with __metaclass__ or runtime base type hackery.
# TODO: figure out a better way...
from ansible.module_utils.basic import *

# Assumes running ansible from source and there is a copy or symlink for azure_rm_common
# found in local lib/ansible/module_utils
from ansible.module_utils.azure_rm_common import *


HAS_AZURE = True

try:
    from azure.storage.cloudstorageaccount import CloudStorageAccount
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
except ImportError:
    HAS_AZURE = False


DOCUMENTATION = '''
---
module: azure_rm_storageblob

short_description: Create and manage blob containers and blob objects.

description:
    - Create and manage blob containers within a given storage account, upload and download objects to the blob
      container, and control access to the objects.
    - For authentication with Azure pass subscription_id, client_id, secret and tenant, or create a
      ~/.azure/credentials file with one or more profiles and pass a profile to the module. When using a credentials
      file, if no profile option is provided, the module will look for a 'default' profile. Each profile should include
      subscription_id, client_id, secret and tenant values.

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
    storage_account:
        description:
            - name of the storage account.
        required: true
        default: null
    blob:
        description:
            - name of a blob object within the container.
        required: false
        default: null
        aliases:
            - blob_name
    container:
        description:
            - name of a blob container within the storage account.
        required: true
        default: null
        aliases:
            - container_name
    dest:
        description:
            - Destination file path. Use with state 'present' to download a blob.
        default: null
        aliases:
            - destination
    force:
        description:
            - When uploading or downloading overwrite an existing file or blob.
        default: false
    resource_group:
        description:
            - name of resource group.
        required: true
        default: null
    src:
        description:
            - Source file path. Use with state 'present' to upload a blob.
        default: null
        aliases:
            - source
    state:
        description:
            - Assert the state of a container or blob. State can be absent, present.
            - Use state 'absent' with a container value only to delete a container. Include a blob value to remove
              a specific blob. A container will not be deleted, if it contains blobs. Use the force option to override,
              deleting the container and all associated blobs.
            - Use state 'present' to create or update a container and upload or download a blob. If the container
              does not exist, it will be created. If it exists, it will be updated with configuration options. Provide
              a blob name and either src or dest to upload or download. Provide a src path to upload and a dest path
              to download. If a blob (uploading) or a file (downloading) already exists, it will not be overwritten.
              Use the force option to overwrite.
        default: present
        choices:
            - absent
            - present
    public_access:
        description:
            - Determine a container's level of public access. By default containers are private.
        choices:
            - container
            - blob
        default: null
    tags:
        description:
            - dictionary of key:value pairs to add to either a container or blob.
        default: null

requirements:
    - "python >= 2.7"
    - "azure >= 1.0.2"

author: "Chris Houseknecht @chouseknecht"
'''

EXAMPLES = '''
# Simple PUT operation
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: mycontainer
    blob_name: image.png
    file_path: /my/images/image.png
    mode: put

# Simple GET operation
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: mycontainer
    blob_name: image.png
    file_path: /downloads/image.png
    mode: get

# PUT/upload with metadata
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: mycontainer
    blob_name: image.png
    file_path: /my/images/image.png
    x_ms_blob_content_type: image/png
    x_ms_meta_name_values:
        val1: foo
        val2: bar
    mode: put

# List blob objects in a container
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: mycontainer
    mode: list

# List blob objects with options
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: mycontainer
    prefix: /my/desired/
    marker: /my/desired/0023.txt
    max_results: 50
    mode: list

# Create an empty container
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: emptycontainer
    mode: create

# Create a container with an object
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: newcontainer
    blob_name: file1.txt
    file_path: /myfiles/file1.txt
    mode: put

# Delete a container and its contents
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: newcontainer
    mode: delete

# GET an object but don't download when file checksums match
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: newcontainer
    blob_name: file1.txt
    file_path: /myfiles/file1.txt
    mode: get
    overwrite: different

# Get an objet but don't download when file already exists
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: newcontainer
    blob_name: file1.txt
    file_path: /myfiles/file1.txt
    mode: get
    overwrite: never

# Delete an object from a container
- azure_rm_storageblob:
    resource_group: mygroup
    account_name: mystorageacct
    container_name: newcontainer
    blob_name: file1.txt
    mode: delete_blob

'''


NAME_PATTERN = re.compile(r"^(?!-)(?!.*--)[a-z0-9\-]+$")

#
# def path_check(path):
#     if os.path.exists(path):
#         return True
#     else:
#         return False
#
#
# def get_blob_facts(bs, container_name, blob_name):
#     blob = None
#     try:
#         blob = bs.get_blob_properties(container_name, blob_name)
#     except AzureMissingResourceHttpError:
#         pass
#     return blob
#
#
# def blob_check(bs, container_name, blob_name):
#     blob = get_blob_facts(bs, container_name, blob_name)
#     if blob is None:
#         raise Exception("Requested blob %s not found in container %s." % (blob_name, container_name))
#     return blob
#
#
# def get_md5(file_path, block_size=2**20):
#     # hash sent to azure needs to be base64 encoded
#     # https://github.com/Azure/azure-storage-python/issues/11
#     md5 = hashlib.md5()
#     f = open(file_path, 'rb')
#     while True:
#         data = f.read(block_size)
#         if not data:
#             break
#         md5.update(data)
#     return md5.digest().encode('base64')[:-1]
#
#
# def put_block_blob(bs, container_name, blob_name, file_path, x_ms_meta_name_values,
#                    x_ms_blob_cache_control, x_ms_blob_content_encoding, x_ms_blob_content_language,
#                    x_ms_blob_content_type):
#     md5_local = get_md5(file_path)
#     bs.put_block_blob_from_path(
#         container_name=container_name,
#         blob_name=blob_name,
#         file_path=file_path,
#         x_ms_blob_content_md5=md5_local,
#         x_ms_meta_name_values=x_ms_meta_name_values,
#         x_ms_blob_cache_control=x_ms_blob_cache_control,
#         x_ms_blob_content_encoding=x_ms_blob_content_encoding,
#         x_ms_blob_content_language=x_ms_blob_content_language,
#         x_ms_blob_content_type=x_ms_blob_content_type,
#         max_connections=5
#     )
#
#
# def get_shared_access_policy(permission, hours=0, days=0):
#     # https://github.com/Azure/azure-storage-python/blob/master/tests/test_storage_blob.py
#     date_format = "%Y-%m-%dT%H:%M:%SZ"
#     start = datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
#     expiry = start + datetime.timedelta(hours=hours, days=days)
#     return SharedAccessPolicy(
#         AccessPolicy(
#             start.strftime(date_format),
#             expiry.strftime(date_format),
#             permission
#         )
#     )
#
#
# def get_identifier(id, hours, days, permission):
#     date_format = "%Y-%m-%dT%H:%M:%SZ"
#     start = datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
#     expiry = start + datetime.timedelta(hours=hours, days=days)
#     si = SignedIdentifier()
#     si.id = id
#     si.access_policy.start = start.strftime(date_format)
#     si.access_policy.expiry = expiry.strftime(date_format)
#     si.access_policy.permission = permission
#     return si


class AzureRMStorageBlob(AzureRMModuleBase):

    def __init__(self, **kwargs):

        self.module_arg_spec = dict(
            storage_account=dict(required=True, type='str'),
            blob=dict(type='str', aliases=['blob_name']),
            container=dict(required=True, type='str', aliases=['container_name']),
            force=dict(type='bool', default=False),
            resource_group=dict(required=True, type='str'),
            src=dict(type='str'),
            state=dict(type='str', default='present', choices=['absent', 'present']),
            tags=dict(type='dict'),
            public_access=dict(type='str', choices=['container', 'blob'])

            # TODO: implement object security
        )

        mutually_exclusive = [('src', 'dest')]

        super(AzureRMStorageBlob, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                 supports_check_mode=True,
                                                 mutually_exclusive=mutually_exclusive,
                                                 **kwargs)

        if not HAS_AZURE:
            self.fail("The Azure python sdk is not installed (try 'pip install azure')")

        self.blob_client = None
        self.blob_details = None
        self.storage_account = None
        self.blob = None
        self.blob_obj = None
        self.container = None
        self.container_obj = None
        self.force = None
        self.resource_group = None
        self.src = None
        self.state = None
        self.tags = None
        self.public_access = None
        self.results = dict(changed=False,
                            check_mode=self.module.check_mode,
                            actions=[])

    def exec_module_impl(self, **kwargs):

        for key in self.module_arg_spec:
            setattr(self, key, kwargs[key])

        if not NAME_PATTERN.match(self.container):
            self.fail("Parameter error: container_name must consist of lowercase letters, "
                      "numbers and hyphens. It must begin with a letter or number. It may "
                      "not contain two consecutive hyphens.")

        # add file path validation

        try:
            # Get keys from the storage account
            self.log('Getting keys')
            keys = dict()
            account_keys = self.storage_client.storage_accounts.list_keys(self.resource_group, self.storage_account)
            keys['key1'] = account_keys.key1
            keys['key2'] = account_keys.key2
        except AzureHttpError as e:
            self.debug('Error getting keys for account %s' % self.storge_account)
            self.fail(str(e.message))

        try:
            self.log('Create blob service')
            self.blob_client = CloudStorageAccount(self.storage_account, keys['key1']).create_page_blob_service()
        except Exception as e:
            self.debug('Error creating blob service.')
            self.fail(str(e))

        self.container_obj = self.get_container()

        if self.blob is not None:
            self.blob_obj = self.get_blob()

        if self.state == 'present':
            # create or update the container
            if self.container_obj is None:
                # create the container
                self.create_container()
            elif self.blob is None:
                # update container attributes
                if self.tags and self.container_obj.get('tags') != self.tags:
                    # Update container tags
                    self.update_container_tags()

            # create, update or download blob
            if self.blob is not None:
                if self.src is not None and self.src_is_valid():
                    if self.blob_obj is None or self.force:
                        self.upload_blob()

                elif self.dest is not None:
                    # verify file existance
                    # download
                    pass

                if self.tags and self.blob_obj.get('tags') != self.tags:
                    # update tags
                    pass

        elif self.state == 'absent':
            if self.container_obj is not None and self.blob is None:
                # Delete container
                if self.container_has_blobs():
                    if self.force:
                        self.delete_container()
                    self.results['actions'].append("Skip delete container {0}. Container has blobs.".format(
                        self.container))
                else:
                    self.delete_container()
            elif self.container_obj is not None and self.blob_obj is not None:
                # Delete blob
                self.delete_blob()

        return self.results

    def get_container(self):
        container = None
        response = None
        try:
            response = self.blob_client.get_container_properties(self.container)
        except AzureMissingResourceHttpError:
            pass
        if response is not None:
            container = dict(
                name=response.name,
                tags=response.metadata,
                last_mdoified=response.properties.last_modified.strftime('%d-%b-%Y %H:%M:%S %z')
            )
        return container

    def get_blob(self):
        blob = None
        response = None
        try:
            response = self.blob_client.get_blob_properties(self.container, self.blob)
        except AzureMissingResourceHttpError:
            pass
        if response:
            blob = dict(
                name=response.name,
                tags=response.metadata,
                last_modified=response.properties.last_modifiedlast_modified.strftime('%d-%b-%Y %H:%M:%S %z')
            )
        return blob

    def create_container(self):
        self.log('Create container %s' % self.container)

        tags = None
        if self.blob is None and self.tags is not None:
            # when a blob is present, then tags are assigned at the blob level
            tags = self.tags

        if not self.check_mode:
            try:
                self.blob_client.create_container(self.container, metadata=tags, public_access=self.public_access)
            except AzureHttpError, exc:
                self.fail("Error creating container {0} - {1}".format(self.container, str(exc)))
        self.container_obj = self.get_container()
        self.results['changed'] = True
        self.results['actions'].append('created container {0}'.format(self.container))
        self.results['container'] = self.container_obj

    def upload_blob(self):
        try:
            self.blob_client.create_blob_from_path(self.container, self.blob, self.src, metadata=self.tags)
        except AzureHttpError, exc:
            self.fail("Error creating blob {0} - {1}".format(self.blob, str(exc)))

        self.blob_obj = self.get_blob()
        self.results['changed'] = True
        self.results['actions'].append('created blob {0} from {1}'.format(self.blob, self.src))
        self.results['blob'] = self.blob_obj

    def src_is_valid(self):
        if not os.path.isfile(self.src):
            self.fail("The source path must be a file.")
        try:
            fp = open(self.src, 'r')
        except IOError as e:
            self.fail("Failed to access {0}. Make sure the file exists and that you have "
                      "read access.".format(self.src))
        else:
            fp.close()
        return True

    def delete_container(self):
        try:
            self.blob_client.delete_container(self.container)
        except AzureHttpError, exc:
            self.fail("Error deleting container {0} - {1}".format(self.container, str(exc)))

        self.results['changed'] = True
        self.results['actions'].append('deleted container {0}'.format(self.container))

    def container_has_blobs(self):
        try:
            response = self.blob_client.list_blobs(self.container)
        except AzureHttpError, exc:
            self.fail("Error list blobs in {0} - {1}".format(self.container, str(exc)))
        if response:
            self.log(response, pretty_print=True)
        return True

    def delete_blob(self):
        try:
            self.blob_client.delete_blob(self.container, self.blob)
        except AzureHttpError, exc:
            self.fail("Error deleting blob {0}:{1} - {2}".format(self.container, self.blob, str(exc)))

        self.results['changed'] = True
        self.results['actions'].append('deleted blob {0}:{1}'.format(self.container, self.blob))

    def update_container_tags(self):
        try:
            self.blob_client.set_container_metadata(self.container, metadata=self.tags)
        except AzureHttpError, exc:
            self.fail("Error updating container tags {0} - {1}".format(self.container, str(exc)))
        self.container_obj = self.get_container()
        self.results['changed'] = True
        self.results['actions'].append("updated container {0} tags.".format(self.container))
        self.results['container'] = self.container_obj


def main():
    if '--interactive' in sys.argv:
        # import the module here so we can reset the default complex args value
        import ansible.module_utils.basic

        ansible.module_utils.basic.MODULE_COMPLEX_ARGS = json.dumps(dict(
            resource_group="rm_demo",
            account_name="mdavistest12341",
            container_name="testcontainer",
            mode="delete",
            # x_ms_meta_name_values,
            # x_ms_blob_public_access,
            # x_ms_blob_cache_control,
            # x_ms_blob_content_encoding,
            # x_ms_blob_content_language,
            x_ms_blob_content_type = 'application/diskimage',
            # prefix,
            # marker,
            # max_results,
            blob_name="jsci.dmg",
            file_path="/Users/mdavis/Downloads/JuniperSetupClientInstaller.dmg",
            # overwrite,
            # permissions,
            # hours,
            # days,
            # access_token,
            log_mode="stderr"
        ))

    AzureRMStorageBlob().exec_module()


if __name__ == '__main__':
    main()