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
        required: true
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
            account=dict(required=True, type='str'),
            blob=dict(type='str', aliases=['blob_name']),
            container=dict(required=True, type='str', aliases=['container_name']),
            force=dict(type='bool', default=false),
            resource_group=dict(required=True, type='str'),
            src=dict(type='str'),
            state=dict(required=True, type='str', default='present', choices=['absent', 'present']),
            tags=dict(type='dict'),
            public_access=dict(type='str', choices=['container', 'blob'])

            # TODO: implement object security
        )

        mutually_exclusive = [('src', 'dest')]

        Super(AzureRMStorageBlob, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                 supports_check_mode=True,
                                                 mutually_exclusive=mutually_exclusive,
                                                 **kwargs)

        self.blob_client = None
        self.blob_details = None
        self.account = None
        self.blob = None
        self.container = None
        self.container_details = None
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


        if not NAME_PATTERN.match(container):
            self.fail("Parameter error: container_name must consist of lowercase letters, "
                      "numbers and hyphens. It must begin with a letter or number. It may "
                      "not contain two consecutive hyphens.")

        # add file path validation

        try:
            # Get keys from the storage account
            self.log('Getting keys')
            keys = dict()
            response = self.storage_client.storage_accounts.list_keys(resource_group, account)
            keys['key1'] = response.storage_account_keys.key1
            keys['key2'] = response.storage_account_keys.key2
        except AzureHttpError as e:
            self.debug('Error getting keys for account %s' % account)
            self.fail(str(e.message))

        try:
            self.log('Create blob service')
            self.blob_client = CloudStorageAccount(account, keys['key1']).create_block_blob_service()
        except Exception as e:
            self.debug('Error creating blob service.')
            self.fail(str(e))

        self.container_details = self.get_container()

        if self.state == 'present':
            if self.container_details is None:
                self.create_container()
            else:
                #TODO check and update
                pass

            if self.blob is not None:
                self.blob_details = self.get_blob()
                if self.src is not None:
                    if self.blob_details is None or self.force:
                        self.upload_blob()

                if self.dest is not None:
                    # verify file existance
                    # download


        if self.state == 'absent':
            # remove things
            pass

        return self.result

    def get_container(self):
        container = None
        try:
            container = self.blob_client.get_container_properties(self.container)
            container['meta_data'] = self.blob_client.get_container_metadata(self.container)
        except AzureMissingResourceHttpError:
            pass
        return container

    def get_blob(self):
        blob = None
        try:
            blob = self.blob_client.get_blob_properties(self.container, self.blob)
        except AzureMissingResourceHttpError:
            pass
        return blob

    def create_container(self):
        self.log('Create container %s' % self.container)

        tags = None
        if self.blob is None and self.tags is not None:
            # when a blob is present, then tags are assigned at the blob level
            tags = self.tags

        if not self.check_mode:
            try:
                self.blob_client.create_container(self.container, tags, self.public_access)
            except AzureHttpError, exc:
                self.fail("Error creating container {0} - {1}".format(self.container, str(exc)))
        self.container_details = self.get_container()
        self.results['changed'] = True
        self.results['actions'].append('created container {0}'.format(self.container))
        self.results['container'] = self.container_details

    def upload_blob(self):
        try:
            self.blob_client.create_blob_from_path(self.container, self.blob, self.src, metadata=self.tags)
        except AzureHttpError, exc:
            self.fail("Error creating blob {0} - {1}".format(self.blob, str(exc)))

        self.blob_details = self.get_blob()
        self.results['changed'] = True
        self.results['actions'].append('created blob {0}'.format(self.blob))
        self.results['blob'] = self.blob_details

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

        #
        #
        #
        # if mode == 'create':
        #     if container is not None:
        #         # container exists
        #         results['container'] = container
        #         results['msg'] = "Container already exists."
        #         return results
        #     # create the container
        #     if not self._module.check_mode:
        #         self.debug('Create container %s' % container_name)
        #         bs.create_container(container_name, x_ms_meta_name_values, x_ms_blob_public_access)
        #         results['container'] = get_container_facts(bs, container_name)
        #     results['msg'] = "Container created successfully."
        #     results['changed'] = True
        #     return results
        #
        # if mode == 'update':
        #     container = get_container_facts(bs, container_name)
        #     if container is None:
        #         # container does not exist
        #         if not self._module.check_mode:
        #             self.debug('Create container %s' % container_name)
        #             bs.create_container(container_name, x_ms_meta_name_values, x_ms_blob_public_access)
        #         results['changed'] = True
        #         results['msg'] = 'Container created successfully.'
        #         return results
        #     # update existing container
        #     results['msg'] = "Container not changed."
        #     if x_ms_meta_name_values:
        #         if not self._module.check_mode:
        #             self.debug('Update x_ms_meta_name_values for container %s' % container_name)
        #             bs.set_container_metadata(container_name, x_ms_meta_name_values)
        #         results['changed'] = True
        #         results['msg'] = 'Container meta data updated successfully.'
        #     if x_ms_blob_public_access:
        #         access = x_ms_blob_public_access
        #         if x_ms_blob_public_access == 'private':
        #             access = None
        #         if not self._module.check_mode:
        #             self.debug('Set access to %s for container %s' % (access, container_name))
        #             bs.set_container_acl(container_name=container_name, x_ms_blob_public_access=access)
        #         results['changed'] = True
        #         results['msg'] = 'Container ACL updated successfully.'
        #     if permissions:
        #         if hours == 0 and days == 0:
        #             raise Exception("Parameter error: expecting hours > 0 or days > 0")
        #         id = "%s-%s" % (container_name, permissions)
        #         si = get_identifier(id, hours, days, permissions)
        #         identifiers = SignedIdentifiers()
        #         identifiers.signed_identifiers.append(si)
        #         if not self._module.check_mode:
        #             self.debug('Set permissions to %s for container %s' % (permissions, container_name))
        #             bs.set_container_acl(container_name=container_name,signed_identifiers=identifiers)
        #         results['changed'] = True
        #         results['msg'] = 'Container ACL updated successfully.'
        #     results['container'] = get_container_facts(bs, container_name)
        #     return results
        #
        # if mode == 'delete':
        #     container = get_container_facts(bs, container_name)
        #     if container is None:
        #         results['msg'] = "Container %s could not be found." % container_name
        #         return results
        #     if not self._module.check_mode:
        #         self.debug('Deleting container %s' % container_name)
        #         bs.delete_container(container_name)
        #     results['changed'] = True
        #     results['msg'] = 'Container deleted successfully.'
        #     return results
        #
        # if mode == 'delete_blob':
        #     if blob_name is None:
        #         raise Exception("Parameter error: blob_name cannot be None.")
        #
        #     container = container_check(bs, container_name)
        #     blob = get_blob_facts(bs, container_name, blob_name)
        #
        #     if not blob:
        #         results['msg'] = 'Blob %s could not be found in container %s.' % (blob_name, container_name)
        #         return results
        #
        #     if not self._module.check_mode:
        #         self.debug('Deleteing %s from container %s.' % (blob_name, container_name))
        #         bs.delete_blob(container_name, blob_name)
        #     results['changed'] = True
        #     results['msg'] = 'Blob successfully deleted.'
        #     return results
        #
        # if mode == 'put':
        #     if not blob_name:
        #         raise Exception("Parameter error: blob_name cannot be None.")
        #
        #     if not file_path :
        #         raise Exception("Parameter error: file_path cannot be None.")
        #
        #     if not path_check(file_path):
        #         raise Exception("File %s does not exist." % file_path)
        #
        #     container = get_container_facts(bs, container_name)
        #     blob = None
        #     if container is not None:
        #         blob = get_blob_facts(bs, container_name, blob_name)
        #
        #     if container is not None and blob is not None:
        #         # both container and blob already exist
        #         md5_remote = blob['content-md5']
        #         md5_local = get_md5(file_path)
        #         results['container'] = container
        #         results['blob'] = blob
        #
        #         if md5_local == md5_remote:
        #             sum_matches = True
        #             results['msg'] = 'File checksums match. File not uploaded.'
        #             if overwrite == 'always':
        #                 if not self._module.check_mode:
        #                     self.debug('Uploading %s to container %s.' % (file_path, container_name))
        #                     put_block_blob(
        #                         bs,
        #                         container_name,
        #                         blob_name,
        #                         file_path,
        #                         x_ms_meta_name_values,
        #                         x_ms_blob_cache_control,
        #                         x_ms_blob_content_encoding,
        #                         x_ms_blob_content_language,
        #                         x_ms_blob_content_type
        #                     )
        #                     results['blob'] = get_blob_facts(bs, container_name, blob_name)
        #                 results['changed'] = True
        #                 results['msg'] = 'File successfully uploaded.'
        #         else:
        #             sum_matches = False
        #             if overwrite in ('always', 'different'):
        #                 if not self._module.check_mode:
        #                     self.debug('Uploading %s to container %s.' % (file_path, container_name))
        #                     put_block_blob(
        #                         bs,
        #                         container_name,
        #                         blob_name,
        #                         file_path,
        #                         x_ms_meta_name_values,
        #                         x_ms_blob_cache_control,
        #                         x_ms_blob_content_encoding,
        #                         x_ms_blob_content_language,
        #                         x_ms_blob_content_type
        #                     )
        #                     results['blob'] = get_blob_facts(bs, container_name, blob_name)
        #                 results['changed'] = True
        #                 results['msg'] = 'File successfully uploaded.'
        #             else:
        #                 results['msg'] = "WARNING: Checksums do not match. Use overwrite parameter to force upload."
        #         return results
        #
        #     if container is None:
        #         # container does not exist. create container and upload.
        #         if not self._module.check_mode:
        #             self.debug('Creating container %s.' % container_name)
        #             bs.create_container(container_name, x_ms_meta_name_values, x_ms_blob_public_access)
        #             self.debug('Uploading %s to container %s.' % (file_path, container_name))
        #             put_block_blob(
        #                 bs,
        #                 container_name,
        #                 blob_name,
        #                 file_path,
        #                 x_ms_meta_name_values,
        #                 x_ms_blob_cache_control,
        #                 x_ms_blob_content_encoding,
        #                 x_ms_blob_content_language,
        #                 x_ms_blob_content_type
        #             )
        #             results['conainer'] = get_container_facts(bs, container_name)
        #             results['blob'] = get_blob_facts(bs, container_name, blob_name)
        #         results['changed'] = True
        #         results['msg'] = 'Successfully created container and uploaded file.'
        #         return results
        #
        #     if container is not None:
        #         # container exists. just upload.
        #         if not self._module.check_mode:
        #             self.debug('Uploading %s to container %s.' % (file_path, container_name))
        #             put_block_blob(
        #                 bs,
        #                 container_name,
        #                 blob_name,
        #                 file_path,
        #                 x_ms_meta_name_values,
        #                 x_ms_blob_cache_control,
        #                 x_ms_blob_content_encoding,
        #                 x_ms_blob_content_language,
        #                 x_ms_blob_content_type
        #             )
        #             results['blob'] = get_blob_facts(bs, container_name, blob_name)
        #         results['changed'] = True
        #         results['msg'] = 'Successfully updloaded file.'
        #         return results
        #
        # if mode == 'list':
        #     container = container_check(bs, container_name)
        #     response = bs.list_blobs(
        #         container_name,
        #         prefix,
        #         marker,
        #         max_results
        #     )
        #     results['blobs'] = []
        #     for blob in response.blobs:
        #         b = dict(
        #             name = blob.name,
        #             snapshot = blob.snapshot,
        #             last_modified = blob.properties.last_modified,
        #             content_length = blob.properties.content_length,
        #             blob_type = blob.properties.blob_type,
        #         )
        #         results['blobs'].append(b)
        #     return results
        #
        # if mode == 'get':
        #     if file_path is None:
        #         raise Exception("Parameter error: file_path cannot be None.")
        #
        #     container = container_check(bs, container_name)
        #     blob = blob_check(bs, container_name, blob_name)
        #     path_exists = path_check(file_path)
        #
        #     if not path_exists or overwrite == 'always':
        #         if not self._module.check_mode:
        #             bs.get_blob_to_path(container_name, blob_name, file_path)
        #         results['changed'] = True
        #         results['msg'] = "Blob %s successfully downloaded to %s." % (blob_name, file_path)
        #         return results
        #
        #     if path_exists:
        #         md5_remote = blob['content-md5']
        #         md5_local = get_md5(file_path)
        #
        #         if md5_local == md5_remote:
        #             sum_matches = True
        #             if overwrite == 'always':
        #                 if not self._module.check_mode:
        #                     bs.get_blob_to_path(container_name, blob_name, file_path)
        #                 results['changed'] = True
        #                 results['msg'] = "Blob %s successfully downloaded to %s." % (blob_name, file_path)
        #             else:
        #                 results['msg'] = "Local and remote object are identical, ignoring. Use overwrite parameter to force."
        #         else:
        #             sum_matches = False
        #             if overwrite in ('always', 'different'):
        #                 if not self._module.check_mode:
        #                     bs.get_blob_to_path(container_name, blob_name, file_path)
        #                 results['changed'] = True
        #                 results['msg'] = "Blob %s successfully downloaded to %s." % (blob_name, file_path)
        #             else:
        #                 results['msg'] ="WARNING: Checksums do not match. Use overwrite parameter to force download."
        #
        #     if sum_matches is True and overwrite == 'never':
        #         results['msg'] = "Local and remote object are identical, ignoring. Use overwrite parameter to force."
        #
        #     return results
        #
        # if mode == 'get_url':
        #     if not blob_name:
        #         raise Exception("Parameter error: blob_name cannot be None.")
        #
        #     container = container_check(bs, container_name)
        #     blob = blob_check(bs, container_name, blob_name)
        #
        #     url = bs.make_blob_url(
        #         container_name=container_name,
        #         blob_name=blob_name,
        #         sas_token=access_token)
        #     results['url'] = url
        #     results['msg'] = "Url: %s" % url
        #     return results
        #
        # if mode == 'get_token':
        #     if hours == 0 and days == 0:
        #         raise Exception("Parameter error: expecting hours > 0 or days > 0")
        #     container = container_check(bs, container_name)
        #     blob = blob_check(bs, container_name, blob_name)
        #     results['blob_name'] = blob_name
        #     sap = get_shared_access_policy(permissions, hours=hours, days=days)
        #     token = bs.generate_shared_access_signature(container_name, blob_name, sap)
        #     results['access_token'] = token
        #     return results

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