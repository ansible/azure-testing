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
from ansible.module_utils.azure_rm_common import *


try:
    from azure.storage.blob.models import ContentSettings
    from azure.storage.cloudstorageaccount import CloudStorageAccount
    from azure.common import AzureMissingResourceHttpError, AzureHttpError
except ImportError:
    # This is handled in azure_rm_common
    pass

DOCUMENTATION = '''
---
module: azure_rm_storageblob

short_description: Create and manage blob containers and blob objects.

description:
    - Create and manage blob containers and blobs within a given storage account. Upload and download blobs. Set blob

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
    content_type
        description:
            - Set the blob content-type header. For example, 'image/png'.
        default: null
    cache_control:
        description:
            - Set the blob cache-control header.
        default: null
    content_disposition:
        description:
            - Set the blob content-disposition header.
        default: null
    content_encoding:
        description:
            - Set the blob encoding header.
        default: null
    content_language:
        description:
            - Set the blob content-language header.
        default: null
    content_md5:
        description:
            - Set the blob md5 hash value.
        default: null
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
            - Determine a container's level of public access. By default containers are private. Can only be set at
              time of container creation.
        choices:
            - container
            - blob
        default: null
    tags:
        description:
            - Dictionary of key:value pairs to add to either a container or blob.
        default: null

requirements:
    - "python >= 2.7"
    - "azure >= 1.0.2"

author: "Chris Houseknecht @chouseknecht"
'''

EXAMPLES = '''
- name: Remove container foo
  azure_rm_storageblob:
    resource_group: testing
    storage_account: clh0002
    container: foo
    state: absent

- name: Create container foo and upload a file
  azure_rm_storageblob:
    resource_group: Testing
    storage_account: clh0002
    container: foo
    blob: graylog.png
    src: ./files/graylog.png
    public_access: container
    content_type: 'application/image'

- name: Download the file
  azure_rm_storageblob:
    resource_group: Testing
    storage_account: clh0002
    container: foo
    blob: graylog.png
    dest: ~/tmp/images/graylog.png
'''

RETURN = '''
{
    "actions": [
        "updated blob foo:graylog.png content settings."
    ],
    "blob": {
        "content_length": 136532,
        "content_settings": {
            "cache_control": null,
            "content_disposition": null,
            "content_encoding": null,
            "content_language": null,
            "content_md5": null,
            "content_type": "application/image"
        },
        "last_modified": "09-Mar-2016 22:08:25 +0000",
        "name": "graylog.png",
        "tags": {},
        "type": "BlockBlob"
    },
    "changed": true,
    "check_mode": false,
    "container": {
        "last_mdoified": "09-Mar-2016 19:28:26 +0000",
        "name": "foo",
        "tags": {}
    }
}
'''


NAME_PATTERN = re.compile(r"^(?!-)(?!.*--)[a-z0-9\-]+$")


class AzureRMStorageBlob(AzureRMModuleBase):

    def __init__(self, **kwargs):

        self.module_arg_spec = dict(
            storage_account=dict(required=True, type='str'),
            blob=dict(type='str', aliases=['blob_name']),
            container=dict(required=True, type='str', aliases=['container_name']),
            dest=dict(type='str'),
            force=dict(type='bool', default=False),
            resource_group=dict(required=True, type='str'),
            src=dict(type='str'),
            state=dict(type='str', default='present', choices=['absent', 'present']),
            tags=dict(type='dict'),
            public_access=dict(type='str', choices=['container', 'blob']),
            content_type=dict(type='str'),
            content_encoding=dict(type='str'),
            content_language=dict(type='str'),
            content_disposition=dict(type='str'),
            cache_control=dict(type='str'),
            content_md5=dict(type='str'),
            # TODO: implement object security
        )

        mutually_exclusive = [('src', 'dest')]

        super(AzureRMStorageBlob, self).__init__(derived_arg_spec=self.module_arg_spec,
                                                 supports_check_mode=True,
                                                 mutually_exclusive=mutually_exclusive,
                                                 **kwargs)

        self.blob_client = None
        self.blob_details = None
        self.storage_account = None
        self.blob = None
        self.blob_obj = None
        self.container = None
        self.container_obj = None
        self.dest = None
        self.force = None
        self.resource_group = None
        self.src = None
        self.state = None
        self.tags = None
        self.public_access = None
        self.results = dict(changed=False,
                            check_mode=self.module.check_mode,
                            actions=[],
                            container=dict(),
                            blob=dict())

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
            self.fail("Error getting keys for account {0}: {1}".format(self.storage_account, str(e)))

        try:
            self.log('Create blob service')
            self.blob_client = CloudStorageAccount(self.storage_account, keys['key1']).create_block_blob_service()
        except Exception as e:
            self.fail("Error creating blob service client: {0}".format(str(e)))

        self.container_obj = self.get_container()

        if self.blob is not None:
            self.blob_obj = self.get_blob()

        if self.state == 'present':
            if self.container_obj is None:
                # create the container
                self.create_container()
            elif self.blob is None:
                # update container attributes
                if self.tags and self.container_obj.get('tags') != self.tags:
                    # Update container tags
                    self.update_container_tags()

            if self.blob is not None:
                # create, update or download blob
                if self.src is not None and self.src_is_valid():
                    if self.blob_obj is None or self.force:
                        self.upload_blob()

                elif self.dest is not None:
                    if self.dest_is_valid():
                        self.download_blob()

                if self.tags and self.blob_obj.get('tags') != self.tags:
                    self.update_blob_tags()

                if self.blob_content_settings_differ():
                    self.update_blob_content_settings()

        elif self.state == 'absent':
            if self.container_obj is not None and self.blob is None:
                # Delete container
                if self.container_has_blobs():
                    if self.force:
                        self.delete_container()
                    else:
                        self.results['actions'].append("Skipped delete container {0}. Container has blobs.".format(
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
                last_modified=response.properties.last_modified.strftime('%d-%b-%Y %H:%M:%S %z'),
                type=response.properties.blob_type,
                content_length=response.properties.content_length,
                content_settings=dict(
                    content_type=response.properties.content_settings.content_type,
                    content_encoding=response.properties.content_settings.content_encoding,
                    content_language=response.properties.content_settings.content_language,
                    content_disposition=response.properties.content_settings.content_disposition,
                    cache_control=response.properties.content_settings.cache_control,
                    content_md5 =response.properties.content_settings.content_md5
                )
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
        content_settings = None
        if self.content_type or self.content_encoding or self.content_language or self.content_disposition or \
                self.cache_control or self.content_md5:
            content_settings = ContentSettings(
                content_type=self.content_type,
                content_encoding=self.content_encoding,
                content_language=self.content_language,
                content_disposition=self.content_disposition,
                cache_control=self.cache_control,
                content_md5=self.content_md5
            )

        try:
            self.blob_client.create_blob_from_path(self.container, self.blob, self.src,
                                                   metadata=self.tags, content_settings=content_settings)
        except AzureHttpError, exc:
            self.fail("Error creating blob {0} - {1}".format(self.blob, str(exc)))

        self.blob_obj = self.get_blob()
        self.results['changed'] = True
        self.results['actions'].append('created blob {0} from {1}'.format(self.blob, self.src))
        self.results['container'] = self.container_obj
        self.results['blob'] = self.blob_obj

    def download_blob(self):
        try:
            self.blob_client.get_blob_to_path(self.container, self.blob, self.dest)
        except Exception, exc:
            self.fail("Failed to download blob {0}:{1} to {2} - {3}".format(self.container,
                                                                            self.blob,
                                                                            self.dest,
                                                                            exc))
            self.results['changed'] = True
            self.results['actions'].append('downloaded blob {0}:{1} to {2}'.format(self.container,
                                                                                   self.blob,
                                                                                   self.dest))

            self.results['container'] = self.container_obj
            self.results['blob'] = self.blob_obj

    def src_is_valid(self):
        if not os.path.isfile(self.src):
            self.fail("The source path must be a file.")
        try:
            fp = open(self.src, 'r')
            fp.close()
        except IOError as e:
            self.fail("Failed to access {0}. Make sure the file exists and that you have "
                      "read access.".format(self.src))
        return True

    def dest_is_valid(self):
        self.dest = os.path.expanduser(self.dest)
        self.dest = os.path.expandvars(self.dest)
        if not os.path.basename(self.dest):
            # dest is a directory
            if os.path.isdir(self.dest):
                self.log("Path is dir. Appending blob name.")
                self.dest += self.blob
            else:
                try:
                    self.log('Attempting to makedirs {0}'.format(self.dest))
                    os.makddirs(self.dest)
                except IOError, exc:
                    self.fail("Failed to create directory {0} - {1}".format(self.dest, exc))
                self.dest += self.blob
        else:
            # does path exist without basename
            file_name = os.path.basename(self.dest)
            path = self.dest.replace(file_name, '')
            self.log('Checking path {0}'.format(path))
            if not os.path.isdir(path):
                try:
                    self.log('Attempting to makedirs {0}'.format(path))
                    os.makedirs(path)
                except IOError, exc:
                    self.fail("Failed to create directory {0} - {1}".format(path, exc))
        self.log('Checking final path {0}'.format(self.dest))
        if os.path.isfile(self.dest) and not self.force:
            # dest already exists and we're not forcing
            self.log('Path already exists')
            return False
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
            list_generator = self.blob_client.list_blobs(self.container)
        except AzureHttpError, exc:
            self.fail("Error list blobs in {0} - {1}".format(self.container, str(exc)))
        if len(list_generator.items) > 0:
            return True
        return False

    def delete_blob(self):
        try:
            self.blob_client.delete_blob(self.container, self.blob)
        except AzureHttpError, exc:
            self.fail("Error deleting blob {0}:{1} - {2}".format(self.container, self.blob, str(exc)))

        self.results['changed'] = True
        self.results['actions'].append('deleted blob {0}:{1}'.format(self.container, self.blob))
        self.results['container'] = self.container_obj

    def update_container_tags(self):
        try:
            self.blob_client.set_container_metadata(self.container, metadata=self.tags)
        except AzureHttpError, exc:
            self.fail("Error updating container tags {0} - {1}".format(self.container, str(exc)))
        self.container_obj = self.get_container()
        self.results['changed'] = True
        self.results['actions'].append("updated container {0} tags.".format(self.container))
        self.results['container'] = self.container_obj

    def update_blob_tags(self):
        try:
            self.blob_client.set_blob_metadata(self.container, self.blob, metadata=self.tags)
        except AzureHttpError, exc:
            self.fail("Update blob tags {0}:{1} - {2}".format(self.container, self.blob, exc))
        self.blob_obj = self.get_blob()
        self.results['changed'] = True
        self.results['actions'].append("updated blob {0}:{1} tags.".format(self.container, self.blob))
        self.results['container'] = self.container_obj
        self.results['blob'] = self.blob_obj

    def blob_content_settings_differ(self):
        if self.content_type or self.content_encoding or self.content_language or self.content_disposition or \
                self.cache_control or self.content_md5:
            settings = dict(
                content_type=self.content_type,
                content_encoding=self.content_encoding,
                content_language=self.content_language,
                content_disposition=self.content_disposition,
                cache_control=self.cache_control,
                content_md5=self.content_md5
            )
            if self.blob_obj['content_settings'] != settings:
                return True

        return False

    def update_blob_content_settings(self):
        content_settings = ContentSettings(
            content_type=self.content_type,
            content_encoding=self.content_encoding,
            content_language=self.content_language,
            content_disposition=self.content_disposition,
            cache_control=self.cache_control,
            content_md5=self.content_md5
        )
        try:
            self.blob_client.set_blob_properties(self.container, self.blob, content_settings=content_settings)
        except AzureHttpError, exc:
            self.fail("Update blob content settings {0}:{1} - {2}".format(self.container, self.blob, exc))

        self.blob_obj = self.get_blob()
        self.results['changed'] = True
        self.results['actions'].append("updated blob {0}:{1} content settings.".format(self.container, self.blob))
        self.results['container'] = self.container_obj
        self.results['blob'] = self.blob_obj

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