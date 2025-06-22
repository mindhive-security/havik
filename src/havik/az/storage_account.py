# Copyright 2025 Mindhive
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
'''
    This modules scans configuration settings of Azure Storage Accounts
    in the given subscription.
'''
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from tqdm import tqdm

from havik.shared import output, llm


def create_storage_mgmt_client(credential, subscription_id):
    '''
        Creates client to do further API calls for Storage Accounts
    '''
    return StorageManagementClient(credential, subscription_id)


def get_all_storage_accounts_in_subscription(storage_client):
    '''
        Creates Iterable of all Storage Accounts in given subscription
    '''
    return storage_client.storage_accounts.list()


def check_encryption(storage_account) -> dict:
    '''
        Gather information about Storage Account encryption settings

        Args: (str) storage_account - StorageAccount object from Azure SDK
        Returns: (dict) - status of encryption settings
    '''
    encryption_status = {
        'EncryptionKeySource': storage_account.encryption.key_source,
        'InfrastructureEncryptionEnabled': storage_account.encryption.require_infrastructure_encryption,
        'Services': {
            'Blob': 'N/A',
            'File': 'N/A',
            'Table': 'N/A',
            'Queue': 'N/A'
        },
        'AllowHTTPSOnly': storage_account.enable_https_traffic_only,
        'MinimumTLS': storage_account.minimum_tls_version
    }

    if storage_account.encryption.services.blob:
        encryption_status['Services']['Blob'] = storage_account.encryption.services.blob.enabled

    if storage_account.encryption.services.file:
        encryption_status['Services']['File'] = storage_account.encryption.services.file.enabled

    if storage_account.encryption.services.table:
        encryption_status['Services']['Table'] = storage_account.encryption.services.table.enabled

    if storage_account.encryption.services.queue:
        encryption_status['Services']['Queue'] = storage_account.encryption.services.queue.enabled

    return encryption_status


def check_public_access(storage_account) -> dict:
    '''
        Gather information about Storage Account Public Access settings

        Args: (str) storage_account - StorageAccount object from Azure SDK
        Returns: (dict) - status of public access settings
    '''
    public_status = {
        'PublicNetworkAccess': storage_account.public_network_access,
        'BlobPublicAccess': storage_account.allow_blob_public_access,
        'DefaultFirewallAction': storage_account.network_rule_set.default_action
    }
    return public_status


def evaluate_storage_security(sub, enc: bool, pub: bool, noai: bool, json: bool) -> None:
    '''
        Runs different security checks on Azure Storage accounts in the subscription and reports the results

        Args:
            (bool) enc - scan encryption settings
            (bool) pub - scan public access settings
            (bool) noai - disable evaluation with LLM
            (bool) json - output in JSON format
        Returns: None
    '''
    # TODO:centralize how to aquire login tokens/credentials
    credential = DefaultAzureCredential()
    client = create_storage_mgmt_client(credential, sub)
    storage_accounts = get_all_storage_accounts_in_subscription(client)
    
    storage_account_security = {}

    for storage in tqdm(storage_accounts, desc='Scanning Storage Accounts', unit='storage'):
        storage_account_security[storage.name] = {'StorageAccountName': storage.name}

        if enc:
            storage_account_security[storage.name]['Encryption'] = check_encryption(storage)
        if pub:
            storage_account_security[storage.name]['PublicAccess'] = check_public_access(storage)
            if not noai:
                pass

    if json:
        output.output_json(storage_account_security)
    else:
        title = 'Azure Storage Accounts Security Scan Results'
        output.output_table(storage_account_security, title)
