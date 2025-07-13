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

from google.cloud import storage
from json import dumps
from tqdm import tqdm

from havik.shared import output, llm, risk


def get_client() -> storage.Client:
    '''
        Returns GCP storage API client

        Args: None

        Returns: (storage.Client) - GCP client
    '''
    return storage.Client()


# Encryption settings
def parse_key(key: str) -> str:
    '''
        Returns the location of the encryption key

        Args: (str) key - encryption key used to encrypt the bucket
        Returns: (str) - key location parsed from the name, e.g.
            projects/project-1234/locations/europe-west1/keyRings/storage-eu/cryptoKeys/buckets-eu -> europe-west1
    '''
    return key.split('/')[3]


def evaluate_storage_encryption(bucket: dict) -> dict:
    '''
        Gets the encryption algorithm applied to the bucket

        Args: (dict) bucket - GCS bucket structure
        Returns: (dict) - encryption settings for the bucket
    '''
    default_kms_key_name = bucket.default_kms_key_name
    bucket_location = bucket.location.lower()
    encryption_algorithm = 'AES-256'

    if default_kms_key_name:
        encryption_key = 'Customer Managed'
        key_location = parse_key(default_kms_key_name)
    else:
        encryption_key = 'Google Managed'
        key_location = bucket_location

    return {
        'BucketLocation': bucket_location,
        'Algorithm': encryption_algorithm,
        'Key': encryption_key,
        'KeyLocation': key_location
    }


# Public access settings
def evaluate_bucket_policy(bucket: dict) -> dict:
    '''
        Evaluates GCS bucket policy with LLM.
        Returns general status of the policy and reasoning.

        Args: (dict) bucket - GCS bucket structure

        Returns: (dict) - dictionary with status and reason
    '''
    policy = bucket.get_iam_policy(requested_policy_version=3)
    policy_json = dumps(policy.to_api_repr(), indent=2)

    prompt = \
        f'''
        Evaluate the following GCP storage bucket policy.
        Respond strictly in JSON with this format:
        {{"Status": "Good" or "Bad", "Reason": "short explanation"}}.

        Policy:
        {dumps(policy_json, indent=2)}
    '''
    model_response = llm.ask_model(prompt)

    return {
        'Status': model_response['Status'],
        'Reason': model_response['Reason']
    }


def evaluate_storage_public_access(bucket: dict) -> dict:
    '''
        Output information about GCS Public Access settings.
        Checks if public access prevention is set.

        Args: (dict) bucket - GCS bucket structure
        Returns: (dict) - status of public access prevention
    '''
    bucket_iam = bucket.iam_configuration
    public_access = 'Allowed'

    if bucket_iam.public_access_prevention == 'enforced':
        public_access = 'Blocked'

    return {
        'Status': public_access
    }


# Dispatcher
def list_buckets() -> list:
    '''
        Returns all buckets in the current account

        Args: None
        Returns: (list) - list of buckets in the current account
    '''
    return get_client().list_buckets()


def evaluate_storage_security(enc: bool, pub: bool, noai: bool, json: bool, html: bool) -> None:
    '''
        Runs different security checks on GCS buckets in the account and reports the results

        Args:
            (bool) enc - scan encryption settings
            (bool) pub - scan public access settings
            (bool) noai - disable evaluation with LLM
            (bool) json - output in JSON format
            (bool) html - output in HTML format
        Returns: None
    '''
    buckets = list_buckets()

    bucket_security = {}

    for bucket in tqdm(buckets, desc='Scanning Buckets', unit='bucket'):
        bucket_security[bucket.name] = {'BucketName': bucket.name}
        bucket_security[bucket.name]['CreationDate'] = str(bucket.time_created)

        bucket_security[bucket.name]['Encryption'] = evaluate_storage_encryption(bucket)
        bucket_security[bucket.name]['PublicAccess'] = evaluate_storage_public_access(bucket)
        bucket_security[bucket.name]['Location'] = evaluate_storage_encryption(bucket)['BucketLocation']

        if not noai:
            bucket_security[bucket.name]['PolicyEval'] = evaluate_bucket_policy(bucket)

        bucket_security[bucket.name]['Risk'] = risk.calculate_risk_score(bucket_security[bucket.name], noai)

    if json:
        output.output_json(bucket_security)
    elif html:
        output.output_html(bucket_security)
    else:
        title = 'GCS Buckets Security Scan Results'
        output.output_table(bucket_security, title)
