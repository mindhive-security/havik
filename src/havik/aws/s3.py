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
    This modules scans configuration settings of AWS S3 buckets
    in the current account.

    Depending on the flags chosen in the main module, it scans
    encryption or public access settings.
'''
from base64 import b64encode
from boto3 import client as Client
from botocore import exceptions
from hashlib import md5
from json import dumps, loads
from tqdm import tqdm

from havik.shared import output, llm, risk

from .helpers import parse_arn, get_client


# Encryption settings
def get_bucket_encryption(s3: Client, bucket:str) -> dict:
    '''
        Gets encryption configuration from the S3 bucket

        Args: (boto3.client) s3 - S3 client
              (str) bucket - the name of the bucket to scan
        Returns: (dict) Encryption configuration from response
    '''
    try:
        response = s3.get_bucket_encryption(Bucket=bucket)

        return response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']

    except exceptions.ClientError as err:
        print(f'Encryption is not configured.')


def check_sse_c_allowed(s3: Client, bucket:str) -> bool:
    '''
        Checks if it is possible to upload and then get an object onto S3 bucket with a customer key (SSE-C)

        Args: (boto3.client) s3 - S3 client
              (str) bucket - the name of the bucket to scan
        Returns: (bool) sse_c_status - if True, then SSE-C is allowed, posing a security risk
    '''
    object_key = 'example.txt'
    encryption_key = b'0123456789abcdef0123456789abcdef'
    sse_c_status = None

    sse_headers = {
        'SSECustomerAlgorithm': 'AES256',
        'SSECustomerKey': b64encode(encryption_key).decode('utf-8'),
        'SSECustomerKeyMD5': b64encode(md5(encryption_key).digest()).decode('utf-8')
    }

    with open('src/havik/aws/files/example.txt', 'rb') as data:
        try:
            s3.put_object(
                Bucket=bucket,
                Key=object_key,
                Body=data,
                SSECustomerAlgorithm=sse_headers['SSECustomerAlgorithm'],
                SSECustomerKey=sse_headers['SSECustomerKey'],
                SSECustomerKeyMD5=sse_headers['SSECustomerKeyMD5']
            )
        except s3.exceptions.ClientError as e:
            if 'explicit deny in a resource-based policy' in str(e):
                sse_c_status = False
                return sse_c_status

    try:
        s3.get_object(Bucket=bucket, Key=object_key)
        sse_c_status = False
    except s3.exceptions.ClientError as e:
        if 'SSECustomerKey' in str(e) or 'InvalidRequest' in str(e):
            sse_c_status = True
            return sse_c_status
        else:
            print(f'Other error: {e}')

    try:
        s3.get_object(
            Bucket=bucket,
            Key=object_key,
            SSECustomerAlgorithm='AES256',
            SSECustomerKey=b64encode(encryption_key).decode('utf-8'),
            SSECustomerKeyMD5=b64encode(
                md5(encryption_key).digest()).decode('utf-8')
        )
    except:
        print('Something went wrong with getting object')

    return sse_c_status


def check_tls_enforced(s3: Client, bucket:str) -> bool:
    '''
        Checks if TLS is enforced in the bucket policy

        Args: (boto3.client) s3 - S3 client
              (str) bucket - the name of the bucket to scan
        Returns: (bool) - if True, the TLS is enforced in the bucket policy
    '''
    try:
        response = s3.get_bucket_policy(Bucket=bucket)
        policy = loads(response['Policy'])

        for statement in policy.get('Statement', []):
            if statement.get('Effect') == 'Deny':
                condition = statement.get('Condition', {})
                if 'Bool' in condition and condition['Bool'].get('aws:SecureTransport') == 'false':
                    return True

    except s3.exceptions.from_code('NoSuchBucketPolicy'):
        print('No bucket policy found')

    return False


def get_bucket_location(s3: Client, bucket:str) -> str:
    '''
        Gets region where the bucket is located.

        Args: (boto3.client) s3 - S3 client
              (str) bucket - the name of the bucket to scan
        Returns: (str) location - The bucket's region
    '''
    location = s3.get_bucket_location(Bucket=bucket)

    return location['LocationConstraint']


def get_key_location(encryption_key: str) -> str:
    '''
        Parses key location from key ARN

        Args: (str) encryption_key - ARN of the encryption key
        Returns: (str) - region part of the ARN
    '''
    return parse_arn(encryption_key)[3]


# Public access settings
def get_bucket_public_configuration(s3: Client, bucket:str) -> bool:
    '''
        Checks the public access configuration of the bucket

        Args: (boto3.client) s3 - S3 client
              (str) bucket - the name of the bucket to scan
        Returns: (bool) - if True, public access is blocked completely
    '''
    public_access_block = s3.get_public_access_block(
        Bucket=bucket
    )

    for block in public_access_block['PublicAccessBlockConfiguration'].values():
        if not block:
            return False

    return True


# Dispatcher
def list_buckets(s3: Client) -> list:
    '''
        Returns all S3 buckets in the current account, except CDK bootstrap one

        Args: (boto3.client) s3 - S3 client
        Returns: (list) buckets - list of S3 buckets in the current account
    '''
    response = s3.list_buckets()
    buckets = [{'BucketName': bucket['Name'], 'CreationDate': bucket['CreationDate']} for bucket in response['Buckets']
               if not bucket['Name'].startswith('cdk-')]

    return buckets


def evaluate_s3_encryption(s3: Client, bucket:str) -> dict:
    '''
        Outputs information about S3 bucket encryption settings

        Args: (boto3.client) s3 - S3 client
              (str) bucket - name of S3 bucket to be scanned
        Returns: (dict) - encryption settings for the bucket
    '''
    encryption = get_bucket_encryption(s3, bucket)
    encryption_algorithm = encryption['SSEAlgorithm']

    if encryption_algorithm == 'AES256':
        key = 'S3 managed'
    else:
        key = 'KMS managed'

    sse_c_status = check_sse_c_allowed(s3, bucket)
    tls_status = check_tls_enforced(s3, bucket)
    bucket_location = get_bucket_location(s3, bucket)

    if 'KMSMasterKeyID' in encryption:
        encryption_key = encryption['KMSMasterKeyID']
        key_location = get_key_location(encryption_key)
    else:
        encryption_key = key
        key_location = bucket_location

    return {
        'Algorithm': encryption_algorithm,
        'Key': encryption_key,
        'KeyLocation': key_location,
        'TLS': tls_status,
        'SSE-C': sse_c_status
    }


def evaluate_s3_public_access(s3: Client, bucket:str) -> dict:
    '''
        Output information about S3 Public Access Block settings

        Args: (boto3.client) s3 - S3 client
              (str) bucket - name of S3 bucket to be scanned
        Returns: (dict) - status of public access block settings
    '''
    return {'Status': 'Blocked'} if get_bucket_public_configuration(s3, bucket) else {'Status': 'Allowed'}


def evaluate_bucket_policy(s3: Client, bucket:str) -> dict:
    '''
        Evaluates bucket policy with the help of LLM

        Args: (boto3.client) s3 - S3 client
              (str) bucket - name of S3 bucket to be scanned
        Returns: (dict) - evaluation result
    '''
    response = s3.get_bucket_policy(Bucket=bucket)
    policy = loads(response['Policy'])

    prompt = \
    f'''
        You are an automated security AWS IAM policy evaluator.
        "Rules:\n"
        "- If the policy allows public access (Principal: *) and has no limiting conditions, mark as Bad.\n"
        "- If policy allows all actions (Action: s3:*), mark as Bad.\n"
        "- If there are wilcards in policy and no conditions, mark as Bad.\n"
        "- If cross-account or cross-service access is allowed and no conditions limiting it on SourceArn, SourceAccount or OrgId, mark as Bad.\n"
        "- If only internal actions (like logging), mark as Good.\n"
        "- Otherwise, use best judgement.\n\n"

        Return ONLY a valid JSON object in this format:
        {{
        "Status": "Good" | "Bad",
        "Reason": "<short explanation without line breaks>" (must be correct JSON serializable, do not use any special symbols or quotes.)
        }}

        Evaluate the following AWS IAM S3 bucket policy:
        {dumps(policy, indent=2)}
    '''
    model_response = llm.ask_model(prompt)

    return {
        'Status': model_response['Status'],
        'Reason': model_response['Reason']
    }


def evaluate_s3_security(enc: bool, pub: bool, noai: bool, json: bool) -> None:
    '''
        Runs different security checks on S3 buckets in the account and reports the results

        Args:
            (bool) enc - scan encryption settings
            (bool) pub - scan public access settings
            (bool) noai - disable evaluation with LLM
            (bool) json - output in JSON format
        Returns: None
    '''
    s3_client = get_client('s3')

    buckets = list_buckets(s3_client)

    bucket_security = {}

    for bucket in tqdm(buckets, desc='Scanning Buckets', unit='bucket'):
        bucket_name = bucket['BucketName']
        bucket_security[bucket_name] = bucket
        bucket_security[bucket_name]['CreationDate'] = str(bucket['CreationDate'])
        bucket_security[bucket_name]['Encryption'] = evaluate_s3_encryption(s3_client, bucket_name)
        bucket_security[bucket_name]['PublicAccess'] = evaluate_s3_public_access(s3_client, bucket_name)
        bucket_security[bucket_name]['Location'] = get_bucket_location(s3_client, bucket_name)
        
        if not noai:
            bucket_security[bucket_name]['PolicyEval'] = evaluate_bucket_policy(s3_client, bucket_name)
        
        bucket_security[bucket_name]['Risk'] = risk.calculate_risk_score(bucket_security[bucket_name], noai)

    if json:
        output.output_json(bucket_security)
    else:
        title = 'S3 Buckets Security Scan Results'
        output.output_table(bucket_security, title)
