'''
    This modules scans configuration settings of AWS S3 buckets
    in the current account.

    Depending on the flags chosen in the main module, it scans
    encryption or public access settings.
'''
from base64 import b64encode
from boto3 import client as boto_client
from botocore import exceptions
from hashlib import md5
from json import dumps, loads
from tqdm import tqdm

from havik.shared import output, llm

from .helpers import parse_arn

s3 = boto_client('s3')
kms = boto_client('kms')


# Encryption settings
def get_bucket_encryption(bucket: str) -> dict:
    '''
        Gets encryption configuration from the S3 bucket

        Args: (str) bucket - the name of the bucket to scan
        Returns: (dict) Encryption configuration from response
    '''
    try:
        response = s3.get_bucket_encryption(Bucket=bucket)

        return response['ServerSideEncryptionConfiguration']['Rules'][0]['ApplyServerSideEncryptionByDefault']

    except exceptions.ClientError as err:
        print(f'Encryption is not configured.')


def check_sse_c_allowed(bucket: str) -> bool:
    '''
        Checks if it is possible to upload and then get an object onto S3 bucket with a customer key (SSE-C)

        Args: (str) bucket - the name of the bucket to scan
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


def check_tls_enforced(bucket: str) -> bool:
    '''
        Checks if TLS is enforced in the bucket policy

        Args: (str) bucket - the name of the bucket to scan
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


def get_bucket_location(bucket: str) -> str:
    '''
        Gets region where the bucket is located.

        Args: (str) bucket - the name of the bucket to scan
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
def get_bucket_public_configuration(bucket: str) -> bool:
    '''
        Checks the public access configuration of the bucket

        Args: (str) bucket - the name of the bucket to scan
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
def list_buckets() -> list:
    '''
        Returns all S3 buckets in the current account, except CDK bootstrap one

        Args: None
        Returns: (list) buckets - list of S3 buckets in the current account
    '''
    response = s3.list_buckets()
    buckets = [bucket['Name'] for bucket in response['Buckets']
               if not bucket['Name'].startswith('cdk-')]

    return buckets


def evaluate_s3_encryption(bucket: str) -> dict:
    '''
        Outputs information about S3 bucket encryption settings

        Args: (str) bucket - name of S3 bucket to be scanned
        Returns: (dict) - encryption settings for the bucket
    '''
    encryption = get_bucket_encryption(bucket)
    encryption_algorithm = encryption['SSEAlgorithm']

    if encryption_algorithm == 'AES256':
        key = 'S3 managed'
    else:
        key = 'KMS managed'

    sse_c_status = check_sse_c_allowed(bucket)
    tls_status = check_tls_enforced(bucket)
    bucket_location = get_bucket_location(bucket)

    evaluate_bucket_policy(bucket)

    if 'KMSMasterKeyID' in encryption:
        encryption_key = encryption['KMSMasterKeyID']
        key_location = get_key_location(encryption_key)
    else:
        encryption_key = key
        key_location = bucket_location

    return {
        'BucketLocation': bucket_location,
        'Algorithm': encryption_algorithm,
        'Key': encryption_key,
        'KeyLocation': key_location,
        'TLS': tls_status,
        'SSE-C': sse_c_status
    }


def evaluate_s3_public_access(bucket: str) -> dict:
    '''
        Output information about S3 Public Access Block settings

        Args: (str) bucket - name of S3 bucket to be scanned
        Returns: (dict) - status of public access block settings
    '''
    return {
        'PublicAccess': get_bucket_public_configuration(bucket)
    }


def evaluate_bucket_policy(bucket: str) -> dict:
    '''
        Evaluates bucket policy with the help of LLM

        Args: (str) bucket - name of S3 bucket to be scanned
        Returns: (dict) - evaluation result
    '''
    response = s3.get_bucket_policy(Bucket=bucket)
    policy = loads(response['Policy'])

    prompt = \
    f'''
        Evaluate the following AWS IAM S3 bucket policy. 
        Respond strictly in JSON with this format: 
        {{"Policy": "Good" or "Bad", "Reason": "short explanation"}}.

        Policy:
        {dumps(policy, indent=2)}
    '''
    model_response = llm.ask_model(prompt)

    return {
        'PolicyStatus': model_response['Policy'],
        'PolicyReason': model_response['Reason']
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
    buckets = list_buckets()

    bucket_security = {}

    for bucket in tqdm(buckets, desc='Scanning Buckets', unit='bucket'):
        bucket_security[bucket] = {'BucketName': bucket}

        if enc:
            bucket_security[bucket]['Encryption'] = evaluate_s3_encryption(bucket)
        if pub:
            bucket_security[bucket]['PublicAccess'] = evaluate_s3_public_access(bucket)
            if not noai:
                bucket_security[bucket]['PolicyEval'] = evaluate_bucket_policy(bucket)

    if json:
        output.output_json(bucket_security)
    else:
        title = 'S3 Buckets Security Scan Results'
        output.output_table(bucket_security, title)
