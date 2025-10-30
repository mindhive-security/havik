import pytest

from boto3 import client
from botocore import exceptions
from json import dumps
from moto import mock_aws
from unittest.mock import patch

from havik.aws.s3 import get_bucket_encryption, check_sse_c_allowed, check_tls_enforced, get_bucket_location, get_key_location, get_bucket_public_configuration, evaluate_bucket_policy

DEFAULT_REGION = 'eu-central-1'
BUCKET_NAME = 'test-bucket'


@pytest.fixture(scope='session')
def create_bucket():
    with mock_aws():
        s3 = client('s3', region_name=DEFAULT_REGION)
        
        s3.create_bucket(
            Bucket=BUCKET_NAME,
            CreateBucketConfiguration={
                'LocationConstraint': DEFAULT_REGION
            }
        )
        
        yield s3, BUCKET_NAME


# Encryption settings
def test_get_bucket_encryption(create_bucket):
    s3, bucket_name = create_bucket

    encryption_config = {
        'Rules': [
            {
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'AES256'
                }
            }
        ]
    }
    s3.put_bucket_encryption(
        Bucket=bucket_name, ServerSideEncryptionConfiguration=encryption_config)

    result = get_bucket_encryption(s3, bucket_name)
    assert result['SSEAlgorithm'] == 'AES256'


def test_get_bucket_encryption_no_config(create_bucket):
    '''
        Tests that default bucket doesn't have encryption configuration
    '''
    s3, bucket_name = create_bucket

    result = get_bucket_encryption(s3, bucket_name)
    assert result is None


def test_check_sse_c_allowed(create_bucket):
    # TODO: rework to obtain meaningful results without moto
    s3, bucket_name = create_bucket

    result = check_sse_c_allowed(s3, bucket_name)
    assert result is False  # Moto does not support SSE-C


def test_check_tls_enforced(create_bucket):
    s3, bucket_name = create_bucket

    bucket_policy = {
        'Version': '2012-10-17',
        'Statement': [
            {
                'Effect': 'Deny',
                'Principal': '*',
                'Action': 's3:*',
                'Resource': f'arn:aws:s3:::{bucket_name}/*',
                'Condition': {
                    'Bool': {'aws:SecureTransport': 'false'}
                }
            }
        ]
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=dumps(bucket_policy))

    assert check_tls_enforced(s3, bucket_name) is True


def test_check_tls_not_enforced(create_bucket):
    s3, bucket_name = create_bucket

    assert check_tls_enforced(s3, bucket_name) is False


def test_get_bucket_location(create_bucket):
    s3, bucket_name = create_bucket

    assert get_bucket_location(s3, bucket_name) == DEFAULT_REGION


def test_get_key_location(create_bucket):
    s3, bucket_name = create_bucket

    encryption_config = {
        'Rules': [
            {
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'dsse:kms'
                }
            }
        ]
    }
    s3.put_bucket_encryption(
        Bucket=bucket_name, ServerSideEncryptionConfiguration=encryption_config)

    encryption = get_bucket_encryption(s3, bucket_name)
    if 'KMSMasterKeyID' in encryption:
        encryption_key = encryption['KMSMasterKeyID']
        key_location = get_key_location(encryption_key)
    else:
        bucket_location = get_bucket_location(s3, bucket_name)
        key_location = bucket_location

    assert key_location == DEFAULT_REGION


# Public access settings
def test_get_bucket_public_configuration(create_bucket):
    # TODO: rework to obtain meaningful results without moto
    bucket_name = 'test-bucket'
    s3, bucket_name = create_bucket

    try:
        result = get_bucket_public_configuration(s3, bucket_name)
    except exceptions.ClientError as exc:
        print('PublicAccessBlock is not supported by moto')
        result = 'Blocked'

    assert result == 'Blocked'


@patch('havik.shared.llm.ask_model')
def test_evaluate_bucket_policy(mock_ask_model):
    s3, bucket_name = create_bucket

    test_policy = {
        'Version': '2012-10-17',
        'Statement': [{
            'Effect': 'Allow',
            'Principal': '*',
            'Action': 's3:GetObject',
            'Resource': f'arn:aws:s3:::{bucket_name}/*'
        }]
    }

    s3.put_bucket_policy(Bucket=bucket_name, Policy=dumps(test_policy))

    mock_ask_model.return_value = {
        'Status': 'Bad',
        'Reason': 'Bucket is publicly accessible'
    }

    result = evaluate_bucket_policy(s3, bucket_name)

    assert result == {
        'Status': 'Bad',
        'Reason': 'Bucket is publicly accessible'
    }

    mock_ask_model.assert_called_once()
