import pytest
from boto3 import client
from moto import mock_aws
from havik.aws.dynamodb import *

DEFAULT_REGION = 'eu-central-1'
TABLE_NAME = 'test-table'


@pytest.fixture(scope="session")
def create_table():
    with mock_aws():
        ddb = client("dynamodb", region_name=DEFAULT_REGION)

        ddb.create_table(
            TableName=TABLE_NAME,
            AttributeDefinitions=[
                {
                    'AttributeName': 'Key',
                    'AttributeType': 'S',
                },
                {
                    'AttributeName': 'Key2',
                    'AttributeType': 'S',
                },
            ],
            KeySchema=[
                {
                    'AttributeName': 'Key',
                    'KeyType': 'HASH',
                },
                {
                    'AttributeName': 'Key2',
                    'KeyType': 'RANGE',
                },
            ],
            BillingMode="PAY_PER_REQUEST",
        )

        yield ddb, TABLE_NAME


def test_list_tables(create_table):
    ddb, table_name = create_table

    result = list_tables(ddb)
    assert result == [table_name]


def test_get_pitr_status_disabled(create_table):
    ddb, table_name = create_table

    result = get_pitr_status(ddb, table_name)
    assert result == 'DISABLED'


def test_get_pitr_status_enabled(create_table):
    ddb, table_name = create_table

    ddb.update_continuous_backups(
        TableName=table_name,
        PointInTimeRecoverySpecification={
            'PointInTimeRecoveryEnabled': True,
            'RecoveryPeriodInDays': 123
        }
    )

    result = get_pitr_status(ddb, table_name)
    assert result == 'ENABLED'
