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
    This modules scans configuration settings of AWS DynamoDB tables
    in the current account.
'''
from boto3 import client as Client
from botocore import exceptions
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from json import dumps, loads
from tqdm import tqdm

from .helpers import parse_arn, get_client

from havik.shared import output, llm, risk, compliance


def list_tables(ddb_client):
    response = ddb_client.list_tables()
    tables = [{'TableName': table, 'CreationDate': ''}
              for table in response['TableNames']]

    print(tables)

    return tables


def get_encryption(ddb_client, table_name):
    response = ddb_client.describe_table(
        TableName=table_name
    )

    return response['Table']['SSEDescription']['Status']


def get_creation_date(ddb_client, table_name):
    response = ddb_client.describe_table(
        TableName=table_name
    )

    return response['Table']['CreationDateTime']


def scan_table(ddb_client: Client, table: str, noai: bool):
    table_name = table['TableName']
    result = {
        'ResourceName': table_name,
        'CreationDate': get_creation_date(ddb_client, table_name),
        'Encryption': get_encryption(ddb_client, table_name)
    }
    return table_name, result


def evaluate_ddb_security(noai: bool, json: bool, html: bool) -> None:
    '''
        Runs different security checks on DynamoDB tables in the account and reports the results

        Args:
            (bool) noai - disable evaluation with LLM
            (bool) json - output in JSON format
            (bool) html - output in HTML format
        Returns: None
    '''
    ddb_client = get_client('dynamodb')

    tables = list_tables(ddb_client)

    table_security = {}

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(scan_table, ddb_client, table, noai) for table in tables]
        total = len(futures)
        done = set()

        with tqdm(total=total, desc='Scanning Tables', unit='table') as pbar:
            while len(done) < total:
                done_now, _ = wait(futures, timeout=0.5, return_when=FIRST_COMPLETED)
                newly_done = done_now - done
                for future in newly_done:
                    table_name, data = future.result()
                    table_security[table_name] = data
                pbar.update(len(newly_done))
                done.update(newly_done)

    if json:
        output.output_json(table_security)
    elif html:
        output.output_html(table_security)
    else:
        title = 'DynamoDB Tables Security Scan Results'
        output.output_table(table_security, title)
