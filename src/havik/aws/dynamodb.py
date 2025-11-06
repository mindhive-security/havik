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

from .helpers import get_client, get_region_from_arn

from havik.shared import output, llm, risk, compliance


def list_tables(ddb_client: Client) -> list:
    '''
        This function list all DynamoDB tables in the account.

        Args: (boto3.Client) ddb_client - boto3 DynamoDB client
        Returns: (list) tables - list of all DynamoDB tables in the account
    '''
    response = ddb_client.list_tables()
    tables = response['TableNames']

    return tables


def get_table_description(ddb_client: Client, table_name: str) -> dict:
    '''
        This function gets the table description in a dictionary.

        Args: (boto3.Client) ddb_client - boto3 DynamoDB client
              (str) table_name - The name of the table

        Returns: (dict) response - Response from DynamoDB API containing table description
    '''
    response = ddb_client.describe_table(
        TableName=table_name
    )

    return response['Table']


def get_pitr_status(ddb_client: Client, table_name: str) -> str:
    '''
        This function gets the status of continuous backups (PITR).

        Args: (boto3.Client) ddb_client - boto3 DynamoDB client
              (str) table_name - The name of the table

        Returns: (str) Status of PITR
    '''
    response = ddb_client.describe_continuous_backups(
        TableName=table_name
    )

    return response['ContinuousBackupsDescription']['PointInTimeRecoveryDescription']['PointInTimeRecoveryStatus']


def evaluate_dynamodb_encryption(table_desc: dict) -> dict:
    '''
        This function evaluates encryption applied to the table.

        Args: (dict) table_desc - Object with table description.

        Return: (dict) - Object with encryption data
    '''
    encryption = table_desc.get('SSEDescription', {})
    master_key_arn = encryption.get('KMSMasterKeyArn')

    if master_key_arn:
        key_location = get_region_from_arn(master_key_arn)
    else:
        key_location = get_region_from_arn(table_desc['TableArn'])

    return {
        'Status': encryption.get('Status'),
        'Algorithm': encryption.get('SSEType'),
        'Key': master_key_arn,
        'KeyLocation': key_location,
    }


def evaluate_table_policy(ddb_client: Client, table_arn: str):
    '''
        This functions evaluates resource-based policy of the table.

        Args: (boto3.Client) ddb_client - boto3 DynamoDB client
              (str) table_name - The name of the table
    '''
    try:
        response = ddb_client.get_resource_policy(
            ResourceArn=table_arn
        )
    except ddb_client.exceptions.PolicyNotFoundException as err:
        return {
            'Status': 'None',
            'Reason': 'No policy'
        }

    policy = loads(response['Policy'])

    prompt = \
        f'''
    You are an automated security AWS IAM policy evaluator.
    "Rules:\n"
    "- If the policy allows public access (Principal: *) and has no limiting conditions, mark as Bad.\n"
    "- If policy allows all actions (Action: dynamodb:*), mark as Bad.\n"
    "- If there are wilcards in policy and no conditions, mark as Bad.\n"
    "- If cross-account or cross-service access is allowed and no conditions limiting it on SourceArn, SourceAccount or OrgId, mark as Bad.\n"
    "- If only internal actions (like logging), mark as Good.\n"
    "- Otherwise, use best judgement.\n\n"

    Return ONLY a valid JSON object in this format:
    Never use special symbols like "*" in the output, it must be JSON serializable all the time.
    {{
    "Status": "Good" | "Bad",
    "Reason": "<short explanation without line breaks>" (must be correct JSON serializable, do not use any special symbols or quotes.)
    }}

    Evaluate the following AWS IAM DynamoDB resource policy:
    {dumps(policy, indent=2)}
    '''
    model_response = llm.ask_model(prompt)

    return {
        'Status': model_response['Status'],
        'Reason': model_response['Reason']
    }


def scan_table(ddb_client: Client, table_name: str, noai: bool, provider: str, service: str) -> tuple[str, dict]:
    '''
        This function scans security configuration of the DynamoDB table.

        Args: (boto3.Client) ddb_client - boto3 DynamoDB client
              (str) table_name - The name of the table
              (bool) noai - Flag disabling evaluation by AI
              (str) provider - cloud provider
              (str) service - cloud service

        Returns: (str) table_name - The name of the table
                 (dict) response - Response from DynamoDB API containing table description
    '''
    table_desc = get_table_description(ddb_client, table_name)
    table_arn = table_desc['TableArn']

    result = {
        'ResourceName': table_name,
        'CreationDate': str(table_desc['CreationDateTime']),
        'Encryption': evaluate_dynamodb_encryption(table_desc),
        'BackupStatus': get_pitr_status(ddb_client, table_name),
        'Location': get_region_from_arn(table_arn),
    }

    if not noai:
        result['PolicyEval'] = evaluate_table_policy(ddb_client, table_arn)

    result['Risk'] = risk.calculate_risk_score(result, noai, provider, service)

    compliance_checks = ['Encryption', 'Location', 'Versioning']
    result['Compliance'] = {'CSA_CCM': {}}
    result['Compliance']['CSA_CCM'] = compliance.ccm_map('AWS', 'DynamoDB', compliance_checks)

    return table_name, result


def evaluate_dynamodb_security(noai: bool, json: bool, html: bool, provider: str, service: str) -> None:
    '''
        Runs different security checks on DynamoDB tables in the account and reports the results

        Args:
            (bool) noai - disable evaluation with LLM
            (bool) json - output in JSON format
            (bool) html - output in HTML format
            (str) provider - cloud provider
            (str) service - cloud service
        Returns: None
    '''
    ddb_client = get_client('dynamodb')

    tables = list_tables(ddb_client)

    table_security = {}

    with ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(scan_table, ddb_client, table_name, noai, provider, service)
                   for table_name in tables]
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
