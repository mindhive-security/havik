'''
    Here stored useful functions, called by other modules
'''
from boto3 import client


def parse_arn(arn: str) -> list:
    '''
        Parses AWS ARN and returns a list of values

        Args: (str) arn - ARN to parse
        Returns: (list) - The list of ARN components
    '''
    return arn.split(':')


def get_client(service: str, region_name: str = 'eu-central-1'):
    return client(service, region_name=region_name)
