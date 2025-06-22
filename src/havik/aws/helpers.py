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
