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
    This tool scans cloud services' configuration settings to
    evaluate cloud security posture.

    It supports AWS, GCP and Azure public cloud service providers.

    The scanner supports multiple command line arguments, which define
    what modules will be launched.

    The main focus of scanning is to indicate problematic misconfigured
    services which can pose a security risk. The tool itself does not
    evaluate the risk, it should be used in alignment with existing
    threat model.
'''
import argparse
import importlib

SUPPORTED_SERVICES_AWS = ['s3', 'dynamodb']
SUPPORTED_SERVICES_GCP = ['storage']
SUPPORTED_SERVICES_AZ = ['storage']


def main() -> None:
    '''
        This is the main module - to call security evaluations for different
        services and configurations.
    '''
    description = 'This tool scans cloud resources and provides security report'
    parser = argparse.ArgumentParser(description=description)

    provider = parser.add_argument_group("Cloud provider")
    provider.add_argument('provider', choices=['aws', 'gcp', 'az'], default='aws', help='Cloud provider')

    services = parser.add_argument_group("Services")
    services.add_argument('service', help='Cloud service')

    configurations = parser.add_argument_group("Configurations")
    configurations.add_argument('--no-ai', action='store_true', help="Disable using AI in evaluations")

    output = parser.add_argument_group("Output")
    output.add_argument('--json', action='store_true', help='Output in JSON')
    output.add_argument('--html', action='store_true', help='Output in HTML')

    account = parser.add_argument_group("Account details")
    account.add_argument('--subscription', help='Azure subscription id to scan')

    args = parser.parse_args()

    try:
        module = importlib.import_module(f'havik.{args.provider}.{args.service}')
        func = getattr(module, f'evaluate_{args.service}_security')
    except (ModuleNotFoundError, AttributeError):
        print(f'Unsupported combination: {args.provider}/{args.service}')
        print('Supported services: ')
        print(f'AWS: {",".join(SUPPORTED_SERVICES_AWS)}')
        print(f'Azure: {",".join(SUPPORTED_SERVICES_AZ)}')
        print(f'GCP: {",".join(SUPPORTED_SERVICES_GCP)}')
    else:
        func(noai=args.no_ai, json=args.json, html=args.html)
