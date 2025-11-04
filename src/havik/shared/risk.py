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
    This module evaluates the risk based on resource configuration settings.
'''
from datetime import datetime, timezone
from havik.shared import agent

TIME_RISK_MULTIPLIER = 5
LOCATION_RISK_DEFAULT_REGION = 'eu'


def location_risk(location: str) -> int:
    '''
        Calculates risk based on resource location.

        Args: (str) location - resource location
        Returns: (int)
    '''
    weight = 0

    if not location.lower().startswith(LOCATION_RISK_DEFAULT_REGION):
        weight += 10

    return weight


def encryption_risk(encryption_config: dict) -> int:
    '''
        Calculates risk score based on encryption settings.

        Args: (dict) encryption_config - encryption_configuration
    '''
    weight = 0

    tls_config = encryption_config.get('TLS')
    key_location = encryption_config.get('KeyLocation')

    if not tls_config:
        weight += 15

    if key_location:
        weight += location_risk(key_location)

    return weight


def time_risk(creation_date: datetime) -> int:
    '''
        Calculates risk score based on time of live of the resource.

        Args: (datetime) creation_date - the date when the resource was created
    '''
    multiplier = TIME_RISK_MULTIPLIER

    now = datetime.now(timezone.utc)
    created_dt = datetime.fromisoformat(creation_date)

    time_delta = now - created_dt
    time_delta_hours = time_delta.total_seconds() / 3600

    # Set of resource's times of live to increase risk score
    thresholds = [12, 24, 168, 336, 720]

    for i, limit in enumerate(thresholds, start=0):
        if time_delta_hours < limit:
            return i

    return i * multiplier


def access_risk(public_access_config: str, policy_eval: str) -> int:
    '''
        Calculates risk score based on access configuration of the resource.
    '''
    weight = 0

    if public_access_config == 'Allowed':
        weight += 20

    if policy_eval == 'Bad':
        weight += 20

    return weight


def calculate_risk_score(security_config: dict, noai: bool, provider: str, service: str) -> int:
    risk_score = 0
    risk_reason = ''

    risk_score += time_risk(security_config['CreationDate'])
    risk_score += access_risk(security_config['PublicAccess']['Status'],
                              security_config.get('PolicyEval', {}).get('Status', ''))
    risk_score += location_risk(security_config['Location'])
    risk_score += encryption_risk(security_config['Encryption'])

    # TODO: Decide if this is needed at all, it is quite sofisticated evaluation with uncertain value.
    if not noai:
        risk_reason = agent.explain_risk(security_config, risk_score, provider, service)

    return {'Score': risk_score, 'Reason': risk_reason}
