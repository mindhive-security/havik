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

TIME_RISK_MULTIPLIER = 5


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

    for i, limit in enumerate(thresholds, start = 0):
        if time_delta_hours < limit:
            return i
        
    return i * multiplier


def access_risk(public_access_config: str, policy_eval: str) -> int:
    '''
        Calculates risk score based on access configuration of the resource.
    '''
    weight = 0

    if public_access_config == 'Allowed':
        weight += 50

    if policy_eval == 'Bad':
        weight += 20

    return weight


def calculate_risk_score(bucket_security: dict) -> int:
    risk_score = 0

    creation_date = bucket_security['CreationDate']
    
    risk_score += time_risk(creation_date)
    risk_score += access_risk(bucket_security['PublicAccess']['Status'], bucket_security.get('PolicyEval', {}).get('Status', ''))

    return risk_score
