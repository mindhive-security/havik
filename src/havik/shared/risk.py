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

    time_delta = now - creation_date
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
    risk_score += access_risk(bucket_security['PublicAccess']['Status'], bucket_security.get('PolicyEval', '')['Status'])

    return risk_score
