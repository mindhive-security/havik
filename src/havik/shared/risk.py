'''
    This module evaluates the risk based on resource configuration settings.
'''
from datetime import datetime, timezone


def time_risk(creation_date: datetime) -> int:
    '''
        Calculates risk score based on time of live of the resource.

        Args: (str) creation_date - the date when the resource was created
    '''
    weight = 0

    now = datetime.now(timezone.utc)

    time_delta = now - creation_date
    time_delta_hours = time_delta.total_seconds() / 3600

    if time_delta_hours >= 12:
        weight += 5
    elif time_delta_hours >= 24:
        weight += 10
    elif time_delta_hours >= 168:
        weight += 15
    elif time_delta_hours >= 720:
        weight += 20
    
    return weight


def calculate_risk_score(creation_date: datetime) -> int:
    risk_score = 0
    
    risk_score += time_risk(creation_date)

    return risk_score
