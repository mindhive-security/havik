'''
    Map cloud configuration checks to regulation standards.
'''
from json import load


def ccm_map(provider: str, service: str, checks: list):
    '''
        Maps service checks to CSA Cloud Control Matrix controls
    '''
    with open('src/havik/shared/files/control_map.json', 'r') as map_file:
        mapping = load(map_file)
        controls = mapping[provider][service]

    return controls
