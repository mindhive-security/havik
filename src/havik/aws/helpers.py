'''
    Here stored useful functions, called by other modules
'''


def parse_arn(arn: str) -> list:
    '''
        Parses AWS ARN and returns a list of values

        Args: (str) arn - ARN to parse
        Returns: (list) - The list of ARN components
    '''
    return arn.split(':')
