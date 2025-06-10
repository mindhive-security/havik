def flatten_dict(d: dict, parent_key: str = '', sep: str = '.') -> dict:
    '''
        Recursively flattens a nested dictionary

        Args: (dict) d - dictionary to flatten
              (str) parent_key='' - parent key in nested keys
              (str) separator='.' - separator in nested keys

        Returns: (dict) - flattened dictionary
    '''
    items = []

    for k, v in d.items():
        new_key = f'{parent_key}{sep}{k}' if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))

    return dict(items)
