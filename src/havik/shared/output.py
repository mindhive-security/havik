from json import dumps
from rich.console import Console
from rich.table import Table

from .helpers import flatten_dict


def output_json(config: dict) -> None:
    '''
        Outputs the result in JSON

        Args: (dict) config - Configuration of resource

        Returns: prints output to stdout
    '''
    print(dumps(config))


def output_table(config: dict, title: str) -> None:
    '''
        Outputs the result in CLI rich Table

        Args: (dict) config - Configuration of resource
              (str) title - Table title

        Returns: prints output to stdout
    '''
    table = Table(title=title)

    flattened = [flatten_dict(item) for item in config.values()]

    # Special treatment for PolicyReason - should not be visible in the table
    # The key should always be the same for AI evaluated policies
    columns = sorted({key for d in flattened for key in d.keys() if key != 'PolicyEval.PolicyReason'})

    for col in columns:
        table.add_column(col, header_style='cyan', justify='center')

    for row in flattened:
        table.add_row(*(str(row.get(col, '')) for col in columns))

    console = Console()
    console.print(table)
