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

from json import dumps
from rich.console import Console
from rich.table import Table

from .helpers import flatten_dict

from havik.shared import llm


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

    # Special treatment for PolicyEval.Reason and Risk.Reason -
    # should not be visible in the table.
    # The key should always be the same for AI evaluated policies
    columns = sorted({key for d in flattened for key in d.keys(
    ) if key != 'PolicyEval.Reason' and key != 'Risk.Reason'})

    for col in columns:
        table.add_column(col, header_style='cyan', justify='center')

    for row in flattened:
        table.add_row(*(str(row.get(col, '')) for col in columns))

    console = Console()
    console.print(table)
