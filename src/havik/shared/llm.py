from json import loads, JSONDecodeError
from os import getenv
from requests import post

LLM_HOST = getenv('LLM_HOST')


def ask_model(prompt):
    response = post(
        f'http://{LLM_HOST}/api/generate',
        json={
            'model': 'mistral',
            'prompt': prompt,
            'stream': False
        }
    )

    output = response.json()['response']

    try:
        return loads(output)
    except JSONDecodeError:
        print('Failed to decode response:')
        print(output)
