import asyncio
import sys
import os
from .base import run_config_file


async def main():
    try:
        conf_fn = sys.argv[1]
    except IndexError:
        try:
            conf_fn = os.environ['LAURELIN_SERVER_CONFIG']
        except KeyError:
            sys.stderr.write('Could not find a config filename - pass as $1 or $LAURELIN_SERVER_CONFIG\n')
            sys.exit(1)
    await run_config_file(conf_fn)


asyncio.run(main(), debug=True)
