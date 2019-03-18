import asyncio
import sys
import os
import logging
from .base import run_config


async def main():
    logger = logging.getLogger('laurelin.server')
    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)

    try:
        conf_fn = sys.argv[1]
    except IndexError:
        try:
            conf_fn = os.environ['LAURELIN_SERVER_CONFIG']
        except KeyError:
            sys.stderr.write('Could not find a config filename - pass as $1 or $LAURELIN_SERVER_CONFIG\n')
            sys.exit(1)
    logger.debug(f'Running config {conf_fn}')
    await run_config(conf_fn)


asyncio.run(main(), debug=True)
