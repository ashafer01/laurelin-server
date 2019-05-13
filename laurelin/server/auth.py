import logging

from laurelin.ldap import rfc4511

from .config import Config
from .exceptions import *

# TODO probly gonna need to dynamically import auth backends
from .simple_auth import SimpleAuthBackend

logger = logging.getLogger(__name__)

_backend_types = {
    'simple': SimpleAuthBackend,
}


def _fmt_res_counters(res_counters):
    strs = []
    for key, val in res_counters.items():
        strs.append(f'{key}={val}')
    return ', '.join(strs)


class AuthStack(object):
    def __init__(self, stack_conf, backend_conf, dit):
        self.stack = stack_conf

        self.backends = {}
        for name, auth_conf in backend_conf.items():
            self.backends[name] = _backend_types[auth_conf['type']](Config(auth_conf), dit)

    async def authenticate(self, name: str, auth_choice: rfc4511.AuthenticationChoice):
        logger.info(f'{name} trying to authenticate')
        res_counters = {}
        for entry in self.stack:
            try:
                backend = self.backends[entry['backend']]
                authed_name = await backend.authenticate(name, auth_choice)
                logger.info(f'{name} successfully authenticated as {authed_name} with auth_backend {entry["backend"]}')
                return authed_name
            except AuthError as e:
                logger.debug(f'{name} failed to authenticate with backend {entry["backend"]}: '
                             f'{e.__class__.__name__}: {e}')
                error_action = entry.get(e.STACK_KEY, e.DEFAULT_ACTION)
                res_counters.setdefault(e.STACK_KEY, 0)
                res_counters[e.STACK_KEY] += 1
                if error_action == 'break':
                    break
                elif error_action == 'continue':
                    continue
                elif error_action is None:
                    raise InternalError('Base exception AuthError was raised')
                else:
                    raise ConfigError('Unknown auth stack action, must be break/continue')
            except KeyError:
                raise ConfigError(f'auth_stack backend {entry["backend"]} does not exist')

        # no auth_backend could authenticate the user with the provided credentials
        res_counter_str = _fmt_res_counters(res_counters)
        logger.info(f'{name} failed to authenticate. Stack results: {res_counter_str}')
        if res_counters.get(AuthInvalidCredentials.STACK_KEY, 0) > 0:
            raise InvalidCredentialsError(f'Provided bind credentials are not valid. Stack results: {res_counter_str}')
        elif res_counters.get(AuthNameDoesNotExist.STACK_KEY, 0) > 0:
            raise InvalidCredentialsError(f'Provided bind user does not exist. Stack results: {res_counter_str}')
        else:
            raise InvalidCredentialsError(f'Could not complete authentication, stack results: {res_counter_str}')
