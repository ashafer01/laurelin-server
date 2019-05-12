from laurelin.ldap import rfc4511

from .config import Config
from .exceptions import *

# TODO probly gonna need to dynamically import auth backends
from .simple_auth import SimpleAuthBackend

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
        res_counters = {}
        for entry in self.stack:
            try:
                backend = self.backends[entry['backend']]
                return await backend.authenticate(name, auth_choice)
            except AuthError as e:
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
        if res_counters.get(AuthInvalidCredentials.STACK_KEY, 0) > 0:
            raise InvalidCredentialsError('Provided bind credentials are not valid. '
                                          f'Stack results: {_fmt_res_counters(res_counters)}')
        elif res_counters.get(AuthNameDoesNotExist.STACK_KEY, 0) > 0:
            raise InvalidCredentialsError('Provided bind user does not exist. '
                                          f'Stack results: {_fmt_res_counters(res_counters)}')
        else:
            raise InvalidCredentialsError('Could not complete authentication, '
                                          f'stack results: {_fmt_res_counters(res_counters)}')
