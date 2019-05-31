import re
import os
import yaml

from .exceptions import *


def _repl_simple_env_var(m):
    var_name = m.group(1)
    return os.environ.get(var_name, '')


def _repl_extended_env_var(m):
    var_name = m.group(1)
    default_spec = m.group(2)
    if default_spec:
        default = m.group(4)
        if m.group(3) == ':-':
            # use default if var is unset or empty
            env_var = os.environ.get(var_name)
            if env_var:
                return env_var
            else:
                return default
        elif m.group(3) == '-':
            # use default if var is unset
            return os.environ.get(var_name, default)
        else:
            raise RuntimeError('unexpected string matched regex')
    else:
        return os.environ.get(var_name, '')


def sub_env_vars(string):
    """
    Substitue environment variables in the given string

    The following forms are supported:

    Simple variables - will use an empty string if the variable is unset
      $FOO

    Bracketed expressions
      ${FOO}
        identical to $FOO
      ${FOO:-somestring}
        uses "somestring" if $FOO is unset, or set and empty
      ${FOO-somestring}
        uses "somestring" only if $FOO is unset

    :param str string: A string possibly containing environment variables
    :return: The string with environment variable specs replaced with their values
    """
    # handle simple un-bracketed env vars like $FOO
    a = re.sub(r'(?<!\\)\$([A-Za-z0-9_]+)', _repl_simple_env_var, string)

    # handle bracketed env vars with optional default specification
    b = re.sub(r'(?<!\\)\$\{([A-Za-z0-9_]+)((:?-)([^}]+))?\}', _repl_extended_env_var, a)
    return b


def resolve_list_env_vars(lst):
    ret = []
    for val in lst:
        if isinstance(val, str):
            ret.append(sub_env_vars(val))
        elif isinstance(val, dict):
            ret.append(resolve_dict_env_vars(val))
        elif isinstance(val, list):
            ret.append(resolve_list_env_vars(val))
        else:
            ret.append(val)
    return ret


def resolve_dict_env_vars(dct):
    ret = {}
    for key, val in dct.items():
        if isinstance(key, str):
            key = sub_env_vars(key)
        if isinstance(val, str):
            ret[key] = sub_env_vars(val)
        elif isinstance(val, dict):
            ret[key] = resolve_dict_env_vars(val)
        elif isinstance(val, list):
            ret[key] = resolve_list_env_vars(val)
        else:
            ret[key] = val
    return ret


def resolve_env_vars(obj):
    if isinstance(obj, str):
        return sub_env_vars(obj)
    elif isinstance(obj, dict):
        return resolve_dict_env_vars(obj)
    elif isinstance(obj, list):
        return resolve_list_env_vars(obj)
    else:
        return obj


class Config(dict):
    def load_file(self, fn):
        with open(fn) as f:
            self.load_stream(f)

    def load_stream(self, f):
        data = yaml.safe_load(f)
        self.load_dict(data)

    def load_dict(self, data):
        if not isinstance(data, dict):
            raise ConfigError('Config must be dict')

        self._load_dict(data, self)

    def _load_dict(self, data, cur_data):
        for key, val in data.items():
            try:
                cur_val = cur_data[key]
                if isinstance(cur_val, dict) and isinstance(val, dict):
                    self._load_dict(val, cur_val)
                elif isinstance(cur_val, list) and isinstance(val, list):
                    cur_val.extend(resolve_list_env_vars(val))
                else:
                    cur_data[key] = resolve_env_vars(val)
            except KeyError:
                cur_data[key] = resolve_env_vars(val)

    def mget(self, *args, default=None):
        dct = self
        for arg in args[:-1]:
            try:
                dct = dct[arg]
            except KeyError:
                return default
        return dct.get(args[-1], default)
