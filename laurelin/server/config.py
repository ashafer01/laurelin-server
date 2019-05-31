import yaml

from .envsubst import envsubst
from .exceptions import *


def resolve_list_env_vars(lst):
    ret = []
    for val in lst:
        ret.append(resolve_env_vars(val))
    return ret


def resolve_dict_env_vars(dct):
    ret = {}
    for key, val in dct.items():
        if isinstance(key, str):
            key = envsubst(key)
        ret[key] = resolve_env_vars(val)
    return ret


def resolve_env_vars(obj):
    if isinstance(obj, str):
        return envsubst(obj)
    elif isinstance(obj, dict):
        return resolve_dict_env_vars(obj)
    elif isinstance(obj, list):
        return resolve_list_env_vars(obj)
    else:
        return obj


def load_config_dict(data, cur_data):
    for key, val in data.items():
        try:
            cur_val = cur_data[key]
            if isinstance(cur_val, dict) and isinstance(val, dict):
                load_config_dict(val, cur_val)
            elif isinstance(cur_val, list) and isinstance(val, list):
                cur_val.extend(resolve_list_env_vars(val))
            else:
                cur_data[key] = resolve_env_vars(val)
        except KeyError:
            cur_data[key] = resolve_env_vars(val)


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

        load_config_dict(data, self)

    def mget(self, *args, default=None):
        dct = self
        for arg in args[:-1]:
            try:
                dct = dct[arg]
            except KeyError:
                return default
        return dct.get(args[-1], default)
