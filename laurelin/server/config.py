import yaml

from .exceptions import *


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
                if isinstance(cur_val, dict):
                    self._load_dict(val, cur_val)
                elif isinstance(cur_val, list):
                    if not isinstance(val, list):
                        raise ConfigError('Must be list')
                    cur_val.extend(val)
                else:
                    cur_data[key] = val
            except KeyError:
                cur_data[key] = val

    def mget(self, *args, default=None):
        dct = self
        for arg in args[:-1]:
            try:
                dct = dct[arg]
            except KeyError:
                return default
        return dct.get(args[-1], default)
