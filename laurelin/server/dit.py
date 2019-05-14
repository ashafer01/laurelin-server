from .backend import DataBackend
from .config import Config
from .dn import parse_dn
from .exceptions import *

# TODO probly gonna need to dynamically import backends
from .memory_backend import MemoryBackend

_backend_types = {
    'memory': MemoryBackend,
}


class DIT(dict):
    def __init__(self, dit_conf):
        for suffix, node_conf in dit_conf.items():
            self[parse_dn(suffix)] = _backend_types[node_conf['data_backend']](suffix, Config(node_conf))

        # sorted list of DIT suffixes - most RDNs first, otherwise order does not matter
        self.suffixes = list(self.keys())
        self.suffixes.sort(key=lambda s: len(s), reverse=True)

    def backend(self, dn) -> (DataBackend, None):
        """Obtain the backend for a given DN"""
        if dn == '':
            return
        dn = parse_dn(dn)
        for suffix in self.suffixes:
            if dn[-len(suffix):] == suffix:
                return self[suffix]
        raise NoSuchObjectError(f'Could not find a backend to handle the DN {dn}')
