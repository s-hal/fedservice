import logging
from collections.abc import Mapping
from time import time
from typing import Any
from typing import Optional

from idpyoidc.impexp import ImpExp

logger = logging.getLogger(__name__)


class ESCache(ImpExp):
    parameter = {
        "_db": {},
        "allowed_delta": 0
    }

    def __init__(self, allowed_delta=300):
        ImpExp.__init__(self)
        self._db = {}
        self.allowed_delta = allowed_delta

    def __setitem__(self, key, value):
        self._db[key] = value

    def __getitem__(self, item):
        try:
            statement = self._db[item]
        except KeyError:
            return None
        else:
            if isinstance(statement, Mapping):
                # Early refresh belongs to the collector, not to cache reads.
                if time() < statement["exp"]:
                    return statement
                else:
                    del self._db[item]
                    return None
            else:
                return statement

    def __delitem__(self, key):
        del self._db[key]

    def keys(self):
        return self._db.keys()

    def __len__(self):
        return len(self._db)

    def __contains__(self, item):
        return item in self._db

    def get(self, key, default: Optional[Any] = None):
        statement = self[key]
        return default if statement is None and key not in self else statement
