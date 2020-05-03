import re
from functools import lru_cache
from typing import Optional, Any, Mapping, Sequence

import regex


class DotDict(dict):

    def __init__(self, initial: dict = None):
        super().__init__()
        if initial is not None:
            for key, value in initial.items():
                if '.' in key:
                    self[key] = value
                else:
                    super().__setitem__(key, value)

    @staticmethod
    def from_obj(initial: Optional[dict]) -> Optional['DotDict']:
        if initial is None:
            return None
        return DotDict(initial)

    def __getitem__(self, key: str):
        if '.' in key:
            key, next_key = key.split('.', 1)
            return super().__getitem__(key)[next_key]
        return super().__getitem__(key)

    def __setitem__(self, key: str, value):
        if '.' in key:
            key, next_key = key.split('.', 1)
            if key not in self:
                super().__setitem__(key, DotDict())
            super().__getitem__(key)[next_key] = value
        else:
            super().__setitem__(key, value)

    def __setattr__(self, key: str, value):
        self[key] = value

    def __getattr__(self, key: str):
        return self[key]

    def __contains__(self, key: str) -> bool:
        if '.' in key:
            key, next_key = key.split('.', 1)
            if super().__contains__(key):
                return next_key in super().__getitem__(key)
            return False
        else:
            return super().__contains__(key)

    def setdefault(self, __key: str, __default=...):
        if '.' in __key:
            __key, next_key = __key.split('.', 1)
            if __key not in self:
                super().__setitem__(__key, DotDict())
            return super().__getitem__(__key).setdefault(next_key, __default)
        else:
            return super().setdefault(__key, __default)

    def get(self, k: str, default=None):
        if '.' in k:
            k, next_key = k.split('.', 1)
            if k in self:
                return super().__getitem__(k).get(next_key, default)
        else:
            return super().get(k, default)

    def pop(self, k: str):
        if '.' in k:
            raise ValueError(f"Cannot pop from sub dict {k}")
        else:
            return super().pop(k)

    def update(self, __m=..., **kwargs: Any):
        if __m is not ...:
            if isinstance(__m, Mapping):
                for key, value in __m.items():
                    self.setdefault(key, value)
            elif isinstance(__m, Sequence):
                for key, value in __m:
                    self.setdefault(key, value)
        for key, value in kwargs.items():
            self.setdefault(key, value)


@lru_cache
def get_regex(expr: str) -> re.Pattern:
    return regex.compile(expr, regex.V1 | regex.UNICODE)