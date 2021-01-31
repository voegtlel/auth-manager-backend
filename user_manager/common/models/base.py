from typing import List

from pydantic import BaseModel
from pymongo import IndexModel


class BaseSubDocument(BaseModel):
    class Config:
        allow_population_by_field_name = True
        validate_assignment = True


class BaseDocument(BaseSubDocument):
    __indexes__: List[IndexModel] = []
    __collection_name__: str

    def update_from(self, src_doc):
        if isinstance(src_doc, BaseModel):
            for key in src_doc.__fields__.keys():
                if key in self.__fields__:
                    setattr(self, key, getattr(src_doc, key))
