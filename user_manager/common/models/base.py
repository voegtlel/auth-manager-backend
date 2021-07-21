from datetime import datetime, date
from enum import Enum
from typing import List, Any, Sequence, Mapping, TypeVar, Type, get_origin, Union
from uuid import UUID

from pydantic import BaseModel, Extra
from pymongo import IndexModel


def _safe_document(doc: Any):
    if doc is None:
        return doc
    if isinstance(doc, Enum):
        return doc.value
    if isinstance(doc, (str, int, float, bool, UUID, datetime)):
        return doc
    if isinstance(doc, Mapping):
        return {k: _safe_document(v) for k, v in doc.items()}
    if isinstance(doc, Sequence):
        return [_safe_document(x) for x in doc]
    if isinstance(doc, date):
        return doc.toordinal()
    raise ValueError(f"Invalid document: {doc}")


def _validate_document(doc: Any, type_: type) -> Any:
    if doc is None:
        return doc
    org = get_origin(type_)
    if isinstance(type_, type) and issubclass(type_, BaseSubDocument):
        allow_extra = type_.__config__.extra == Extra.allow
        if allow_extra:
            aliases = set(field.alias for field in type_.__fields__.values() if field.has_alias)
        else:
            aliases = set()
        assert isinstance(doc, dict)
        return {
            **{
                key: _validate_document(doc.get(field.alias, doc.get(key)) if field.has_alias else doc.get(key), field.outer_type_)
                for key, field in type_.__fields__.items()
                if (field.has_alias and field.alias in doc) or key in doc
            }, **({
                key: _validate_document(value, type(value))
                for key, value in doc.items()
                if key not in type_.__fields__ and key not in aliases
            } if allow_extra else {})
        }
    elif org is not None and issubclass(org, list):
        assert isinstance(doc, list)
        t_inner = getattr(type_, '__args__', ())[0]
        return [_validate_document(value, t_inner) for value in doc]
    elif org is not None and issubclass(org, dict):
        assert isinstance(doc, dict)
        t_k_inner = getattr(type_, '__args__', ())[0]
        t_v_inner = getattr(type_, '__args__', ())[1]
        return {_validate_document(k, t_k_inner): _validate_document(v, t_v_inner) for k, v in doc.items()}
    elif isinstance(type_, type) and issubclass(type_, date) and isinstance(doc, (int, float)):
        return date.fromordinal(int(doc))
    return doc


TDocument = TypeVar('TDocument', bound='BaseSubDocument')


class BaseSubDocument(BaseModel):
    class Config:
        allow_population_by_field_name = True
        validate_assignment = True


class BaseDocument(BaseSubDocument):
    __indexes__: List[IndexModel] = []
    __collection_name__: str

    def document(self):
        return _safe_document(self.dict(exclude_none=True, by_alias=True))

    @classmethod
    def validate_override(cls: Type[TDocument], data: Union[dict, BaseModel], **overrides) -> TDocument:
        if isinstance(data, BaseModel):
            data = data.dict(exclude=set(overrides.keys()))
        assert isinstance(data, dict)
        data.update(overrides)
        if 'id' in data:
            data['_id'] = data.pop('id')
        return cls.validate(_validate_document(data, cls))

    @classmethod
    def validate_document(cls: Type[TDocument], doc: Union[dict, BaseModel]) -> TDocument:
        if isinstance(doc, BaseModel):
            doc = doc.dict(exclude_none=True)
            if 'id' in doc:
                doc['_id'] = doc.pop('id')
        assert isinstance(doc, dict)
        return cls.validate(_validate_document(doc, cls))

    def update_from(self, src_doc):
        if isinstance(src_doc, BaseModel):
            for key in src_doc.__fields__.keys():
                if key in self.__fields__:
                    setattr(self, key, getattr(src_doc, key))
        else:
            assert False
