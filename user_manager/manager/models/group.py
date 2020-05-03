from typing import List, Optional

from pydantic import BaseModel


class GroupInList(BaseModel):
    id: str

    group_name: str
    visible: bool


class GroupInRead(BaseModel):
    id: str

    group_name: str
    notes: Optional[str]

    visible: bool

    member_groups: List[str] = []
    members: List[str] = []


class GroupInWrite(BaseModel):
    group_name: str
    notes: Optional[str]

    visible: bool

    member_groups: List[str] = []
    members: List[str] = []


class GroupInCreate(GroupInWrite):
    id: str
