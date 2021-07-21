from pydantic import BaseModel


class GroupMailInList(BaseModel):
    id: str
    group_id: str
    from_address: str
