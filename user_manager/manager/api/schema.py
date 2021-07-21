from authlib.oidc.core import UserInfo
from fastapi import APIRouter, Depends, HTTPException
from fastapi.params import Body

from user_manager.common.models import DbManagerSchema
from user_manager.common.mongo import async_read_schema, async_update_schema, async_user_collection
from user_manager.manager.api.user_helpers import apply_property_template
from user_manager.manager.auth import Authentication
from user_manager.manager.helper import DotDict
from user_manager.manager.models import ManagerSchema

router = APIRouter()


@router.get(
    '/schema',
    tags=['User Manager'],
    response_model=ManagerSchema,
    dependencies=[Depends(Authentication())],
)
async def get_schema() -> ManagerSchema:
    """Gets the whole schema."""
    return ManagerSchema.validate(await async_read_schema())


@router.put(
    '/schema',
    tags=['User Manager'],
)
async def update_schema(
    schema: ManagerSchema = Body(...),
    user: UserInfo = Depends(Authentication()),
):
    is_admin = 'admin' in user['roles']
    if not is_admin:
        raise HTTPException(401)
    new_schema = DbManagerSchema.validate_override(schema, id=0)
    existing_schema = await async_read_schema()

    removed_properties = [
        prop for prop in existing_schema.properties_by_key.values()
        if prop.key not in new_schema.properties_by_key
    ]
    for removed_property in removed_properties:
        if removed_property.protected:
            raise HTTPException(400, f"Cannot modify protected property {removed_property.key}")
    for prop in new_schema.properties_by_key.values():
        existing_prop = existing_schema.properties_by_key.get(prop.key)
        if existing_prop is not None and existing_prop.protected and (
                existing_prop.protected != prop.protected or
                existing_prop.type != prop.type or
                existing_prop.values != prop.values or
                existing_prop.write_once != prop.write_once
        ):
            raise HTTPException(400, f"Cannot modify protected property {existing_prop.key}")
    modified_template_props = [
        prop
        for prop in new_schema.properties_by_key.values()
        if prop.template is not None and
        prop.key in existing_schema.properties_by_key and
        existing_schema.properties_by_key[prop.key].template != prop.template and not prop.write_once
    ]
    if removed_properties:
        await async_user_collection.update_many(
            {'$or': [{prop.key: {'$exists': True}} for prop in removed_properties]},
            {'$unset': {prop.key: 1 for prop in removed_properties}},
        )
    if modified_template_props:
        async for user in async_user_collection.find():
            user_data = DotDict(user)
            changed = False
            for prop in modified_template_props:
                new_val = apply_property_template(user_data, prop)
                if new_val != user_data[prop.key]:
                    user_data[prop.key] = new_val
                    changed = True
            if changed:
                await async_user_collection.replace_one({'_id': user_data['_id']}, user_data)
    await async_update_schema(new_schema)
