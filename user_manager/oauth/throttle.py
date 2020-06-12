import asyncio
import ipaddress
import math
from datetime import datetime, timedelta, timezone
from email.utils import formatdate, format_datetime
from ipaddress import IPv4Address, IPv6Address, IPv6Network
from typing import Union, Optional

from starlette.requests import Request

from user_manager.common.config import config
from user_manager.common.models import IpLoginThrottle
from user_manager.common.mongo import async_ip_login_throttle_collection

_max_throttle_count = int(
    math.log2(config.oauth2.login_throttler.max_delay / config.oauth2.login_throttler.base_delay) + 1
)


def normalize_source(request: Request) -> Optional[str]:
    try:
        ip_address: Union[IPv4Address, IPv6Address, IPv6Network] = ipaddress.ip_address(request.client.host)
    except ValueError as e:
        print(f"WARNING: Did not get IPv4/IPv6 from source: {e}, maybe configured incorrectly")
        return None
    if ip_address.is_private and config.oauth2.login_throttler.skip_private:
        return None
    if isinstance(ip_address, IPv6Address):
        masked_ip_net = int(ip_address) & 0xffffffffffffffff0000000000000000
        ip_address = IPv6Network(str(IPv6Address(masked_ip_net)) + '/64')
    return str(ip_address)


async def async_throttle(request: Request):
    if not config.oauth2.login_throttler.enable:
        return
    ip_address = normalize_source(request)
    if ip_address is None:
        return
    throttle_data = await async_ip_login_throttle_collection.find_one({'_id': ip_address})
    if throttle_data is None:
        return 0
    throttle = IpLoginThrottle.validate(throttle_data)
    delay = (throttle.next_retry - datetime.utcnow()).total_seconds()
    if delay > 0:
        print(f"Throttle check from {request.client.host} (from {ip_address}): {delay}sec at {throttle.next_retry}")
        await asyncio.sleep(delay)


async def async_throttle_failure(request: Request) -> str:
    if not config.oauth2.login_throttler.enable:
        return formatdate(usegmt=True)
    ip_address = normalize_source(request)
    if ip_address is None:
        return formatdate(usegmt=True)
    throttle_data = await async_ip_login_throttle_collection.find_one({'_id': ip_address})
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    if throttle_data is None:
        delay = config.oauth2.login_throttler.base_delay
        throttle = IpLoginThrottle(
            ip=request.client.host,
            retries=1,
            last_retry=now,
            next_retry=now + timedelta(seconds=delay),
            forget_time=now + timedelta(seconds=config.oauth2.login_throttler.reset_cutoff),
        )
        await async_ip_login_throttle_collection.insert_one(throttle.dict(exclude_none=True, by_alias=True))
    else:
        throttle = IpLoginThrottle.validate(throttle_data)
        throttle.retries = min(throttle.retries + 1, _max_throttle_count)
        throttle.last_retry = now
        delay = min(
            config.oauth2.login_throttler.base_delay * (2 ** throttle.retries), config.oauth2.login_throttler.max_delay
        )
        throttle.next_retry = now + timedelta(seconds=delay)
        throttle.forget_time = now + timedelta(seconds=config.oauth2.login_throttler.reset_cutoff)
        await async_ip_login_throttle_collection.replace_one(
            {'_id': throttle.ip}, throttle.dict(exclude_none=True, by_alias=True)
        )
    print(f"Throttling {throttle.ip} (from {ip_address}) for {delay}sec until {throttle.next_retry}")

    return format_datetime(throttle.next_retry, usegmt=True)
