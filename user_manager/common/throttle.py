import asyncio
import ipaddress
from uuid import uuid4

import math
from datetime import datetime, timedelta, timezone
from email.utils import formatdate, format_datetime
from ipaddress import IPv4Address, IPv6Address, IPv6Network
from typing import Union, Optional, Tuple

from starlette.requests import Request

from user_manager.common.config import config
from user_manager.common.models import DbIpLoginThrottle
from user_manager.common.mongo import async_ip_login_throttle_collection

_max_throttle_count = int(
    math.log2(config.oauth2.login_throttler.max_delay / config.oauth2.login_throttler.base_delay) + 1
)


def normalize_ip_address(ip_address: str) -> Optional[str]:
    try:
        ip_address: Union[IPv4Address, IPv6Address, IPv6Network] = ipaddress.ip_address(ip_address)
    except ValueError as e:
        print(f"WARNING: Did not get IPv4/IPv6 from source: {e}, maybe configured incorrectly")
        return None
    if ip_address.is_private and config.oauth2.login_throttler.skip_private:
        return None
    if isinstance(ip_address, IPv6Address):
        masked_ip_net = int(ip_address) & 0xffffffffffffffff0000000000000000
        ip_address = IPv6Network(str(IPv6Address(masked_ip_net)) + '/64')
    return str(ip_address)


async def _async_throttle_delay(ip_address_str: str) -> Tuple[float, Optional[datetime]]:
    if not config.oauth2.login_throttler.enable:
        return 0, None
    ip_address = normalize_ip_address(ip_address_str)
    if ip_address is None:
        return 0, None
    throttle_data = await async_ip_login_throttle_collection.find_one({'_id': ip_address})
    if throttle_data is None:
        return 0, None
    throttle = DbIpLoginThrottle.validate_document(throttle_data)
    next_retry = throttle.next_retry.replace(tzinfo=timezone.utc)
    delay = (next_retry - datetime.utcnow().replace(tzinfo=timezone.utc)).total_seconds()
    if delay > 0:
        print(f"Throttle check from {ip_address_str} (from {ip_address}): {delay}sec at {throttle.next_retry}")
        return delay, next_retry
    return 0, None


async def async_throttle_delay(ip_address_str: str) -> Tuple[Optional[str], Optional[str]]:
    delay, next_retry = await _async_throttle_delay(ip_address_str)
    if delay > 0:
        return str(int(delay + 0.999)), format_datetime(next_retry, usegmt=True)
    return None, None


async def async_throttle(request: Request) -> Tuple[Optional[str], Optional[str]]:
    return await async_throttle_delay(request.client.host)


async def async_throttle_sleep(request: Request):
    delay, _ = await _async_throttle_delay(request.client.host)
    if delay > 0:
        await asyncio.sleep(delay)


async def async_throttle_failure(ip_address_str: str) -> Tuple[str, str]:
    if not config.oauth2.login_throttler.enable:
        return formatdate(usegmt=True), "0"
    ip_address = normalize_ip_address(ip_address_str)
    if ip_address is None:
        return formatdate(usegmt=True), "0"
    throttle_data = await async_ip_login_throttle_collection.find_one({'_id': ip_address})
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    if throttle_data is None:
        delay = config.oauth2.login_throttler.base_delay
        next_retry = now + timedelta(seconds=delay)
        throttle = DbIpLoginThrottle(
            ip=ip_address,
            retries=1,
            last_retry=now,
            next_retry=next_retry,
            forget_time=now + timedelta(seconds=config.oauth2.login_throttler.reset_cutoff),
        )
        await async_ip_login_throttle_collection.insert_one(throttle.document())
    else:
        throttle = DbIpLoginThrottle.validate_document(throttle_data)
        throttle.retries = min(throttle.retries + 1, _max_throttle_count)
        throttle.last_retry = now
        delay = min(
            config.oauth2.login_throttler.base_delay * (2 ** throttle.retries), config.oauth2.login_throttler.max_delay
        )
        next_retry = now + timedelta(seconds=delay)
        throttle.next_retry = next_retry
        throttle.forget_time = now + timedelta(seconds=config.oauth2.login_throttler.reset_cutoff)
        await async_ip_login_throttle_collection.replace_one(
            {'_id': throttle.ip}, throttle.document()
        )
    print(f"Throttling {throttle.ip} (from {ip_address_str}) for {delay}sec until {throttle.next_retry}")
    return format_datetime(next_retry, usegmt=True), str(int(delay + 0.999))


async def async_throttle_failure_request(request: Request) -> Tuple[str, str]:
    return await async_throttle_failure(request.client.host)
