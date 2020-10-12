import re
from typing import Sequence, Optional

from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import Response, PlainTextResponse

ALL_METHODS = ("DELETE", "GET", "OPTIONS", "PATCH", "POST", "PUT")


class CORSHelper:
    def __init__(
        self,
        allow_origins: Sequence[str] = (),
        allow_methods: Sequence[str] = ("GET",),
        allow_headers: Sequence[str] = (),
        allow_credentials: bool = False,
        allow_origin_regex: str = None,
        expose_headers: Sequence[str] = (),
        max_age: int = 600,
    ) -> None:

        if "*" in allow_methods:
            allow_methods = ALL_METHODS

        compiled_allow_origin_regex = None
        if allow_origin_regex is not None:
            compiled_allow_origin_regex = re.compile(allow_origin_regex)

        simple_headers = {}
        if "*" in allow_origins:
            simple_headers["Access-Control-Allow-Origin"] = "*"
        if allow_credentials:
            simple_headers["Access-Control-Allow-Credentials"] = "true"
        if expose_headers:
            simple_headers["Access-Control-Expose-Headers"] = ", ".join(expose_headers)

        preflight_headers = {}
        if "*" in allow_origins:
            preflight_headers["Access-Control-Allow-Origin"] = "*"
        else:
            preflight_headers["Vary"] = "Origin"
        preflight_headers.update(
            {
                "Access-Control-Allow-Methods": ", ".join(allow_methods),
                "Access-Control-Max-Age": str(max_age),
            }
        )
        if allow_headers and "*" not in allow_headers:
            preflight_headers["Access-Control-Allow-Headers"] = ", ".join(allow_headers)
        if allow_credentials:
            preflight_headers["Access-Control-Allow-Credentials"] = "true"

        self.allow_origins = allow_origins
        self.allow_methods = allow_methods
        self.allow_headers = [h.lower() for h in allow_headers]
        self.allow_all_origins = "*" in allow_origins
        self.allow_all_headers = "*" in allow_headers
        self.allow_origin_regex = compiled_allow_origin_regex
        self.simple_headers = simple_headers
        self.preflight_headers = preflight_headers

    def options(self, request: Request) -> Optional[Response]:
        origin = request.headers.get("origin")
        if origin is None:
            return None
        if "access-control-request-method" in request.headers:
            return self._preflight_response(request_headers=request.headers)
        return None

    def augment(self, request: Request, response: Response):
        origin = request.headers.get("origin")
        if origin is None:
            return
        response.headers.update(self.simple_headers)
        origin = request.headers["Origin"]
        has_cookie = "cookie" in request.headers

        # If request includes any cookie headers, then we must respond
        # with the specific origin instead of '*'.
        if self.allow_all_origins and has_cookie:
            response.headers["Access-Control-Allow-Origin"] = origin

        # If we only allow specific origins, then we have to mirror back
        # the Origin header in the response.
        elif not self.allow_all_origins and self._is_allowed_origin(origin=origin):
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers.add_vary_header("Origin")

    def _is_allowed_origin(self, origin: str) -> bool:
        if self.allow_all_origins:
            return True

        if self.allow_origin_regex is not None and self.allow_origin_regex.fullmatch(
            origin
        ):
            return True

        return origin in self.allow_origins

    def _preflight_response(self, request_headers: Headers) -> Response:
        requested_origin = request_headers["origin"]
        requested_method = request_headers["access-control-request-method"]
        requested_headers = request_headers.get("access-control-request-headers")

        headers = dict(self.preflight_headers)
        failures = []

        if self._is_allowed_origin(origin=requested_origin):
            if not self.allow_all_origins:
                # If self.allow_all_origins is True, then the "Access-Control-Allow-Origin"
                # header is already set to "*".
                # If we only allow specific origins, then we have to mirror back
                # the Origin header in the response.
                headers["Access-Control-Allow-Origin"] = requested_origin
        else:
            failures.append("origin")

        if requested_method not in self.allow_methods:
            failures.append("method")

        # If we allow all headers, then we have to mirror back any requested
        # headers in the response.
        if self.allow_all_headers and requested_headers is not None:
            headers["Access-Control-Allow-Headers"] = requested_headers
        elif requested_headers is not None:
            for header in [h.lower() for h in requested_headers.split(",")]:
                if header.strip() not in self.allow_headers:
                    failures.append("headers")

        # We don't strictly need to use 400 responses here, since its up to
        # the browser to enforce the CORS policy, but its more informative
        # if we do.
        if failures:
            failure_text = "Disallowed CORS " + ", ".join(failures)
            return PlainTextResponse(failure_text, status_code=400, headers=headers)

        return PlainTextResponse("OK", status_code=200, headers=headers)


allow_all_get_cors = CORSHelper(
    allow_origins='*',
    allow_methods=('GET',),
    allow_headers=('authorization',),
    allow_credentials=True,
)
allow_all_get_post_cors = CORSHelper(
    allow_origins='*',
    allow_methods=('GET', 'POST'),
    allow_headers=('authorization',),
    allow_credentials=True,
)
allow_all_post_cors = CORSHelper(
    allow_origins='*',
    allow_methods=('POST',),
    allow_headers=('authorization',),
    allow_credentials=True,
)
allow_all_get_head_cors = CORSHelper(
    allow_origins='*',
    allow_methods=('GET', 'HEAD'),
)
