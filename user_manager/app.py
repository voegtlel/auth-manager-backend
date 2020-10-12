from user_manager.manager.app import app as manager_app
from user_manager.oauth.app import app

app.mount('/api/v1/manager', manager_app)


def print_routes(container, prefix=''):
    if hasattr(container, 'routes'):
        for route in getattr(container, 'routes'):
            print_routes(route, prefix + getattr(container, 'path', ''))
    elif hasattr(container, 'path'):
        print(
            f"Route {', '.join(getattr(container, 'methods', None))} {prefix}{getattr(container, 'path', None)}: "
            f"{getattr(container, 'name', None)}"
        )
    else:
        print(f"Route {repr(container)}")


print_routes(app)
