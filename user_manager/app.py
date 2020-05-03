from user_manager.manager.app import app as manager_app
from user_manager.oauth.app import app

app.mount('/api/v1/manager', manager_app)

for route in app.routes:
    print(f"Route {getattr(route, 'methods', None)} {getattr(route, 'path', None)}: {getattr(route, 'name', None)}")
