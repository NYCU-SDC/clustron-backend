# python
# RESTler authentication settings documentation:
#   https://github.com/microsoft/restler-fuzzer/blob/main/docs/user-guide/Authentication.md
#   https://github.com/microsoft/restler-fuzzer/blob/main/docs/user-guide/SettingsFile.md
import requests
import sys
import os

ACCESS_TOKEN = None
API_SERVER = os.getenv("API_SERVER", "http://backend:8080")
INTERNAL_LOGIN_URL = f"{API_SERVER}/api/internal/login"

def debug(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)
    with open("./auth.log", "a") as f:
        print(*args, file=f, **kwargs)

def get_access_token(user_id: str) -> str:
    global ACCESS_TOKEN
#     debug("auth.py: get_access_token called with user_id =", user_id)
#     debug("auth.py: INTERNAL_LOGIN_URL =", INTERNAL_LOGIN_URL)
    try:
        response = requests.post(INTERNAL_LOGIN_URL, json={"user_id": user_id}, timeout=10)
#         debug("auth.py: HTTP status code =", response.status_code)
        response.raise_for_status()
        data = response.json()
        token = data.get("access_token")
        if not token:
            raise ValueError("no access_token in response JSON")
        ACCESS_TOKEN = token
        return ACCESS_TOKEN
    except Exception:
#         debug("auth.py: exception while obtaining token:")
        raise

if __name__ == "__main__":
#     debug("auth.py invoked, argv =", sys.argv)
    if len(sys.argv) < 2:
        print("Usage: auth.py <value_for_auth_param>", file=sys.stderr)
        sys.exit(1)

    auth_param_value = sys.argv[1]
    try:
        token = get_access_token(auth_param_value)
    except Exception:
        # ensure non-zero exit so caller can detect failure
        sys.exit(2)

    print("{u'api': {}}")
    print(f"Authorization: Bearer {token}")

    # debug artifact for local investigation (written to file, not stdout)
    try:
        with open("./token.txt", "w") as f:
            f.write(token)
    except Exception:
        debug("auth.py: failed to write token.txt")
        traceback.print_exc(file=sys.stderr)
