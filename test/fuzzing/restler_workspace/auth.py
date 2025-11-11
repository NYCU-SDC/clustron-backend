import requests
import sys

ACCESS_TOKEN = None
API_SERVER = "http://backend:8080"
INTERNAL_LOGIN_URL = f"{API_SERVER}/api/internal/login"

def get_access_token(user_id: str) -> str:
    global ACCESS_TOKEN

    # send request to INTERNAL_LOGIN_URL to get token
    response = requests.post(INTERNAL_LOGIN_URL, json={"user_id": user_id})
    response.raise_for_status()
    data = response.json()

    ACCESS_TOKEN = data["access_token"]
    return ACCESS_TOKEN

if __name__ == "__main__":
    # RESTler passes arguments via command line (sys.argv)
    # The first argument (index 0) is the script name.
    # The second argument (index 1) will be the value passed from engine_setting.
    if len(sys.argv) < 2:
        print("Usage: auth.py <value_for_auth_param>", file=sys.stderr)
        sys.exit(1)

    # 1. Capture the argument passed by RESTler
    auth_param_value = sys.argv[1]

    # 2. Use this value to get the token
    token = get_access_token(auth_param_value)

    # 3. Print the token to stdout as the *only* output. This is what RESTler captures.
    print(f"Bearer {token}")

    # Write the token to a file for debugging purposes
    with open("./token.txt", "w") as f:
        f.write(token)