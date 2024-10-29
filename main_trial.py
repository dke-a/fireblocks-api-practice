from dotenv import load_dotenv
import os
import jwt
import requests
import time
import uuid
import hashlib 
from urllib.parse import urlencode

load_dotenv()
base_path = os.getenv("FIREBLOCKS_BASE_PATH")
api_key = os.getenv("FIREBLOCKS_API_KEY")
secret_key_path = os.getenv("FIREBLOCKS_SECRET_KEY_PATH")
with open(secret_key_path, 'r') as key_file:
    secret_key = key_file.read()

def generate_jwt(api_key, secret_key, uri, query_params=None, body=""):
    # JWT header
    headers = {
        "alg": "RS256",
        "typ": "JWT"
    }

    # Calculate the current timestamp and expiration time
    iat = int(time.time())
    exp = iat + 30  # JWT expiration (within 30 seconds)
    nonce = str(uuid.uuid4())  # Generate a unique nonce

    # Create a SHA-256 hash of the request body
    body_hash = hashlib.sha256(body.encode()).hexdigest()

    # Construct full URI path including query parameters
    full_uri = uri
    if query_params:
        # Remove None values and convert to query string
        filtered_params = {k: v for k, v in query_params.items() if v is not None}
        if filtered_params:
            query_string = urlencode(filtered_params)
            full_uri = f"{uri}?{query_string}"
            

    # Create the JWT payload
    payload = {
        "uri": full_uri,
        "nonce": nonce,
        "iat": iat,
        "exp": exp,
        "sub": api_key,
        "bodyHash": body_hash
    }

    # Encode the token using the RS256 algorithm
    token = jwt.encode(payload, secret_key, algorithm="RS256", headers=headers)
    return token

def get_vault_accounts_paged(name_prefix=None, name_suffix=None, min_amount_threshold=None,
                           asset_id=None, order_by="DESC", before=None, after=None, limit=200):
    # Endpoint URI for vault accounts (paginated)
    uri = "/v1/vault/accounts_paged"
    url = base_path + uri.replace('/v1', '')  # Remove /v1 from final URL since it's in base_path
    print(url)
    # Define query parameters
    params = {
        "namePrefix": name_prefix,
        "nameSuffix": name_suffix,
        "minAmountThreshold": min_amount_threshold,
        "assetId": asset_id,
        "orderBy": order_by,
        "before": before,
        "after": after,
        "limit": limit
    }
    
    # Generate JWT for the request with query parameters
    jwt_token = generate_jwt(api_key, secret_key, uri, query_params=params)
    
    # Set headers with JWT and API Key
    headers = {
        "Authorization": f"Bearer {jwt_token}",
        "X-API-Key": api_key
    }
    
    # Remove None values from params
    params = {k: v for k, v in params.items() if v is not None}
    
    # Send the GET request
    response = requests.get(url, headers=headers, params=params)
    
    # Handle the response
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: {response.status_code}")
        print(response.json())
        return None

# Example usage
vault_accounts = get_vault_accounts_paged(name_prefix="Test", limit=50)
print(vault_accounts)