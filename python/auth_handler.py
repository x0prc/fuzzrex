import requests
import json

class AuthHandler:
    def __init__(self, auth_type=None, token=None):
        self.auth_type = auth_type
        self.token = token
        self.oauth2_credentials = {
            'client_id': 'YOUR_CLIENT_ID',
            'client_secret': 'YOUR_CLIENT_SECRET',
            'token_url': '',  # Replace with actual token URL
            'scope': 'YOUR_SCOPE'  # Optional: specify scopes if required
        }

    def get_auth_headers(self):
        headers = {}
        if self.auth_type == 'token' and self.token:
            headers['Authorization'] = f'Bearer {self.token}'
        elif self.auth_type == 'oauth2':
            self.token = self.retrieve_oauth2_token()
            headers['Authorization'] = f'Bearer {self.token}'
        return headers

    def retrieve_oauth2_token(self):
        try:
            response = requests.post(self.oauth2_credentials['token_url'], data={
                'grant_type': 'client_credentials',  # Change as needed (e.g., authorization_code)
                'client_id': self.oauth2_credentials['client_id'],
                'client_secret': self.oauth2_credentials['client_secret'],
                'scope': self.oauth2_credentials.get('scope', '')
            })

            if response.status_code == 200:
                token_info = response.json()
                return token_info.get('access_token')
            else:
                print(f"Failed to retrieve OAuth2 token: {response.status_code} {response.text}")
                return None

        except requests.RequestException as e:
            print(f"Error during OAuth2 token retrieval: {e}")
            return None
