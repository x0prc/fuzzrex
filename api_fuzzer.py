import random
import string

class ApiFuzzer:
    def __init__(self, openapi_file, auth_type=None, token=None):
        self.openapi_file = openapi_file
        self.auth_handler = AuthHandler(auth_type, token)
        self.state_manager = StateManager()
        self.load_openapi()

    def load_openapi(self):
        with open(self.openapi_file, 'r') as file:
            self.openapi_spec = json.load(file)

    def generate_requests(self):
        for path, methods in self.openapi_spec['paths'].items():
            for method, details in methods.items():
                fuzzed_data = self.create_fuzzed_data(details.get('parameters', []))
                yield path, method.upper(), fuzzed_data

    def create_fuzzed_data(self, parameters):
        fuzzed_data = {}
        for param in parameters:
            param_name = param['name']
            param_type = param['schema']['type']

            if param_type == 'string':
                fuzzed_data[param_name] = self.fuzz_string(param)
            elif param_type == 'integer':
                fuzzed_data[param_name] = self.fuzz_integer(param)
            elif param_type == 'boolean':
                fuzzed_data[param_name] = random.choice([True, False])
            elif param_type == 'array':
                fuzzed_data[param_name] = [self.fuzz_string(param['items']) for _ in range(random.randint(1, 5))]
            elif param_type == 'object':
                fuzzed_data[param_name] = self.fuzz_object(param['schema'])

        return fuzzed_data

    def fuzz_string(self, param):
        length = random.randint(1, 100)  
        return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))

    def fuzz_integer(self, param):
        min_value = param.get('minimum', -1000)  
        max_value = param.get('maximum', 1000)   
        return random.randint(min_value - 10, max_value + 10)  

    def fuzz_object(self, schema):
        return {prop: self.create_fuzzed_data([{'name': prop, 'schema': schema['properties'][prop]}])[prop]
                for prop in schema['properties']}

    def run(self):
    for path, method, data in self.generate_requests():
        if 'session_token' in self.state_manager.get_state():
            data['sessionToken'] = self.state_manager.get_state()['session_token']
        
        response = self.send_request(method, path, data)
        if response:
            print(f"Response from {method} {path}: {response.status_code}")
            self.state_manager.update_state(response)


    def send_request(self, method, path, data):
        url = f"http://localhost:5000{path}"
        try:
            response = requests.request(method, url, json=data, headers=self.auth_handler.get_auth_headers())
            return response
        except requests.RequestException as e:
            print(f"Error sending request: {e}")
            return None
