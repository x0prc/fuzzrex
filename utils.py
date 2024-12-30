import json
import random
import string

def load_openapi_spec(openapi_file):
    """Load and parse the OpenAPI specification file."""
    try:
        with open(openapi_file, 'r') as file:
            spec = json.load(file)
            return spec
    except FileNotFoundError:
        raise FileNotFoundError(f"OpenAPI specification file '{openapi_file}' not found.")
    except json.JSONDecodeError:
        raise ValueError(f"Error decoding JSON from the OpenAPI specification file '{openapi_file}'.")

def generate_random_string(length=10):
    """Generate a random string of fixed length."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

def generate_random_integer(min_value=-1000, max_value=1000):
    """Generate a random integer within the specified range."""
    return random.randint(min_value, max_value)

def generate_random_boolean():
    """Generate a random boolean value."""
    return random.choice([True, False])

def generate_random_array(item_generator, min_items=1, max_items=5):
    """Generate a random array of items using the provided item generator function."""
    length = random.randint(min_items, max_items)
    return [item_generator() for _ in range(length)]

def generate_fuzzed_data(param):
    """Generate fuzzed data based on parameter definitions."""
    param_type = param['schema']['type']
    
    if param_type == 'string':
        return generate_random_string(random.randint(1, 100))  # Random string length between 1 and 100
    elif param_type == 'integer':
        min_value = param['schema'].get('minimum', -1000)
        max_value = param['schema'].get('maximum', 1000)
        return generate_random_integer(min_value - 10, max_value + 10)  # Fuzzing around limits
    elif param_type == 'boolean':
        return generate_random_boolean()
    elif param_type == 'array':
        item_generator = lambda: generate_fuzzed_data(param['items'])
        return generate_random_array(item_generator)
    elif param_type == 'object':
        return {prop: generate_fuzzed_data({'schema': schema}) for prop, schema in param['schema']['properties'].items()}
    
    # Return None for unsupported types
    return None

