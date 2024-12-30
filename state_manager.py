class StateManager:
    def __init__(self):
        self.state = {}
        self.last_response = None

    def update_state(self, response):
        self.last_response = response.json() if response.status_code == 200 else None
        
        if response.status_code == 200:
            if 'userId' in self.last_response:
                self.state['current_user_id'] = self.last_response['userId']
            if 'sessionToken' in self.last_response:
                self.state['session_token'] = self.last_response['sessionToken']
        
        print(f"Updated state with response: {self.last_response}")

    def get_state(self):
        return self.state
