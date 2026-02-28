![f](https://github.com/user-attachments/assets/ecc42996-b9e9-4e85-8b15-395e36dbd117)
A CLI tool designed to identify vulnerabilities in RESTful APIs and their associated configuration files through intelligent fuzz testing.

[Additional Docs](https://x0prc.github.io/notes/Notes/Published-Documentation/FuzzRex)

# Core Features
1. **Dynamic API Fuzzing**:
    - Parse OpenAPI specifications.
    - Generate and send fuzzed requests to API endpoints.
    - Monitor responses for errors or unexpected behaviors.
2. **Configuration File Fuzz Testing**:
    - Support multiple configuration file formats (JSON, YAML, XML).
    - Generate malformed configurations and test application behavior.
    - Log issues and provide recommendations.
3. **Reporting**:
    - Generate comprehensive reports for both API fuzzing and configuration testing.

# Fuzzing Architecture
| [Source](https://www.fuzzingbook.org/html/Fuzzer.html)  |  [Source](https://dfrws.org/wp-content/uploads/2019/06/pres_gaslight_-_a_comprehensive_fuzzing_architecture_for_memory_forensics_frameworks.pdf) |
:-------------------------:|:------------------------------------:
![AB](https://github.com/user-attachments/assets/c7076971-bb2e-4f79-a5b4-6cca615adad4) | ![CD](https://github.com/user-attachments/assets/cefd9cff-4e32-4f1a-ab54-adbd4e0625a2)
- **Input Handling**: Accepts user-specified OpenAPI files and configuration files.
- **Fuzzing Engine**: Responsible for generating fuzzed inputs and sending requests.
- **Monitoring Module**: Captures responses and application behavior.
- **Reporting Module**: Compiles findings into user-friendly reports.

# Motivation
Fuzzers exist in a variety of options and with ton of features. This CLI tool is a simple combination of API Schema and associated Configuration Files Fuzzing as a package for assessing multiple vulnerabilities and thus saving time. Fuzzrex is designed not only as a testing tool but also as a collaborative platform for developers and security professionals.

# Pre-requisites
`pip install requests PyYAML jsonschema`

# Installation
- Create a Virtual Environment
  - `python3 -m venv venv`
  - `source venv/bin/activate`
> [!NOTE]
> For Windows use:
    - `venv\Scripts\activate` 
- Install Required Packages
  `pip install -r requirements.txt`
- Prepare Your OpenAPI Specification
  - Ensure you have an OpenAPI specification file (e.g., openapi.json) that defines your API endpoints. Place this file in an accessible location on your filesystem.
- Run the tool
  `./fuzzrex.sh --api path/to/openapi.json --auth oauth2 --token YOUR_API_TOKEN_HERE`      
