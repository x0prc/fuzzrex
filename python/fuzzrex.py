import argparse
from api_fuzzer import ApiFuzzer
from config_fuzzer import ConfigFuzzer

def main():
    parser = argparse.ArgumentParser(description='Fuzzrex')
    parser.add_argument('--api', help='Path to OpenAPI specification file', required=False)
    parser.add_argument('--config', help='Path to configuration file', required=False)

    args = parser.parse_args()

    if args.api:
        fuzzer = ApiFuzzer(args.api)
        fuzzer.run()

    if args.config:
        fuzzer = ConfigFuzzer(args.config)
        fuzzer.run()

if __name__ == '__main__':
    main()
