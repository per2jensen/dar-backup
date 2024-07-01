#!/usr/bin/env python3

import os
import subprocess
import logging
import argparse
import sys

UNIT_TEST_DIR = '/tmp/unit-test/'
VERSION = "0.1"

def setup_logging(debug=False):
    log_file = os.path.join(UNIT_TEST_DIR, 'test_runner.log')
    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG if debug else logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if debug else logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger().addHandler(console)
    logging.info(f"Logging to {log_file}")

def run_tests(debug=False):
    test_dir = os.path.dirname(__file__)
    test_files = [f for f in os.listdir(os.path.join(test_dir)) if f.startswith('test-') and f.endswith('.py')]

    for test_file in test_files:
        test_path = os.path.join(test_dir, test_file)
        if debug:
            logging.info(f"Running test: {test_file}")
        result = subprocess.run(['python3', test_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if debug:
            logging.info(f"STDOUT:\n{result.stdout}")
            logging.info(f"STDERR:\n{result.stderr}")
        
        if result.returncode != 0:
            logging.error(f"Test {test_file} failed with return code {result.returncode}")
        else:
            logging.info(f"Test {test_file} passed successfully")

def show_version():
    script_name = os.path.basename(sys.argv[0])
    print(f"{script_name} {VERSION}")
    print('''Licensed under GNU GENERAL PUBLIC LICENSE v3, see the supplied file "LICENSE" for details.
THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW, not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See section 15 and section 16 in the supplied "LICENSE" file.''')

def main():
    parser = argparse.ArgumentParser(description="Run unit tests with optional debug output.")
    parser.add_argument('--debug', action='store_true', help="Show detailed debug output.")
    parser.add_argument('--version', '-v', action='store_true', help="Show version information.")
    args = parser.parse_args()

    if args.version:
        show_version()
        sys.exit(0)

    os.makedirs(UNIT_TEST_DIR, exist_ok=True)
    setup_logging(debug=args.debug)
    run_tests(debug=args.debug)

if __name__ == "__main__":
    main()

