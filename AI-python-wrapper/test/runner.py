#!/usr/bin/env python3

import os
import subprocess
import logging
import argparse

UNIT_TEST_DIR = '/tmp/unit-test/'

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
    test_files = [f for f in os.listdir(test_dir) if f.startswith('test-') and f.endswith('.py')]

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

def main():
    parser = argparse.ArgumentParser(description="Run unit tests with optional debug output.")
    parser.add_argument('--debug', action='store_true', help="Show detailed debug output.")
    args = parser.parse_args()

    os.makedirs(UNIT_TEST_DIR, exist_ok=True)
    setup_logging(debug=args.debug)
    run_tests(debug=args.debug)

if __name__ == "__main__":
    main()
