from pathlib import Path
from argparse import ArgumentParser
from pysd.main import main

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("target", type=Path)
    parser.add_argument("--log-level", choices=["TRACE", "DEBUG", "INFO", "SUCCESS", "WARNING", "ERROR", "CRITICAL"], default="INFO")
    args = parser.parse_args()
    ec = main(args)
    exit(ec)