import sys
from argparse import Namespace
from loguru import logger
from pysd.view.elfview import ElfView


def main(args: Namespace):

    logger.remove()
    logger.add(sys.stderr, level=args.log_level)

    if not args.target.is_file():
        logger.error(f"{args.target} is not a file.")
        return -1
    else:
        logger.debug(f"decompiling {args.target}...")

    view = ElfView.from_file(args.target)

    return 0
