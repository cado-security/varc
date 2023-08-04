import argparse
import logging

from varc_core.systems import acquire_system

if __name__ == "__main__":
    logging_level = logging.INFO
    logging.basicConfig(
        format='[%(asctime)s]:[%(levelname)s] - %(message)s',
        handlers=[
            logging.FileHandler("varc.log"),
            logging.StreamHandler()
        ],
        level=logging_level
    )

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--skip-memory",
        action="store_false",
        dest="include_memory",
        help="Skip collecting process memory, which can be slow",
    )
    parser.add_argument(
        "--skip-open",
        action="store_false",
        dest="include_open",
        help="Skip collecting open files, which can be slow",
    )
    parser.add_argument(
        "--dump-extract",
        action="store_true",
        dest="extract_dumps",
        help="Extract process memory dumps, which can be slow",
    )
    parser.add_argument(
        "--yara-scan",
        action="store",
        dest="yara_scan",
        help="Scan process memory using compiled YARA rule file, which can be slow.",
    )
    # Allow other arguments - needed for unittests
    parser.add_argument('args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    acquire_system(
        include_memory=args.include_memory,
        include_open=args.include_open,
        extract_dumps=args.extract_dumps,
        yara_file=args.yara_scan
    )
