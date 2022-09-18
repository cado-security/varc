"""This file carves out binary and log data from systems, heavily based on RipRaw
"""
import string
import os
import os.path
import shutil
from datetime import datetime
import logging
from typing import Union
from typing import List
import mimetypes
from tempfile import TemporaryDirectory
from pathlib import Path
from os import listdir
from os.path import isfile, join
import zipfile
import magic
import re


# Used to extract strings
ASCII_BYTE = " !\"#\$%&'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
n = 6
combined_reg = "(?:[%s]\x00|[%s]){%d,}" % (ASCII_BYTE, ASCII_BYTE, n)
combined_re = re.compile(combined_reg)
# Allow lines with 7+ chars
good_line = re.compile("[ 0-9a-zA-Z\.:]{7,}")

# First files in the list match first
# Used for file carving
file_markers = [
    # elf
    "7f 45 4c 46 02 01 01",
    # jpg
    "ff d8 ff e0",
    # 7z
    "37 7a bc af 27",
    # avi
    "41 56 49 20",
    # bz
    "42 5A 68",
    # docx
    "50 4b 03 04 14",
    # doc
    "d0 cf 11 e0 a1",
    # png
    "89 50 4e 47",
    # rar
    "52 61 72 21",
    # zip
    "50 4b 30 30",
    # exe
    "4d 5a 90 00 03",
    # 2021
    "30 32 31 2d",
    # 2022
    "30 32 32 2d",
    # ElfChnk EVT
    "45 6c 66 43 68 6e 6b",
    # Evtx chunk
    "2a 2a 00 00",
    # PNG
    "89 50 4e 47 0d 0a 1a 0a",
    # doc
    "d0 cf 11 e0 a1 b1",
    # pst
    "21 42 4e a5 6f b5 a6",
    # <html
    "3c 68 74 6d",
    # <HTML
    "3c 48 54 4d",
    # LNK File
    "4c 00 00 00 01 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46",
    # <plist
    "70 6c 69 73 74",
]


def combined_strings_text(buf: bytes) -> str:
    """ Get strings worth indexing """
    results = []
    buf = buf.replace(b"\xff", b"\x00")
    decoded_text = buf.decode("utf8", "ignore")
    lines = combined_re.findall(decoded_text)
    current_regex = good_line
    for line in lines:
        if current_regex.search(line):
            results.append(line)
    text_output = "\n".join(results)
    # Remove non printable
    text_output = "".join(filter(lambda x: x in string.printable, text_output))
    return text_output


def combined_strings(buf: bytes) -> int:
    """Returns how many strings are in the buffer

    :param 
    """
    return len(combined_strings_text(buf))


def write_file(file_count: int, data_bytes: bytes, output_dir: Path, output_prefix: str, text_mode: bool = False) -> None:
    """Write bytes to a file as text or binary

    :param file_count:
    :param data_bytes:
    :param output_dir:
    :param output_prefix:
    :param text_mode: 
    """

    file_extension = ".bin"
    if text_mode:
        file_extension = ".log"

    mime_type = magic.from_buffer(data_bytes, mime=True)

    if mime_type != "application/octet-stream":
        extension = mimetypes.guess_extension(mime_type)
        if extension:
            file_extension = extension

    file_name = output_prefix + str(file_count) + file_extension
    file_path = os.path.join(output_dir, file_name)

    if text_mode:
        text_content = combined_strings_text(data_bytes)

        # Sub-split the text/log file if it contains dates
        # Into a single file for each possible log entry
        now = datetime.utcnow()
        current_year = str(now.year)
        last_year = str(now.year - 1)
        if current_year in text_content or last_year in text_content:
            log_parts = []
            if current_year in text_content:
                log_parts = text_content.split(current_year)
            if last_year in text_content:
                log_parts = text_content.split(last_year)

            # Append delimeter year at the start of each split text
            file_extension = ".log"

            for split_count, part in enumerate(log_parts):
                text_part = part
                if split_count != 0:
                    text_part = current_year + part

                file_name = (
                    output_prefix
                    + str(file_count)
                    + "_"
                    + str(split_count)
                    + file_extension
                )
                file_path = os.path.join(output_dir, file_name)

                with open(file_path, "w") as f:
                    f.write(text_part)

        # Text but doesnt contain a date
        else:
            with open(file_path, "w") as f:
                f.write(str(data_bytes))

    else:
        # Cant find a way to stop mypy erroring
        with open(file_path, "wb") as f:  # type: ignore
            f.write(data_bytes)  # type: ignore


def split_buffer(buffer: bytes, start_text: bool, file_markers: List[str]) -> int:
    """Split into text and data halves

    :param buffer:
    :param start_text: 
    :param file_markers:

    :return:
    """
    for file_marker in file_markers:
        byte_marker = bytearray.fromhex(file_marker)

        if byte_marker in buffer:
            before = buffer.split(byte_marker)[0]
            return len(before)

    # No header matches - Split on text vs binary
    count = 0
    for b in buffer:
        is_text = str(chr(b)).isprintable()
        # If it started with text
        if start_text:
            if not is_text:
                # We've found the split point
                return count
        # If starts with binary
        else:
            if is_text:
                # We've found the split point
                return count
        count += 1
    return count


def zip_folder(dir_name: str) -> str:
    """Zip a folder
    
    :param dir_name: path to zip
    """
    if not os.path.exists(dir_name):
        os.mkdir(dir_name)
    return shutil.make_archive(dir_name, "zip", dir_name)


def extract_dumps(input_archive: Path) -> Union[str, None]:
    """Carve process memory dump for potentially useful embedded files
    
    :param input_archive: 
    """

    logging.info("Beginning process memory dump carving")

    # 10 MB max filesize - Increasing this will slow performance
    MAX_FILESIZE = 1024 * 10000
    # Amount to read each iteration
    READ_AMOUNT = 10240

    file_count = 0
    text_mode = False
    data_buffer = bytes()

    with zipfile.ZipFile(input_archive, "a", zipfile.ZIP_DEFLATED) as dump_archive:
        for proc_dump in dump_archive.namelist():
            if proc_dump.startswith("process_dumps") and proc_dump.endswith(".mem"):
                dump_file_name = proc_dump.split("/")[-1]
                output_prefix = dump_file_name.split(".")[0]
                logging.info(f"Carving process dump {dump_file_name}")
                with dump_archive.open(proc_dump, "r") as dump:
                    with TemporaryDirectory() as extract_dir:
                        while True:
                            data = dump.read(READ_AMOUNT)

                            if bytearray(READ_AMOUNT) == data:
                                # Skip empty sections
                                pass
                            else:
                                just_split = False
                                strings_length = combined_strings(data)
                                # TODO: Remove
                                split_point = 0

                                if text_mode:
                                    # We're now looking at strings
                                    if strings_length < 1000 or len(data_buffer) > MAX_FILESIZE:
                                        # logging.info("Processed " + str(mb_processed) + " Megabytes")
                                        # logging.info("Buffer length: " + str(len(data_buffer)))
                                        split_point = split_buffer(data, True, file_markers)
                                        text_mode = False
                                        file_count += 1
                                        data_buffer += data[:split_point]
                                        write_file(file_count, data_buffer, Path(extract_dir), output_prefix, True)
                                        data_buffer = data[split_point:]
                                        just_split = True

                                else:
                                    # Now we're looking at binary
                                    if strings_length >= 1000 or len(data_buffer) > MAX_FILESIZE:
                                        # logging.info("Processed " + str(mb_processed) + " Megabytes")
                                        # logging.info("Buffer length: " + str(len(data_buffer)))
                                        split_point = split_buffer(data, False, file_markers)
                                        text_mode = True
                                        file_count += 1
                                        write_file(file_count, data_buffer + data[:split_point], Path(extract_dir), output_prefix, False)
                                        data_buffer = data[split_point:]
                                        just_split = True

                                if not just_split:
                                    data_buffer += data

                            if len(data) < READ_AMOUNT:
                                #logging.info("Less than expected data, passing")
                                write_file(file_count, data_buffer + data[:split_point], Path(extract_dir), output_prefix, text_mode)
                                break

                        # Write each carved file into dir in zip
                        carved_files = [file for file in listdir(extract_dir) if isfile(join(extract_dir, file))]
                        for carved in carved_files:
                            carved_filepath = join(extract_dir, carved)
                            dump_archive.write(carved_filepath, f"{proc_dump}_carved/{carved}")

                logging.info("Carving of process dumps complete")
    return None