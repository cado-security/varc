import os
import re


def remove_special_characters(string: str) -> str:
    """Removes special characters from string.

    :param string: string to modify
    :return: string without special chars
    """
    return re.sub('\W+', '', string)


def strip_drive(path: str) -> str:
    """Removes drive prefix from a path

    :param path: Path string to remove drive from

    :return: Windows path without drive prefix
    """
    new_path = os.path.splitdrive(path)[1]
    new_path = new_path[1:] if new_path.startswith(os.sep) else new_path
    return new_path
