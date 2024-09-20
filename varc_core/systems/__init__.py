import logging
from sys import platform
from typing import Optional

from varc_core.exceptions import MissingOperatingSystemInfo
from varc_core.systems.base_system import BaseSystem


def acquire_system(
    include_memory: bool = True,
    include_open: bool = True,
    extract_dumps: bool = False,
    yara_file: Optional[str] = None,
    output_path: Optional[str] = None
) -> BaseSystem:
    """Returns the either a windows or linux system or osx system

    :return: Returns the system object for the OS
    :rtype WindowsSystem or LinuxSystem or OsxSystem
    """  
    logging.info(f"Operating System is: {platform}")
    if platform == "linux" or platform == "linux2":
        from varc_core.systems.linux import LinuxSystem
        return LinuxSystem(include_memory, include_open, extract_dumps, yara_file, output_path=output_path)
    elif platform == "darwin":
        from varc_core.systems.osx import OsxSystem
        return OsxSystem(include_memory, include_open, extract_dumps, output_path=output_path)
    elif platform == "win32":
        from varc_core.systems.windows import WindowsSystem
        return WindowsSystem(include_memory, include_open, extract_dumps, yara_file, output_path=output_path)
    else:
        raise MissingOperatingSystemInfo()