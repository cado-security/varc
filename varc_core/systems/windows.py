import logging
import tempfile
import zipfile
from os import remove as del_file
from os import sep
from pathlib import Path
from sys import platform
from typing import Any, Optional, Tuple

from tqdm import tqdm
from varc_core.systems.base_system import BaseSystem

if platform == "win32": # dont try to import on linux
   from sys import maxsize

   import pymem

class WindowsSystem(BaseSystem):
    """
    """

    def __init__(
        self,
        include_memory: bool,
        include_open: bool,
        extract_dumps: bool,
        yara_file: Optional[str],
        **kwargs: Any
    ) -> None:
        super().__init__(include_memory=include_memory, include_open=include_open, extract_dumps=extract_dumps, yara_file=yara_file, **kwargs)
        if self.include_memory:
            if self.yara_file:
                self.yara_scan()
            self.dump_processes()

            if self.extract_dumps:
                from varc_core.utils import dumpfile_extraction
                dumpfile_extraction.extract_dumps(Path(self.output_path))

    def read_process(self, handle: int, address: int) -> Tuple[Optional[bytes], int]:
        """ Read a process. Based on pymems pattern module

        :param handle: int of the handle
        :param address: int of the address

        :return: The process contents
        :rtype: Tuple[Optional[bytes], int]
        """

        mbi = pymem.memory.virtual_query(handle, address)
        next_region: int = int(mbi.BaseAddress + mbi.RegionSize)
        allowed_protections = [
            pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READ,
            pymem.ressources.structure.MEMORY_PROTECTION.PAGE_EXECUTE_READWRITE,
            pymem.ressources.structure.MEMORY_PROTECTION.PAGE_READWRITE,
            pymem.ressources.structure.MEMORY_PROTECTION.PAGE_READONLY,
        ]
        if mbi.state != pymem.ressources.structure.MEMORY_STATE.MEM_COMMIT or mbi.protect not in allowed_protections:
            return None, next_region 
        try:
            page_bytes = None
            page_bytes = pymem.memory.read_bytes(handle, address, mbi.RegionSize)
        except Exception:
            logging.warning("Failed to read a memory page")
        return page_bytes, next_region
    
    def dump_processes(self) -> None:
        """
        Based on pymem's 'Pattern' module
        """
        archive_out = self.output_path
        for proc in tqdm(self.process_info, desc="Process dump progess", unit=" procs"):
            # If scanning with YARA, only dump processes if they triggered a rule
            if self.yara_hit_pids:
                if proc["Process ID"] not in self.yara_hit_pids:
                    continue
            pid = proc["Process ID"]
            p_name = proc["Name"]

            # Set upper limits on memory address to read
            user_space_limit = 0x7FFFFFFF0000 if maxsize > 2**32 else 0x7fff0000

            # Open handle to process memory for reading
            try:
                p = pymem.Pymem()
                p.open_process_from_id(pid)
            except (TypeError, pymem.exception.CouldNotOpenProcess):
                logging.warning(f"Could not open process {p_name} (pid {pid}) for reading. Cannot dump this process.")
                continue
            except pymem.exception.WinAPIError:
                logging.warning(f"API error attempting to open process {p_name} (pid {pid}) for reading. Cannot dump this process.")
                continue
            
            # Dump all pages the process virtual address space
            next_region = 0
            with zipfile.ZipFile(archive_out, 'a', compression=zipfile.ZIP_DEFLATED) as zip_file:
                with tempfile.NamedTemporaryFile(mode="w+b", buffering=0, delete=False) as tmpfile:
                    while next_region < user_space_limit:
                        proc_page_bytes, next_region = self.read_process(p.process_handle, next_region)
                        if proc_page_bytes:
                            tmpfile.write(proc_page_bytes)
                    zip_file.write(tmpfile.name, f"process_dumps{sep}{p_name}_{pid}.mem")
                del_file(tmpfile.name)
        logging.info(f"Dumping processing has completed. Output file is located: {archive_out}")
