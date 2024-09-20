"""Every get_ function must return: List[dict]

notepad.exe.mem - Dumped memory
notepad.exe.mem.log - Dumped memory log

Try to keep functions working cross-platform where possible
If it can't work cross-platform, put any platform specific code in the class that inherits this base
    e.g. In linux.py
"""
import io
import json
import logging
import os
import os.path
import socket
import tarfile
import time
import zipfile
from base64 import b64encode
from datetime import datetime
from typing import Any, List, Optional, Union

import lz4.frame  # type: ignore
import mss
import psutil
from tqdm import tqdm
from varc_core.utils.string_manips import remove_special_characters, strip_drive

try:
    import yara
    _YARA_AVAILABLE = True

except ImportError:
    _YARA_AVAILABLE = False

_MAX_OPEN_FILE_SIZE = 10000000  # 10 Mb max dumped filesize


class _TarLz4Wrapper:

    def __init__(self, path: str) -> None:
        self._lz4 = lz4.frame.open(path, 'wb')
        self._tar = tarfile.open(fileobj=self._lz4, mode="w")

    def writestr(self, path: str, value: Union[str, bytes]) -> None:
        info = tarfile.TarInfo(path)
        info.size = len(value)
        self._tar.addfile(info, io.BytesIO(value if isinstance(value, bytes) else value.encode()))

    def write(self, path: str, arcname: str) -> None:
        self._tar.add(path, arcname)

    def __enter__(self) -> "_TarLz4Wrapper":
        return self

    def __exit__(self, type: Any, value: Any, traceback: Any) -> None:
        self._tar.close()
        self._lz4.close()


class BaseSystem:
    """A 

    :param process_name: 
    :param process_id: 
    :param take_screenshot: 
    :param include_memory: 
    :param include_open: 
    :param extract_dumps: 
    """

    def __init__(
            self,
            process_name: Optional[str] = None,
            process_id: Optional[int] = None,
            take_screenshot: bool = True,
            include_memory: bool = True,
            include_open: bool = True,
            extract_dumps: bool = False,
            yara_file: Optional[str] = None,
            output_path: Optional[str] = None
    ) -> None:
        self.todays_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        logging.info(f'Acquiring system: {self.get_machine_name()}, at {self.todays_date}')
        self.timestamp = datetime.timestamp(datetime.now())
        self.process_name = process_name
        self.process_id = process_id
        self.include_memory = include_memory
        self.include_open = include_open
        self.screenshot = take_screenshot
        self.extract_dumps = extract_dumps
        self.yara_file = yara_file
        self.yara_results: List[dict] = []
        self.yara_hit_pids: List[int] = []
        self.output_path = output_path or os.path.join("", f"{self.get_machine_name()}-{self.timestamp}.zip")

        if self.process_name and self.process_id:
            raise ValueError(
                "Only one of Process name or Process ID (PID) can be used. Please re-run using one or the other.")
        
        self.acquire_volatile()

        if self.yara_file:
            if not _YARA_AVAILABLE:
                logging.error("YARA not available. yara-python is required and is either not installed or not functioning correctly.")
            else:
                try:
                    yara_rules = yara.load(self.yara_file)
                    self.yara_rules = yara_rules
                except:
                    logging.error("Unable to load YARA rules.")

        if self.yara_file and not self.include_memory and _YARA_AVAILABLE:
            logging.info("YARA hits will be recorded only since include_memory is not selected.")

    def get_network(self) -> List[str]:
        """Get active network connections
            
        :return: List of netstat logs
        :rtype List[string]
        """
        network = []
        try:
            connections = psutil.net_connections()
        except psutil.AccessDenied:
            logging.error("Access denied attempting to get network connections")  # without sudo on osx
            connections = []

        for conn in connections:
            syslog_date: str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            process_name: str = psutil.Process(conn.pid).name()

            if not conn.raddr:
                conn_raddr_ip = "0.0.0.0"  # <-- can expand and modify per OS if needed, I mimicked how windows shows it
                conn_raddr_port = "0"  # <-- can expand and modify per OS if needed, I mimicked how windows shows it
            else:
                conn_raddr_ip = conn.raddr.ip
                conn_raddr_port = conn.raddr.port

            log_line = f'{syslog_date} {conn.laddr.ip} {conn.laddr.port} {conn_raddr_ip} {conn_raddr_port} {process_name}'
            network.append(log_line)

        return network

    def get_processes_dict(self) -> List[dict]:
        """Get processes on system, potentially filtered

        :return: List of processes as dicts
        """
        if self.process_id:
            return [psutil.Process(self.process_id).as_dict()]
        elif self.process_name:
            process_choice = []
            for proc in psutil.process_iter():
                proc_dict = proc.as_dict()
                if proc_dict["name"].lower() == self.process_name.lower():
                    process_choice.append(proc_dict)
            return process_choice
        else:
            return [proc.as_dict() for proc in psutil.process_iter()]

    def dump_loaded_files(self) -> List[str]:
        """Collects files that are open

        :return: List of filepaths that were collected
        """

        process_choice = self.get_processes_dict()

        open_files: List[str] = []
        mapped_filepaths: List[str] = []
        exe_paths: List[str] = []

        for process in process_choice:
            proc_open_files = process.get("open_files", [])
            if proc_open_files:
                open_files += [open_file.path for open_file in proc_open_files]
            proc_memory_maps = process.get("memory_maps", [])
            if proc_memory_maps:
                mapped_filepaths += [path.path for path in proc_memory_maps]
            proc_exe = process.get("exe", [])
            if proc_exe:
                exe_paths += proc_exe

        # Combine and unique
        paths = list(set(open_files + mapped_filepaths + exe_paths))
        # only return paths that exist
        return [path for path in paths if (len(path) > 1 and os.path.exists(path) and os.path.getsize(path))]

    def get_processes(self) -> List[dict]:
        """Get running process(es) 

        :return: List of running processes - e.g. [{'pid': 1}]
        """
        process_data: List[dict] = []

        process_choice = self.get_processes_dict()

        for process in process_choice:
            creation_time = datetime.utcfromtimestamp(process["create_time"]).strftime('%Y-%m-%d %H:%M:%S')
            open_files_raw = process["open_files"]
            open_files = []
            if open_files_raw:
                for open_file in open_files_raw:
                    open_files.append(open_file.path)
            open_files_str = " ".join(open_files)
            cmd_line = ""
            # Windows
            if isinstance(process["cmdline"], str):
                cmd_line = process["cmdline"]
            # Linux, OSX
            if isinstance(process["cmdline"], List):
                cmd_line = " ".join(process["cmdline"])
            connections = []
            if "connections" in process:
                if process["connections"]:
                    for conn in process["connections"]:
                        if conn.laddr and conn.raddr:
                            log_line = f"{time.time()} {conn.laddr.ip} {conn.laddr.port} {conn.raddr.ip} {conn.raddr.port}"
                            connections.append(log_line)

            memory_maps = process.get("memory_maps", [])
            mapped_filepaths = []
            if memory_maps:
                mapped_filepaths = [path.path for path in memory_maps]

            process_data.append({"Process ID": process["pid"], "Name": process["name"], "Username": process["username"],
                                 "Status": process["status"], "Executable Path": process["exe"], "Command": cmd_line,
                                 "Parent ID": process["ppid"], "Creation Time": creation_time,
                                 "Open Files": open_files_str, "Connections": "\r\n".join(connections),
                                 "Mapped Filepaths": ",".join(mapped_filepaths)
                                 })
        return process_data

    def dict_to_json(self, rows: List[dict]) -> str:
        """Takes a list of rows/dict and returns as a json with a CadoJsonTable header

        :param rows: The List[Dict] of row data e.g. [{'filepath': 'file.txt'}]

        :return: The Json string
        """
        table_dict = {"format": "CadoJsonTable", "rows": rows}
        return json.dumps(table_dict, sort_keys=False, indent=1)
    
    # match argument of type yara.Match
    def yara_hit_readable(self, match: Any) -> dict:
        matches: bool = match['matches']
        rule: str = match['rule']
        namespace: str = match['namespace']
        tags: List[str] = match['tags']
        meta: dict = match['meta']
        pid: int = match['pid']
        proc_name: str = match['proc_name']
        y_strings = match['strings']
        
        hits: List[dict] = []
        for y_hit in y_strings:
            identifier: str = y_hit.identifier
            instances = y_hit.instances
            for inst in instances:
                hit = {
                    'matches': matches,
                    'identifier': identifier,
                    'matched_data_b64': b64encode(inst.matched_data).decode('utf-8'),
                    'matched_length': inst.matched_length,
                    'offset': inst.offset,
                    'xor_key': inst.xor_key,
                    'plaintext': inst.plaintext().decode('utf-8')
                }
                hits.append(hit)
        result = {
            'rule': rule,
            'namespace': namespace,
            'tags': tags,
            'meta': meta,
            'pid' : pid,
            'proc_name': proc_name,
            'hits': hits
        }
        return result

    def get_machine_name(self) -> str:
        """Return machine name without any special characters removed

        :return: The machine name without any special characters
        """
        return remove_special_characters(socket.gethostname())

    def take_screenshot(self) -> Optional[bytes]:
        """Takes a screenshot of all connected monitors and returns the bytes of the image

        :return:  The raw image
        """
        try:
            with mss.mss() as sct:
                monitor = sct.monitors[0]  # monitors[0] is all connected monitors in one
                sct_img = sct.grab(monitor)
                png = mss.tools.to_png(sct_img.rgb, sct_img.size)
                return png
        except mss.exception.ScreenShotError:
            logging.error("Unable to take screenshot")
        return None

    def acquire_volatile(self) -> None:
        """Acquire volatile data into a zip file
        This is called by all OS's
        """
        self.process_info = self.get_processes()
        self.network_log = self.get_network()
        self.dumped_files = self.dump_loaded_files() if self.include_open else []
        table_data = {}
        table_data["processes"] = self.dict_to_json(self.process_info)
        open_files_dict = [{"Open File": open_file} for open_file in self.dumped_files]
        table_data["open_files"] = self.dict_to_json(open_files_dict)
        if self.screenshot:
            screenshot_image = self.take_screenshot()
        else:
            screenshot_image = None

        with self._open_output() as output_file:
            if screenshot_image:
                output_file.writestr(f"{self.get_machine_name()}-{self.timestamp}.png", screenshot_image)
            for key, value in table_data.items():
                output_file.writestr(f"{key}.json", value.encode())
            if self.network_log:
                logging.info("Adding Netstat Data")
                output_file.writestr("netstat.log", "\r\n".join(self.network_log).encode())
            if self.include_open and self.dumped_files:
                for file_path in self.dumped_files:
                    logging.info(f"Adding open file {file_path}")
                    try:
                        if os.path.getsize(file_path) > _MAX_OPEN_FILE_SIZE:
                            logging.warning(f"Skipping file as too large {file_path}")
                        else:
                            try:
                                output_file.write(file_path, strip_drive(f"./collected_files/{file_path}"))
                            except PermissionError:
                                logging.warn(f"Permission denied copying {file_path}")
                    except FileNotFoundError:
                        logging.warning(f"Could not open {file_path} for reading")

    def _open_output(self) -> Union[zipfile.ZipFile, _TarLz4Wrapper]:
        if self.output_path.endswith('.tar.lz4'):
            return _TarLz4Wrapper(self.output_path)
        else:
            return zipfile.ZipFile(self.output_path, 'a', compression=zipfile.ZIP_DEFLATED)

    def yara_scan(self) -> None:
        def yara_hit_callback(hit: dict) -> Any:
            self.yara_results.append(hit)
            if self.include_memory:
                logging.info(f"YARA rule {hit['rule']} triggered. Process will be dumped.")
            else:
                logging.info(f"YARA rule {hit['rule']} was triggered.")
            return yara.CALLBACK_CONTINUE
        
        if not _YARA_AVAILABLE:
            return None

        archive_out = self.output_path
        for proc in tqdm(self.process_info, desc="YARA scan progess", unit=" procs"):
            pid = proc["Process ID"]
            p_name = proc["Name"]
            logging.info(f"Scanning pid {pid} with YARA")
            try:
                matches = self.yara_rules.match(pid=pid, callback=yara_hit_callback, which_callbacks=yara.CALLBACK_MATCHES, timeout=30)
                if matches:
                    self.yara_hit_pids.append(pid)
                    self.yara_results[-1]['pid'] = pid
                    self.yara_results[-1]['proc_name'] = p_name
            except Exception as yerr:
                logging.error(f"Error scanning process with YARA: {yerr}")
            
        if self.yara_results:
            combined_yara_results = []
            for yara_hit in self.yara_results:
                combined_yara_results.append(self.yara_hit_readable(yara_hit))
            with zipfile.ZipFile(archive_out, 'a', compression=zipfile.ZIP_DEFLATED) as zip_file:
                zip_file.writestr("yara_results.json", self.dict_to_json(combined_yara_results))
                logging.info("YARA scan results written to yara_results.json in output archive.")
        else:
            logging.info("No YARA rules were triggered. Nothing will be written to the output archive.")

