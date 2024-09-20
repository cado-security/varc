import unittest
from zipfile import ZipFile

from varc_core.systems import BaseSystem, acquire_system

class TestBaseCases(unittest.TestCase):
    system: BaseSystem

    @classmethod
    def setUpClass(cls) -> None:
        cls.system = acquire_system()
        cls.system.acquire_volatile()


    def test_some_processes(self) -> None:
        processes = self.system.get_processes()
        self.assertTrue(len(processes) > 0)
        process_names = [process["Name"] for process in processes]
        self.assertIn("python3", process_names)
        
        
    def test_dump_files(self) -> None:
        open_files = self.system.dump_loaded_files()
        self.assertTrue(len(open_files) > 0)
        # Check we pulled at least one file from /bin/
        with ZipFile(self.system.output_path) as z:
            binary_files = [binary for binary in z.namelist() if ("/bin/" in binary in binary.lower())]
            self.assertGreater(len(binary_files), 0)
                        