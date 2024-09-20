import unittest
from zipfile import ZipFile

from varc_core.systems import BaseSystem, acquire_system


class TestBaseCases(unittest.TestCase):
    system: BaseSystem

    @classmethod
    def setUpClass(cls) -> None:
        cls.system = acquire_system()
        cls.system.acquire_volatile()

    @classmethod
    def tearDownClass(cls) -> None:
        pass

    def test_get_processes(self) -> None:
        processes = self.system.get_processes()
        self.assertTrue(len(processes) > 0)

    def test_get_network(self) -> None:
        network = self.system.get_network()
        self.assertTrue(len(network) > 0)

    def test_got_files(self) -> None:
        # Check we got atleast 10 files
        with ZipFile(self.system.output_path) as z:
            self.assertGreater(len(z.namelist()), 10)
