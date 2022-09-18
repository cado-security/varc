from typing import Any

from varc_core.systems.base_system import BaseSystem


class OsxSystem(BaseSystem):

    def __init__(
        self,
        include_memory: bool = True,
        include_open: bool = True,
        extract_dumps: bool = False,
        **kwargs: Any
    ) -> None:
        super().__init__(include_memory=include_memory, include_open=include_open, extract_dumps=extract_dumps, **kwargs)
