"""VARC custom exceptions
"""

class VarcException(Exception):
    """Base class for exeptions with a message that can be displayed to users
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.user_message = message

class MissingOperatingSystemInfo(VarcException):
    def __init__(self) -> None:
        super().__init__("Failed to detect operating system.")
