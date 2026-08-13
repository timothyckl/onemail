"""Raw input at the detection boundary."""

from dataclasses import dataclass


@dataclass(frozen=True)
class EmailInput:
    """One email file and its unmodified RFC 822 bytes."""

    file: str
    content: bytes

    def __post_init__(self) -> None:
        if not self.file:
            raise ValueError("email input requires a file name")
        if not isinstance(self.content, bytes):
            raise TypeError("email content must be bytes")
