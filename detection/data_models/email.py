"""Raw email at the detection boundary."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Email:
    """One email file and its unmodified RFC 822 bytes."""

    file: str
    content: bytes

    def __post_init__(self) -> None:
        if not self.file:
            raise ValueError("email requires a file name")
        if not isinstance(self.content, bytes):
            raise TypeError("email content must be bytes")
