"""Read phishing emails from the Phishing Pot corpus."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Tuple, Union


@dataclass(frozen=True)
class PhishingEmail:
    """One positively labelled phishing email."""

    file: str
    content: bytes
    label: str = field(default="phishing", init=False)

    def __post_init__(self) -> None:
        if not self.file:
            raise ValueError("phishing email requires a file name")
        if not isinstance(self.content, bytes):
            raise TypeError("phishing email content must be bytes")


class PhishingPot:
    """Provide stable access to the email samples in a Phishing Pot checkout."""

    label = "phishing"

    def __init__(self, directory: Union[str, Path]) -> None:
        self.directory = Path(directory)

    def files(self) -> Tuple[Path, ...]:
        """Return corpus-relative EML paths in stable order."""

        if not self.directory.is_dir():
            raise FileNotFoundError(f"Phishing Pot directory not found: {self.directory}")
        return tuple(
            sorted(
                (
                    path.relative_to(self.directory)
                    for path in self.directory.rglob("*")
                    if path.is_file() and path.suffix.lower() == ".eml"
                ),
                key=lambda path: path.as_posix(),
            )
        )

    def read(self, file: Path) -> PhishingEmail:
        """Read one corpus-relative path without changing its bytes."""

        path = self.directory / file
        return PhishingEmail(file=file.as_posix(), content=path.read_bytes())
