"""List the positively labelled emails in Phishing Pot."""

from pathlib import Path

from dataset import PhishingPot


def main() -> None:
    phishing_pot = PhishingPot(Path("dataset/phishing_pot/email"))
    for file in phishing_pot.files():
        email = phishing_pot.read(file)
        print(email.file, email.label)


if __name__ == "__main__":
    main()
