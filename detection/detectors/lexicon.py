"""Static phrase lexicons for deterministic language rules.

Every entry is written in *normalized* form -- lower-case, accent-stripped
ASCII with single spaces -- because detectors match these phrases against text
produced by ``detection.textnorm.normalize``. A unit test asserts that each
entry is a fixed point of ``normalize``, so a phrase can never silently fail
to match its own spelling.

Matching is plain substring containment (see ``matching_phrases``), so entries
are deliberately multi-word or otherwise specific enough not to occur inside
unrelated words.

The languages covered (English, Portuguese, Spanish, French, German, Dutch,
Italian) mirror the observed phishing corpus, which is dominated by English,
Brazilian Portuguese, and German lures.
"""

from typing import Final, Tuple


# Phrases that solicit a credential, identity, account, or payment action.
# Consumed by ``CredentialUrlDetector`` and always paired with a URL host that
# is unrelated to the sender, so breadth here does not fire on its own.
CREDENTIAL_LANGUAGE: Final[Tuple[str, ...]] = (
    # --- original list (kept first for stable evidence ordering) ---
    "verify your account",
    "verify your details",
    "sign in to continue",
    "signin",
    "log in",
    "login",
    "unlock your account",
    "your password will expire",
    "account is locked",
    "account will be locked",
    "validate your account",
    "unusual activity",
    "unusual sign-in",
    "verify now",
    # --- English: verification / confirmation ---
    "please verify",
    "verify your wallet",
    "verify your identity",
    "verify your email",
    "verify your information",
    "verification required",
    "identity verification",
    "confirm your account",
    "confirm your identity",
    "confirm your information",
    "confirmation required",
    "check your account",
    # --- English: account state ---
    "has been locked",
    "has been blocked",
    "has been suspended",
    "has been limited",
    "has been restricted",
    "is currently suspended",
    "temporarily restricted",
    "temporarily suspended",
    "account on hold",
    "reactivate your",
    # --- English: security pretext ---
    "unauthorized access",
    "unauthorized sign",
    "unusual login",
    "suspicious activity",
    "suspicious sign",
    "security alert",
    "security notice",
    # --- English: update / payment action ---
    "update your account",
    "update your payment",
    "update your billing",
    "update your information",
    "billing information",
    "payment information",
    "payment method",
    "action required",
    "action needed",
    "immediate action",
    # --- English: password ---
    "reset your password",
    "password has expired",
    "password expired",
    # --- English: crypto wallet ---
    "wallet has been",
    "wallet is currently",
    "secure your wallet",
    "connect your wallet",
    "recovery phrase",
    "seed phrase",
    # --- Portuguese ---
    "sua conta foi",
    "conta bloqueada",
    "conta suspensa",
    "acesso suspeito",
    "acesso bloqueado",
    "bloqueamos",
    "foi bloqueado",
    "foi bloqueada",
    "pela fiscalizacao",
    "sua encomenda foi",
    "seu pedido esta",
    "seu pedido foi",
    "regularize",
    "regularizacao",
    "atualize seus dados",
    "confirme seus dados",
    "valide seus dados",
    "senha expirou",
    "credito liberado",
    "restituicao",
    "seu cpf",
    "sua cnh",
    # --- Spanish ---
    "verifique su cuenta",
    "su cuenta ha sido",
    "cuenta bloqueada",
    "cuenta suspendida",
    "actualice sus datos",
    "confirme sus datos",
    "acceso no autorizado",
    "restablecer su contrasena",
    # --- French ---
    "verifiez votre compte",
    "votre compte a ete",
    "compte bloque",
    "compte suspendu",
    "confirmation requise",
    "confirmez votre",
    "mettez a jour",
    "acces non autorise",
    "votre mot de passe",
    "reinitialiser votre",
    # --- German ---
    "bestatigen sie",
    "verifizieren sie",
    "ihr konto wurde",
    "konto gesperrt",
    "aktualisieren sie ihre",
    "ungewohnliche aktivitat",
    "passwort lauft ab",
    "ist abgelaufen",
    "verlangern sie",
    # --- Dutch ---
    "verifieer uw",
    "bevestig uw",
    "account geblokkeerd",
    "uw wachtwoord",
    "werk uw gegevens bij",
    # --- Italian ---
    "verifica il tuo",
    "account bloccato",
    "account sospeso",
    "aggiorna i tuoi dati",
    "conferma la tua",
)

# Phrases signalling payment pressure or manufactured urgency in messages that
# carry no link or attachment. Consumed by ``BecNoPayloadDetector``.
URGENCY_LANGUAGE: Final[Tuple[str, ...]] = (
    # --- original list (kept first for stable evidence ordering) ---
    "wire transfer",
    "gift card",
    "gift cards",
    "urgent",
    "confidential",
    "cannot call",
    "in a meeting",
    "before the bank closes",
    "process a vendor payment",
    # --- English ---
    "immediate attention",
    "quick response",
    "are you available",
    "need a favor",
    "kindly confirm",
    "payment request",
    "outstanding invoice",
    "invoice attached",
    "overdue invoice",
    "bank details",
    "change of bank",
    "new bank account",
    # --- Portuguese / Spanish ---
    "transferencia urgente",
    "pagamento urgente",
    "com urgencia",
    "pago urgente",
    # --- French ---
    "virement urgent",
    "de toute urgence",
    # --- German ---
    "dringende uberweisung",
)

# Advance-fee, lottery, and prize lures. Defined here so the corpus-mined
# vocabulary lives with the other lexicons; consumed by the Phase 4
# advance-fee detector.
ADVANCE_FEE_LANGUAGE: Final[Tuple[str, ...]] = (
    # --- English ---
    "you have won",
    "you have been selected",
    "claim your prize",
    "claim your reward",
    "claim your free",
    "claim your share",
    "lottery",
    "inheritance",
    "beneficiary",
    "next of kin",
    "unclaimed fund",
    "million dollars",
    "compensation fund",
    "business proposal",
    "mutual benefit",
    "transfer of funds",
    "congratulations you",
    "free spins",
    "welcome bonus",
    "no deposit bonus",
    # --- German ---
    "gewinnen sie",
    "sie haben gewonnen",
    "sichern sie sich",
    "einkaufsgutschein",
    "keine einzahlung",
    "im wert von",
    # --- Portuguese ---
    "voce ganhou",
    "resgate seu premio",
    "resgate agora",
    "giros gratis",
    # --- French ---
    "vous avez gagne",
    "felicitations vous",
    # --- Spanish ---
    "usted ha ganado",
    "ha sido seleccionado",
    # --- Dutch ---
    "u heeft gewonnen",
)
