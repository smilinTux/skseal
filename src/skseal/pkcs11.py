"""PKCS#11 hardware token support for SKSeal.

Enables signing with YubiKey, NitroKey, and other PKCS#11-compatible
hardware security modules. Private keys never leave the token — the
signing operation happens on-device.

Supported tokens:
    - YubiKey 5 (via libykcs11.so or OpenSC)
    - NitroKey Pro/Start (via OpenSC)
    - Any PKCS#11-compatible HSM (SoftHSM2 for testing)

Common PKCS#11 module paths:
    - OpenSC:  /usr/lib/opensc-pkcs11.so (or /usr/lib/x86_64-linux-gnu/)
    - YubiKey: /usr/lib/libykcs11.so
    - SoftHSM: /usr/lib/softhsm/libsofthsm2.so

Usage::

    from skseal.pkcs11 import list_tokens, sign_with_token

    tokens = list_tokens("/usr/lib/opensc-pkcs11.so")
    for t in tokens:
        print(f"Slot {t.slot_id}: {t.label} ({t.manufacturer})")

    signature = sign_with_token(
        module_path="/usr/lib/opensc-pkcs11.so",
        token_label="OpenPGP card",
        pin="123456",
        data=b"hash-to-sign",
    )
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger("skseal.pkcs11")

# Well-known PKCS#11 module paths by platform and token type.
DEFAULT_MODULE_PATHS: list[str] = [
    "/usr/lib/opensc-pkcs11.so",
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/libykcs11.so",
    "/usr/lib/x86_64-linux-gnu/libykcs11.so",
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/opt/homebrew/lib/opensc-pkcs11.so",  # macOS Homebrew
    "/usr/local/lib/opensc-pkcs11.so",
]


# ---------------------------------------------------------------------------
# Library detection
# ---------------------------------------------------------------------------


def _has_pkcs11() -> bool:
    """Return True if PyKCS11 is importable."""
    try:
        import PyKCS11  # noqa: F401
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class TokenInfo:
    """Information about a PKCS#11 token (hardware security module).

    Attributes:
        slot_id: PKCS#11 slot number.
        label: Human-readable token label.
        manufacturer: Token manufacturer string.
        model: Token model string.
        serial: Token serial number.
        has_private_key: Whether a private signing key was found.
        key_id: Hex-encoded key identifier (if found).
        key_label: Key label on the token (if found).
        mechanism: Signing mechanism supported.
    """

    slot_id: int
    label: str
    manufacturer: str = ""
    model: str = ""
    serial: str = ""
    has_private_key: bool = False
    key_id: Optional[str] = None
    key_label: Optional[str] = None
    mechanism: str = "RSA_PKCS"


@dataclass
class PKCS11Config:
    """Configuration for PKCS#11 operations.

    Attributes:
        module_path: Path to the PKCS#11 shared library.
        token_label: Label of the token to use (optional, uses first found).
        slot_id: Specific slot ID (optional, overrides token_label).
        pin: User PIN for the token.
        key_id: Specific key ID to use (hex, optional).
        key_label: Specific key label to use (optional).
        hash_algorithm: Hash algorithm for signing (sha256, sha384, sha512).
    """

    module_path: str = ""
    token_label: Optional[str] = None
    slot_id: Optional[int] = None
    pin: str = ""
    key_id: Optional[str] = None
    key_label: Optional[str] = None
    hash_algorithm: str = "sha256"


# ---------------------------------------------------------------------------
# Module path discovery
# ---------------------------------------------------------------------------


def find_pkcs11_module() -> Optional[str]:
    """Auto-detect an available PKCS#11 module on the system.

    Searches well-known paths for PKCS#11 shared libraries.

    Returns:
        Path to the first found module, or None if none found.
    """
    for path in DEFAULT_MODULE_PATHS:
        if Path(path).exists():
            logger.debug("Found PKCS#11 module: %s", path)
            return path
    return None


# ---------------------------------------------------------------------------
# Token enumeration
# ---------------------------------------------------------------------------


def list_tokens(module_path: Optional[str] = None) -> list[TokenInfo]:
    """List all available PKCS#11 tokens.

    Enumerates all slots with tokens present and returns metadata
    for each, including whether a private signing key is available.

    Args:
        module_path: Path to the PKCS#11 module. Auto-detected if None.

    Returns:
        List of TokenInfo objects for each available token.

    Raises:
        RuntimeError: If PyKCS11 is not installed or module not found.
    """
    if not _has_pkcs11():
        raise RuntimeError(
            "PyKCS11 is not installed. Install with: pip install PyKCS11"
        )

    if module_path is None:
        module_path = find_pkcs11_module()
    if module_path is None:
        raise RuntimeError(
            "No PKCS#11 module found. Specify --module or install OpenSC."
        )

    import PyKCS11

    lib = PyKCS11.PyKCS11Lib()
    lib.load(module_path)

    tokens: list[TokenInfo] = []
    slots = lib.getSlotList(tokenPresent=True)

    for slot_id in slots:
        try:
            token_info = lib.getTokenInfo(slot_id)
            label = token_info.label.strip()
            manufacturer = token_info.manufacturerID.strip()
            model = token_info.model.strip()
            serial = token_info.serialNumber.strip()

            info = TokenInfo(
                slot_id=slot_id,
                label=label,
                manufacturer=manufacturer,
                model=model,
                serial=serial,
            )

            # Check for private signing keys
            try:
                session = lib.openSession(slot_id)
                objs = session.findObjects([
                    (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                    (PyKCS11.CKA_SIGN, True),
                ])
                if objs:
                    info.has_private_key = True
                    # Get key metadata from first signing key
                    attrs = session.getAttributeValue(objs[0], [
                        PyKCS11.CKA_ID,
                        PyKCS11.CKA_LABEL,
                    ])
                    if attrs[0]:
                        info.key_id = bytes(attrs[0]).hex()
                    if attrs[1]:
                        info.key_label = bytes(attrs[1]).decode("utf-8", errors="replace")
                session.closeSession()
            except Exception as exc:
                logger.debug("Could not inspect slot %d keys: %s", slot_id, exc)

            tokens.append(info)
        except Exception as exc:
            logger.debug("Could not read slot %d: %s", slot_id, exc)

    return tokens


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------


def sign_with_token(
    data: bytes,
    config: Optional[PKCS11Config] = None,
    *,
    module_path: Optional[str] = None,
    token_label: Optional[str] = None,
    slot_id: Optional[int] = None,
    pin: Optional[str] = None,
    key_id: Optional[str] = None,
    key_label: Optional[str] = None,
    hash_algorithm: str = "sha256",
) -> bytes:
    """Sign data using a PKCS#11 hardware token.

    The private key never leaves the token. The data is hashed and the
    hash is sent to the token for signing.

    Args:
        data: Raw bytes to sign (will be hashed).
        config: Full PKCS11Config object (overrides keyword args).
        module_path: Path to PKCS#11 module.
        token_label: Token label to match.
        slot_id: Specific slot to use.
        pin: Token user PIN.
        key_id: Hex-encoded key ID on the token.
        key_label: Key label on the token.
        hash_algorithm: Hash algorithm (sha256, sha384, sha512).

    Returns:
        Raw signature bytes.

    Raises:
        RuntimeError: If signing fails or token/key not found.
    """
    if not _has_pkcs11():
        raise RuntimeError(
            "PyKCS11 is not installed. Install with: pip install PyKCS11"
        )

    # Resolve config
    if config is not None:
        module_path = config.module_path or module_path
        token_label = config.token_label or token_label
        slot_id = config.slot_id if config.slot_id is not None else slot_id
        pin = config.pin or pin
        key_id = config.key_id or key_id
        key_label = config.key_label or key_label
        hash_algorithm = config.hash_algorithm or hash_algorithm

    if module_path is None:
        module_path = find_pkcs11_module()
    if module_path is None:
        raise RuntimeError("No PKCS#11 module found")
    if not pin:
        raise RuntimeError("PIN is required for hardware token signing")

    import PyKCS11

    lib = PyKCS11.PyKCS11Lib()
    lib.load(module_path)

    # Find the target slot
    target_slot = _find_slot(lib, slot_id=slot_id, token_label=token_label)

    # Open authenticated session
    session = lib.openSession(target_slot, PyKCS11.CKF_RW_SESSION)
    try:
        session.login(pin)
    except PyKCS11.PyKCS11Error as exc:
        session.closeSession()
        raise RuntimeError(f"Token login failed: {exc}") from exc

    try:
        # Find the signing key
        key_handle = _find_signing_key(
            session, key_id=key_id, key_label=key_label
        )

        # Hash the data
        digest = hashlib.new(hash_algorithm, data).digest()

        # Select mechanism based on hash algorithm
        mechanism = _get_mechanism(hash_algorithm)

        # Sign
        signature = session.sign(key_handle, digest, mechanism)
        return bytes(signature)

    except PyKCS11.PyKCS11Error as exc:
        raise RuntimeError(f"PKCS#11 signing failed: {exc}") from exc
    finally:
        try:
            session.logout()
        except Exception:
            pass
        session.closeSession()


def get_public_key_der(
    config: Optional[PKCS11Config] = None,
    *,
    module_path: Optional[str] = None,
    token_label: Optional[str] = None,
    slot_id: Optional[int] = None,
    pin: Optional[str] = None,
    key_id: Optional[str] = None,
    key_label: Optional[str] = None,
) -> bytes:
    """Extract the public key from a PKCS#11 token in DER format.

    Args:
        config: Full PKCS11Config object.
        module_path: Path to PKCS#11 module.
        token_label: Token label to match.
        slot_id: Specific slot to use.
        pin: Token user PIN (may not be required for public key).
        key_id: Hex-encoded key ID on the token.
        key_label: Key label on the token.

    Returns:
        DER-encoded public key bytes.

    Raises:
        RuntimeError: If key not found or extraction fails.
    """
    if not _has_pkcs11():
        raise RuntimeError(
            "PyKCS11 is not installed. Install with: pip install PyKCS11"
        )

    if config is not None:
        module_path = config.module_path or module_path
        token_label = config.token_label or token_label
        slot_id = config.slot_id if config.slot_id is not None else slot_id
        pin = config.pin or pin
        key_id = config.key_id or key_id
        key_label = config.key_label or key_label

    if module_path is None:
        module_path = find_pkcs11_module()
    if module_path is None:
        raise RuntimeError("No PKCS#11 module found")

    import PyKCS11

    lib = PyKCS11.PyKCS11Lib()
    lib.load(module_path)

    target_slot = _find_slot(lib, slot_id=slot_id, token_label=token_label)
    session = lib.openSession(target_slot)

    if pin:
        try:
            session.login(pin)
        except PyKCS11.PyKCS11Error:
            pass  # Public key may be readable without login

    try:
        # Find matching public key object
        search_attrs = [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY)]
        if key_id:
            search_attrs.append((PyKCS11.CKA_ID, bytes.fromhex(key_id)))
        if key_label:
            search_attrs.append((PyKCS11.CKA_LABEL, key_label))

        objs = session.findObjects(search_attrs)
        if not objs:
            raise RuntimeError("No public key found on token")

        # Get the DER-encoded public key value
        attrs = session.getAttributeValue(objs[0], [PyKCS11.CKA_VALUE])
        if not attrs[0]:
            raise RuntimeError("Could not read public key value from token")

        return bytes(attrs[0])

    finally:
        try:
            session.logout()
        except Exception:
            pass
        session.closeSession()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _find_slot(
    lib,  # PyKCS11.PyKCS11Lib
    *,
    slot_id: Optional[int] = None,
    token_label: Optional[str] = None,
) -> int:
    """Find a PKCS#11 slot by ID or token label.

    Args:
        lib: Loaded PyKCS11 library.
        slot_id: Direct slot number.
        token_label: Token label to search for.

    Returns:
        Slot ID.

    Raises:
        RuntimeError: If no matching slot is found.
    """
    slots = lib.getSlotList(tokenPresent=True)
    if not slots:
        raise RuntimeError("No PKCS#11 tokens found")

    if slot_id is not None:
        if slot_id in slots:
            return slot_id
        raise RuntimeError(f"Slot {slot_id} not found or has no token")

    if token_label is not None:
        for sid in slots:
            try:
                info = lib.getTokenInfo(sid)
                if info.label.strip() == token_label:
                    return sid
            except Exception:
                continue
        raise RuntimeError(f"No token with label '{token_label}' found")

    # Default to first slot
    return slots[0]


def _find_signing_key(
    session,  # PyKCS11.Session
    *,
    key_id: Optional[str] = None,
    key_label: Optional[str] = None,
):
    """Find a private signing key on a PKCS#11 token.

    Args:
        session: Authenticated PKCS#11 session.
        key_id: Hex-encoded key ID to match.
        key_label: Key label to match.

    Returns:
        Key object handle.

    Raises:
        RuntimeError: If no signing key found.
    """
    import PyKCS11

    search_attrs = [
        (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
        (PyKCS11.CKA_SIGN, True),
    ]
    if key_id:
        search_attrs.append((PyKCS11.CKA_ID, bytes.fromhex(key_id)))
    if key_label:
        search_attrs.append((PyKCS11.CKA_LABEL, key_label))

    objs = session.findObjects(search_attrs)
    if not objs:
        raise RuntimeError(
            "No private signing key found on token"
            + (f" matching key_id={key_id}" if key_id else "")
            + (f" matching label={key_label}" if key_label else "")
        )

    return objs[0]


def _get_mechanism(hash_algorithm: str):
    """Get the PKCS#11 signing mechanism for a hash algorithm.

    Args:
        hash_algorithm: "sha256", "sha384", or "sha512".

    Returns:
        PyKCS11 Mechanism object for RSA signing with the specified hash.
    """
    import PyKCS11

    mechanisms = {
        "sha256": PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS, None),
        "sha384": PyKCS11.Mechanism(PyKCS11.CKM_SHA384_RSA_PKCS, None),
        "sha512": PyKCS11.Mechanism(PyKCS11.CKM_SHA512_RSA_PKCS, None),
    }

    mech = mechanisms.get(hash_algorithm)
    if mech is None:
        raise RuntimeError(f"Unsupported hash algorithm: {hash_algorithm}")

    return mech
