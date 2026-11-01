"""RFC 8785 vectors frozen by Sentinel Deterministic Core v10.0."""

from pathlib import Path

import pytest

from packages.protocol_contracts import models as contract_models
from packages.protocol_contracts.models import canonicalize_jcs_bytes


def test_open_spec_models_are_the_extracted_module() -> None:
    assert "sentinel-open-spec" in Path(contract_models.__file__).resolve().parts
    assert not hasattr(contract_models, "validate_safe_resource_uri")


def test_jcs_rejects_ieee754_floats() -> None:
    with pytest.raises(ValueError, match="IEEE 754 floats are prohibited"):
        canonicalize_jcs_bytes({"amount": 19.99})


def test_jcs_utf16_code_unit_sorting_and_nfc_collision() -> None:
    bmp_char = "\ue000"
    supplementary_char = "\U00010000"
    encoded = canonicalize_jcs_bytes({bmp_char: 1, supplementary_char: 2}).decode("utf-8")
    assert encoded.index(supplementary_char) < encoded.index(bmp_char)
    with pytest.raises(ValueError, match="DUPLICATE_CANONICAL_KEY_AFTER_NFC"):
        canonicalize_jcs_bytes({"\u00e9": 1, "e\u0301": 2})


def test_jcs_money_amount_is_integer_cents() -> None:
    encoded = canonicalize_jcs_bytes({"amount_cents": 1999}).decode("utf-8")
    assert encoded == '{"amount_cents":1999}'
