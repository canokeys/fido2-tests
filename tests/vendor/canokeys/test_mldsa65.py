import pytest
from binascii import hexlify
from pqcrypto.sign import ml_dsa_65

from tests.utils import FidoRequest

MLDSA65 = -49
COSE_KTY_LABEL = 1
COSE_ALG_LABEL = 3
COSE_AKP_PUB_LABEL = -1
COSE_KEY_KTY_AKP = 7
MLDSA_PK_BYTES = 1952
MLDSA_SIG_BYTES = 3309


def _debug_dump(credential_data, ga_res):
    print("authdata", hexlify(ga_res.auth_data))
    print("cdh", hexlify(ga_res.request.cdh))
    print("sig", hexlify(ga_res.signature))
    print("public_key_labels", list(credential_data.public_key.keys()))
    print("public_key_alg", credential_data.public_key[COSE_ALG_LABEL])
    print("public_key_kty", credential_data.public_key[COSE_KTY_LABEL])
    print("public_key_len", len(credential_data.public_key[COSE_AKP_PUB_LABEL]))


def _verify_assertion_signature(credential_data, ga_res):
    signed_message = bytes(ga_res.auth_data) + ga_res.request.cdh
    public_key = credential_data.public_key[COSE_AKP_PUB_LABEL]

    assert ml_dsa_65.verify(public_key, signed_message, ga_res.signature)

    tampered_message = bytearray(signed_message)
    tampered_message[-1] ^= 0x01
    assert not ml_dsa_65.verify(public_key, bytes(tampered_message), ga_res.signature)


def test_get_info_algorithms(info):
    print(info.algorithms)
    assert {"alg": MLDSA65, "type": "public-key"} in info.algorithms


def test_mldsa65_make_credential_get_assertion(device):
    mc_req = FidoRequest(
        rp={"id": "example.org", "name": "rp"},
        user={"id": b"\x01", "name": "u", "displayName": "u"},
        key_params=[{"type": "public-key", "alg": MLDSA65}],
    )
    try:
        mc_res = device.sendMC(*mc_req.toMC())
    except Exception as e:
        pytest.fail(f"makeCredential with ML-DSA-65 failed: {e}")

    setattr(mc_res, "request", mc_req)

    credential_data = mc_res.auth_data.credential_data
    public_key = credential_data.public_key

    assert public_key[COSE_KTY_LABEL] == COSE_KEY_KTY_AKP
    assert public_key[COSE_ALG_LABEL] == MLDSA65
    assert len(public_key[COSE_AKP_PUB_LABEL]) == MLDSA_PK_BYTES

    allow_list = [{"id": credential_data.credential_id[:], "type": "public-key"}]
    ga_req = FidoRequest(allow_list=allow_list)
    try:
        ga_res = device.sendGA(*ga_req.toGA())
    except Exception as e:
        pytest.fail(f"getAssertion with ML-DSA-65 credential failed: {e}")

    setattr(ga_res, "request", ga_req)

    try:
        assert ga_res.auth_data.rp_id_hash == mc_res.auth_data.rp_id_hash
        assert ga_res.credential is not None
        assert ga_res.credential["id"] == credential_data.credential_id
        assert len(ga_res.signature) == MLDSA_SIG_BYTES
        _verify_assertion_signature(credential_data, ga_res)
    except Exception:
        _debug_dump(credential_data, ga_res)
        raise
