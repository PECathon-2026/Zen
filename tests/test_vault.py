import pytest

from zenlens.gate import egress_check
from zenlens.vault import Vault, VaultError, infer_kind, placeholder, secret_name

PW = "Synth-Pass-4471"  # synthetic


def test_resolve_and_kinds():
    v = Vault({"login_password": PW, "work_email": "demo.user@example.test", "nick": ("text", "zed")})
    assert v.resolve("{{SECRET:login_password}}") == PW
    assert v.kind("login_password") == "password" and v.kind("work_email") == "email" and v.kind("nick") == "text"
    assert infer_kind("card_cvv") == "card" and infer_kind("bank_otp") == "otp"
    with pytest.raises(VaultError) as e:
        v.resolve("{{SECRET:missing}}")
    assert "missing" in str(e.value)


def test_value_never_in_repr_or_errors():
    v = Vault({"login_password": PW})
    assert PW not in repr(v) and PW not in str(v) and "login_password" in repr(v)
    with pytest.raises(VaultError) as e:
        v.kind("nope")
    assert PW not in str(e.value)
    with pytest.raises(TypeError):
        import pickle
        pickle.dumps(v)


def test_from_env_and_file(tmp_path):
    v = Vault.from_env(env={"ZENLENS_SECRET_LOGIN_PASSWORD": PW, "HOME": "/x"})
    assert v.names() == ["login_password"] and v.resolve(placeholder("login_password")) == PW
    f = tmp_path / "secrets.env"
    f.write_text("# synthetic\nlogin_password=" + PW + "\npin:otp=482913\n")
    v = Vault.from_file(f)
    assert v.kind("pin") == "otp" and v.resolve("{{SECRET:pin}}") == "482913"
    f.write_text("garbage line\n")
    with pytest.raises(VaultError) as e:
        Vault.from_file(f)
    assert "garbage" not in str(e.value)


def test_placeholders_pass_gate_and_values_are_canaries():
    v = Vault({"login_password": PW})
    payload = '{"text": "{{SECRET:login_password}}", "label": "[REDACTED:EMAIL]", "x": "[REDACTED:CARD]"}'
    assert egress_check(payload, v.canaries()) == payload
    from zenlens.gate import Blocked
    with pytest.raises(Blocked):
        egress_check("oops " + PW, v.canaries())
    assert secret_name("{{SECRET:a_b}}") == "a_b" and secret_name("x {{SECRET:a}}") is None
