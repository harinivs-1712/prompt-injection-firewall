from examples.demo_offline import run_demo


def test_offline_demo_scripted_scenarios():
    output = "\n".join(run_demo(write_output=False))
    assert "`search_notes`: **ALLOW**" in output
    assert "linked send: **BLOCK**" in output
    assert "external send authorization: **ALLOW**" in output
    assert "USER_APPROVED" in output
    assert "Audit hash chain valid: **(True, None)**" in output
