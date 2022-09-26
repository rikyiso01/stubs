from subprocess import check_call


def test_all():
    try:
        check_call("pyright", shell=True)
    except:
        assert False
