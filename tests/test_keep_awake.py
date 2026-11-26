"""A long AVIT run keeps a Mac from idle-sleeping, and never elsewhere or in tests."""

from threatlint import keep_awake as ka


class FakeProcess:
    def __init__(self, args, **_kwargs):
        self.args, self.terminated = args, False

    def terminate(self):
        self.terminated = True


def test_caffeinate_blocks_idle_sleep_for_the_run_and_stops_after():
    started = []
    popen = lambda args, **kw: started.append(FakeProcess(args, **kw)) or started[-1]
    with ka.keep_awake(platform="darwin", env={}, popen=popen, exists=lambda _p: True) as process:
        assert process.args[:3] == ["/usr/bin/caffeinate", "-i", "-w"] and process.args[3].isdigit()
        assert not process.terminated
    assert started[0].terminated


def test_keep_awake_is_off_elsewhere_when_disabled_and_under_pytest():
    popen = lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("must not start caffeinate"))
    for platform, env in (("linux", {}), ("darwin", {"THREATLINT_KEEP_AWAKE": "0"}), ("darwin", {"PYTEST_CURRENT_TEST": "x"})):
        with ka.keep_awake(platform=platform, env=env, popen=popen, exists=lambda _p: True) as process:
            assert process is None


def test_a_missing_caffeinate_never_breaks_the_run():
    def popen(*_args, **_kwargs):
        raise OSError("not found")
    with ka.keep_awake(platform="darwin", env={}, popen=popen, exists=lambda _p: True) as process:
        assert process is None
