import resource
import subprocess

import pytest

TIMEOUT = 60
MEM_LIMIT = 8_000_000_000  # bytes


@pytest.mark.coreutils
def test_coreutils(coreutils_tests):
    """Test the decompiler with the given test case"""

    def limit_mem():
        resource.setrlimit(resource.RLIMIT_AS, (MEM_LIMIT, resource.RLIM_INFINITY))

    sample, function_name = coreutils_tests
    try:
        task = subprocess.run(
            ("python3", "decompile.py", sample, function_name), timeout=TIMEOUT, preexec_fn=limit_mem, capture_output=True, check=True
        )
    except subprocess.CalledProcessError as e:
        #  Delete the current exception context
        raise RuntimeError(f"crash:\n{e.stderr.decode('utf-8')}") from None
