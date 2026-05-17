import os

import pytest


@pytest.fixture(scope='session')
def cluster_namespace_prefix() -> str:
    return os.environ.get('PYROUTE2_CNI_TEST_PREFIX', 'pyroute2-cni-test')
