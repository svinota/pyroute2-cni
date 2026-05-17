import os
import time
import uuid

from kubernetes import client, config


def load_client() -> client.CoreV1Api:
    config.load_kube_config()
    return client.CoreV1Api()


def unique_name(prefix: str) -> str:
    return f'{prefix}-{uuid.uuid4().hex[:8]}'


def wait_for(condition, timeout: float = 60.0, interval: float = 1.0) -> None:
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            if condition():
                return
        except Exception as err:  # pragma: no cover - diagnostic path
            last_error = err
        time.sleep(interval)
    if last_error is not None:
        raise AssertionError(f'timed out waiting: {last_error}')
    raise AssertionError('timed out waiting')


def test_image() -> str:
    return os.environ.get('PYROUTE2_CNI_TEST_IMAGE', 'busybox:1.36')
