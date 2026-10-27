from http.client import RemoteDisconnected

from kubernetes.client.exceptions import ApiException
from urllib3.exceptions import (
    MaxRetryError,
    NewConnectionError,
    ProtocolError,
    ReadTimeoutError,
)

TRANSIENT_API_STATUSES = {0, 409, 429, 500, 502, 503, 504}


def is_transient_error(err: BaseException) -> bool:
    if isinstance(
        err,
        (
            TimeoutError,
            ConnectionError,
            RemoteDisconnected,
            ProtocolError,
            ReadTimeoutError,
            MaxRetryError,
            NewConnectionError,
        ),
    ):
        return True
    if isinstance(err, ApiException):
        if err.status in TRANSIENT_API_STATUSES:
            return True
    text = str(err).lower()
    return any(
        token in text
        for token in (
            'connection aborted',
            'remote end closed connection',
            'timed out',
        )
    )
