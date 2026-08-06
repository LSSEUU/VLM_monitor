import socket

import pytest
from pytest_socket import SocketBlockedError


def test_default_test_suite_blocks_network_sockets() -> None:
    with (
        pytest.warns(UserWarning, match="tried to use socket.socket"),
        pytest.raises(SocketBlockedError),
    ):
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
