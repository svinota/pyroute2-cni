from unittest.mock import MagicMock, patch

from pyroute2_cni import kubernetes as k8s_helpers


def test_get_node_ip_prefers_internal():
    node = MagicMock()
    node.status.addresses = [
        MagicMock(type='ExternalIP', address='203.0.113.10'),
        MagicMock(type='InternalIP', address='10.0.0.10'),
    ]
    with patch.object(k8s_helpers, 'get_node', return_value=node):
        assert k8s_helpers.get_node_ip('node-1') == '10.0.0.10'
