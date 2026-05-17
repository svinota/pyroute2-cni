from pyroute2_cni.protocols import PluginProtocol


def test_protocol_exports_expected_methods():
    assert hasattr(PluginProtocol, 'setup')
    assert hasattr(PluginProtocol, 'cleanup')
    assert hasattr(PluginProtocol, 'resync')
