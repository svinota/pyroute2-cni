from pyroute2_cni.request import CNIConfig, CNIInterface, CNIRequest


def test_request_defaults():
    req = CNIRequest()
    assert req.error == ''
    assert req.errno == 0
    assert req.netns == 0


def test_interface_model():
    iface = CNIInterface(name='eth0', mac='aa:bb:cc:dd:ee:ff')
    assert iface.name == 'eth0'


def test_config_model():
    cfg = CNIConfig(cniVersion='0.4.0')
    assert cfg.cniVersion == '0.4.0'
