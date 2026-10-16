import pytest

from huawei_tower.modem.errors import ModemParseError
from huawei_tower.modem.xmlutil import child_text, element_to_dict, parse_xml


def test_parse_sanitized_device_fixture():
    root = parse_xml(
        "<response><DeviceName>H158-381</DeviceName><ProductFamily>LTE</ProductFamily></response>"
    )
    assert child_text(root, "DeviceName") == "H158-381"
    assert element_to_dict(root) == {"DeviceName": "H158-381", "ProductFamily": "LTE"}


def test_repeated_xml_tags_become_lists():
    root = parse_xml("<response><band>n78</band><band>B3</band></response>")
    assert element_to_dict(root) == {"band": ["n78", "B3"]}


def test_invalid_xml_fails_closed():
    with pytest.raises(ModemParseError):
        parse_xml("<response>")
