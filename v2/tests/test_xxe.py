import xml.etree.ElementTree as ET
import pytest

pytestmark = pytest.mark.unit

payload = """<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<root>&xxe;</root>"""


def _write_xml(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


def test_xxe_default_parser(tmp_path):
    xml_path = _write_xml(tmp_path, "xxe.xml", payload)
    print("--- Testing default parser ---")
    try:
        for _, elem in ET.iterparse(xml_path):
            if "root" in str(elem.text):  # check if passwd content leaked (root user)
                print("VULNERABLE: Found 'root' in text")
            else:
                print(f"Text: {elem.text}")
    except Exception as e:
        print(f"Error: {e}")


def test_xxe_parser_entity_disabled(tmp_path):
    xml_path = _write_xml(tmp_path, "xxe.xml", payload)
    print("\n--- Testing parser.entity = {} ---")
    try:
        parser = ET.XMLParser()
        parser.entity = {}
        for _, elem in ET.iterparse(xml_path, parser=parser):
            if "root" in str(elem.text):
                print("VULNERABLE: Found 'root' in text")
            else:
                print(f"Text: {elem.text}")
    except Exception as e:
        print(f"Error: {e}")
