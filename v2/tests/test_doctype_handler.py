import xml.etree.ElementTree as ET
import pytest

pytestmark = pytest.mark.unit

xml_data = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>"""


def _write_xml(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


def test_doctype_handler_assignment(tmp_path):
    xml_path = _write_xml(tmp_path, "xxe_handler.xml", xml_data)
    print("--- Testing doctype handler assignment ---")
    try:
        parser = ET.XMLParser()

        def deny_doctype(name, pubid, system):
            print(f"Intercepted DOCTYPE: {name}")
            raise ValueError("DOCTYPE is forbidden")

        # Attempt to assign handler (Monkey patching? Or does it look for it?)
        parser.doctype = deny_doctype

        for _, elem in ET.iterparse(xml_path, parser=parser):
            print(f"Element: {elem.tag}")
    except Exception as e:
        print(f"Caught exception: {e}")
