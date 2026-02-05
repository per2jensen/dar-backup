import xml.etree.ElementTree as ET
import pytest

pytestmark = pytest.mark.unit

xml_data = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>safe</root>"""


class DoctypeStripper:
    def __init__(self, path):
        self.f = open(path, "r", encoding="utf-8")
        self.buf = ""

    def read(self, n=-1):
        # Handle read-all case roughly (though iterparse shouldn't use it generally)
        if n is None or n < 0:
            # Fallback to reading everything, filtering lines
            out = []
            for line in self.f:
                if "<!DOCTYPE" not in line:
                    out.append(line)
            return "".join(out)

        while len(self.buf) < n:
            line = self.f.readline()
            if not line:
                break
            if "<!DOCTYPE" not in line:
                self.buf += line

        result, self.buf = self.buf[:n], self.buf[n:]
        return result


def _write_xml(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


def test_doctype_stripper(tmp_path):
    xml_path = _write_xml(tmp_path, "xxe_class.xml", xml_data)
    print("--- Testing DoctypeStripper ---")
    try:
        stream = DoctypeStripper(xml_path)
        for _, elem in ET.iterparse(stream):
            print(f"Element: {elem.tag}")
        print("Success")
    except Exception as e:
        print(f"Failed: {e}")
