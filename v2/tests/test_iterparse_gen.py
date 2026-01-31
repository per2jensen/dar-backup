import xml.etree.ElementTree as ET
import pytest

pytestmark = pytest.mark.unit








xml_data = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>safe</root>"""

with open("xxe_class.xml", "w") as f:
    f.write(xml_data)

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

print("--- Testing DoctypeStripper ---")
try:
    stream = DoctypeStripper("xxe_class.xml")
    for _, elem in ET.iterparse(stream):
        print(f"Element: {elem.tag}")
    print("Success")
except Exception as e:
    print(f"Failed: {e}")