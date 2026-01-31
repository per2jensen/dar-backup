import xml.etree.ElementTree as ET
import os
import pytest

pytestmark = pytest.mark.unit






payload = """<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>\n<root>&xxe;</root>"""

with open("xxe.xml", "w") as f:
    f.write(payload)

print("--- Testing default parser ---")
try:
    for _, elem in ET.iterparse("xxe.xml"):
        if "root" in str(elem.text): # check if passwd content leaked (root user)
            print("VULNERABLE: Found 'root' in text")
        else:
            print(f"Text: {elem.text}")
except Exception as e:
    print(f"Error: {e}")

print("\n--- Testing parser.entity = {} ---")
try:
    parser = ET.XMLParser()
    parser.entity = {}
    for _, elem in ET.iterparse("xxe.xml", parser=parser):
        if "root" in str(elem.text):
            print("VULNERABLE: Found 'root' in text")
        else:
            print(f"Text: {elem.text}")
except Exception as e:
    print(f"Error: {e}")

