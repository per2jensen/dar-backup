import xml.etree.ElementTree as ET

xml_data = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>"""

with open("xxe_handler.xml", "w") as f:
    f.write(xml_data)

print("--- Testing doctype handler assignment ---")
try:
    parser = ET.XMLParser()
    def deny_doctype(name, pubid, system):
        print(f"Intercepted DOCTYPE: {name}")
        raise ValueError("DOCTYPE is forbidden")
    
    # Attempt to assign handler (Monkey patching? Or does it look for it?)
    parser.doctype = deny_doctype
    
    for _, elem in ET.iterparse("xxe_handler.xml", parser=parser):
        print(f"Element: {elem.tag}")
except Exception as e:
    print(f"Caught exception: {e}")
