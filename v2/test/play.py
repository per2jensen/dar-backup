import xml.etree.ElementTree as ET

xml_data="""<?xml version="1.0" ?>
<!DOCTYPE Catalog SYSTEM "dar-catalog.dtd">
<Catalog format="1.2">
<Directory name="tmp">
<Attributes data="referenced" metadata="absent" user="root" group="root" permissions=" drwxrwxrwt" atime="1719672702" mtime="1719672251" ctime="1719672251" />
	<Directory name="unit-test">
	<Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" drwxrwxr-x" atime="1719673420" mtime="1719673420" ctime="1719673420" />
		<Directory name="test_create_full_diff_incr_backup">
		<Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" drwxrwxr-x" atime="1719673420" mtime="1719673420" ctime="1719673420" />
			<Directory name="data">
			<Attributes data="referenced" metadata="absent" user="pj" group="pj" permissions=" drwxrwxr-x" atime="1719673420" mtime="1719673420" ctime="1719673420" />
				<File name="file3.txt" size="42 o" stored="42 o" crc="1324162c" dirty="no" sparse="no" delta_sig="no" patch_base_crc="" patch_result_crc="">
				<Attributes data="saved" metadata="absent" user="pj" group="pj" permissions=" -rw-rw-r--" atime="1719673420" mtime="1719673420" ctime="1719673420" />
				</File>
			</Directory>
		</Directory>
	</Directory>
</Directory>
</Catalog>
"""





# Function to recursively find <File> tags and build their full paths
def find_files_with_paths(element, current_path=""):
    files = []
    if element.tag == "Directory":
        current_path = f"{current_path}/{element.get('name')}"
    for child in element:
        if child.tag == "File":
            file_path = f"{current_path}/{child.get('name')}"
            files.append(file_path)
        elif child.tag == "Directory":
            files.extend(find_files_with_paths(child, current_path))
    return files


# Parse the XML data
root = ET.fromstring(xml_data)
# Extract full paths for all <File> elements
file_paths = find_files_with_paths(root)


def success():
	print("\033[1m\033[32mSUCCESS\033[0m")
	print("\033[1m\033[31mErrors\033[0m encountered")
# Print the full paths
#for path in file_paths:
#    print(path)


success()