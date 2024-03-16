import hashlib
import os
import ctypes
import sys
import xml.etree.ElementTree as ET

def load_iocs(ioc_file):
    ioc_signatures = set()
    tree = ET.parse(ioc_file)
    root = tree.getroot()
    ns = {'openioc': 'http://schemas.mandiant.com/2010/ioc'}
    for indicator in root.findall('.//openioc:IndicatorItem[@condition="is"]', ns):
        ioc = indicator.find('openioc:Content', ns).text
        ioc_signatures.add(ioc.strip())
    return ioc_signatures

def scan_file(file_path, ioc_signatures):
    with open(file_path, "rb") as f:
        file_content = f.read()
        file_hash = hashlib.md5(file_content).hexdigest()

    if file_hash in ioc_signatures:
        print(f"The file '{file_path}' matches an IOC and could be malicious.")
        delete_option = input("Do you want to delete this file? (yes/no): ").lower()
        if delete_option == "yes":
            os.remove(file_path)
            print(f"The file '{file_path}' has been deleted.")
    else:
        print(f"The file '{file_path}' is clean.")

def run_as_admin():
    if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)

def main():
    run_as_admin()

    ioc_file = "OpenIOC_file.xml"  # Path to the OpenIOC XML file
    ioc_signatures = load_iocs(ioc_file)

    while True:
        directory_path = input("Enter the directory path to scan (or type 'exit' to quit): ")
        if directory_path.lower() == 'exit':
            break
        if os.path.isdir(directory_path):
            for filename in os.listdir(directory_path):
                file_path = os.path.join(directory_path, filename)
                if os.path.isfile(file_path):
                    scan_file(file_path, ioc_signatures)
                else:
                    print(f"{file_path} is not a file.")
        else:
            print("Invalid directory path.")

if __name__ == "__main__":
    main()
