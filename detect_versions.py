import requests
import io
import struct
import zlib
import re
import zipfile
import argparse

from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text

start_byte = 0  # Replace with the starting byte of the range you want
end_byte = 4096 
lib_files = ['libapp.so', 'libflutter.so']
lib_folders = ['arm64-v8a','armeabi-v7a','x86_64']
zip_file_url = "https://storage.googleapis.com/flutter_infra_release/flutter/{}/dart-sdk-windows-x64.zip"
flutter_releases_url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json"

def title():
    print("""
   ___ _                             
  / __\ |_   ___   ____   _____ _ __ 
 / _\ | | | | \ \ / /\ \ / / _ \ '__|
/ /   | | |_| |\ V /  \ V /  __/ |   
\/    |_|\__,_| \_/    \_/ \___|_|   
By TheRed0ne 2024 - Https://thered0ne.com                           
    """)

def extract_libs_from_apk(apk_file_path, folder_names):
    lib_contents = {}
    lib_files_to_extract = {'libflutter.so', 'libapp.so'}
    
    with zipfile.ZipFile(apk_file_path, 'r') as apk_file:
        for file_info in apk_file.infolist():
            for folder_name in folder_names:
                if folder_name in file_info.filename:
                    for lib_file in lib_files_to_extract:
                        if lib_file in file_info.filename:
                            with apk_file.open(file_info) as file:
                                lib_contents[lib_file] = file.read()
                                lib_files_to_extract.remove(lib_file)  # Remove file from set
                                break
                    if not lib_files_to_extract:  # Break out of outer loop if all files are extracted
                        break
            if not lib_files_to_extract:  # Break out of outer loop if all files are extracted
                break

    return lib_contents

def check_urls(engine_hashes):
    global zip_file_url
    for engine_hash in engine_hashes:
        response = requests.head(zip_file_url.format(engine_hash.decode('utf-8')))
        if response.status_code == 200:
            return engine_hash.decode('utf-8')
    return None

def is_boring_ssl_used(file_data):
    data = file_data
    match = re.findall(b'x509\.cc\x00', data)
    if match:
        return True
    return False

def extract_libapp_hashes(file_data):
    app_snapshot_hashes = re.findall(b'\x00([a-fA-F\d]{32})', file_data)
    return app_snapshot_hashes

def extract_libflutter_hashes(file_data):
        engine_sha_hashes = re.findall(b'\x00([a-f\\d]{40})(?=\x00)', file_data)
        snapshot_hashes = re.findall(b'\x00([a-fA-F\d]{32})\x00', file_data)
        return engine_sha_hashes, snapshot_hashes

def extract_info(apk_file):
    lib_contents = extract_libs_from_apk(apk_file, lib_files)
    if not lib_contents:
        print("[Error] No libraries found")
        return None
        
    app_snapshot_hash = extract_libapp_hashes(lib_contents.get('libapp.so'))
    engine_sha_hashes, libflutter_snapshot_hash = extract_libflutter_hashes(lib_contents.get('libflutter.so'))

    if app_snapshot_hash[0] != libflutter_snapshot_hash[0]:
        print("[Info] The libapp and libflutter are not from the same app. The engine version could not be correct !")
        return None
        
    valid_hash = check_urls(engine_sha_hashes)

    if valid_hash is None:
        print("[Info] This APK maybe was patched ! no valid hash found")
        return None

    dart_version = get_offline_dart_version(lib_contents.get('libflutter.so'))
    revision = ''
    if not dart_version:
        dart_version, revision = get_online_dart_version(zip_file_url.format(valid_hash), start_byte, end_byte)

    can_by_bypassed = is_boring_ssl_used(lib_contents.get('libflutter.so'))

    return dart_version, revision, can_by_bypassed

def get_offline_dart_version(libflutter_data):
    index = libflutter_data.find(b'(stable)')

    if index and index != -1:
        dart_version = re.sub(b'[^0-9.]', b'', libflutter_data[index-10:index])
        return dart_version.decode('utf-8')
    return None

def get_online_dart_version(url, start_byte, end_byte):
    headers = {"Range": f"bytes={start_byte}-{end_byte}"}
    with requests.get(url, headers=headers, stream=True) as r:
        if "20" in str(r.status_code):  # Partial Content
            zip_data = io.BytesIO(r.content)
        else:
            return
        
    while zip_data.tell() < 4096:
        _, _, _, compMethod, _, _, _, compSize, _, filenameLen, extraLen = struct.unpack("<IHHHHHIIIHH", zip_data.read(30))

        filename = zip_data.read(filenameLen)
        if extraLen > 0:
            zip_data.seek(extraLen, io.SEEK_CUR)

        data = zip_data.read(compSize)
        if b'revision' in filename:
            filename = filename.strip()
            dart_revision = zlib.decompress(data, wbits=-zlib.MAX_WBITS).strip() # -zlib.MAX_WBITS => Automatic detection
        elif b'version' in filename:
            filename = filename.strip()
            dart_version = zlib.decompress(data, wbits=-zlib.MAX_WBITS).strip() # -zlib.MAX_WBITS => Automatic detection

    return dart_version.decode('utf-8'), dart_revision.decode('utf-8')

def get_all_infos(url, dart_version):
    json_response = requests.get(url)
    if json_response.status_code == 200:
        json_data = json_response.json()

        filtered_releases = [release for release in json_data['releases'] if release['channel'] == 'stable' and dart_version in release.get('dart_sdk_version', '')]
        if filtered_releases:
            return filtered_releases
    else:
        print("No items found matching the criteria.")

def main():
    title()

    parser = argparse.ArgumentParser(description="Process an APK file.")
    parser.add_argument("apk_file", help="Path to the APK file to process")

    args = parser.parse_args()

    if args.apk_file is not None:
        result = extract_info(args.apk_file)
        if result is not None:
            dart_version, commit_id, can_be_bypassed = result
            releases = get_all_infos(flutter_releases_url, dart_version)
            console = Console()
            table = Table(show_header=True, header_style="bold blue", box=box.ROUNDED)
    
            table.add_column("Engine Version", style="dim", width=7, justify="center")
            table.add_column("Dart SDK Version", style="dim", width=7, justify="center")
            table.add_column("Release Date", style="dim", width=28, justify="center")
            table.add_column("Archive", style="dim", width=48, justify="center")
            table.add_column("Possible SSL bypass ?", style="dim", width=8, justify="center")

            for index, release in enumerate(releases):
                last_index = len(releases) - 1
                is_last_element = index == last_index

                table.add_row(
                    release["version"],
                    release.get("dart_sdk_version", ""),
                    release["release_date"],
                    release["archive"],
                    str(can_be_bypassed) if is_last_element else "",
                )
            console.print(table)

    else:
        print("No APK file provided.")
        
if __name__ == "__main__":
    main()

