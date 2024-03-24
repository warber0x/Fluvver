import requests
import io
import struct
import zlib
import re
import zipfile
import argparse
import os

from rich.console import Console
from rich.table import Table
from rich import box

zip_file_url = "https://storage.googleapis.com/flutter_infra_release/flutter/{}/dart-sdk-windows-x64.zip"

def title():
    print("""
   ___ _                             
  / __\ |_   ___   ____   _____ _ __ 
 / _\ | | | | \ \ / /\ \ / / _ \ '__|
/ /   | | |_| |\ V /  \ V /  __/ |   
\/    |_|\__,_| \_/    \_/ \___|_|   
By TheRed0ne 2024 - Https://thered0ne.com                           
    """)

def extract_libs_from_apk(apk_file_path, lib_files):
    lib_contents = {}    
    with zipfile.ZipFile(apk_file_path, 'r') as apk_file:
        for file_info in apk_file.infolist():
            for lib_file in lib_files:
                if lib_file in file_info.filename:
                    with apk_file.open(file_info) as file:
                        lib_contents[lib_file] = file.read()
                        lib_files.remove(lib_file)
            if not lib_files:
                break

    return lib_contents

def get_arch(apk_file_path):
    arch_folders = ['armeabi-v7a', 'arm64-v8a', 'x86', 'x86_64']
    arch_list = []
    with zipfile.ZipFile(apk_file_path, 'r') as apk_file:
        file_list = apk_file.namelist()
        lib_directories = set(os.path.dirname(file) for file in file_list if file.startswith('lib/'))
        for arch in arch_folders:
            if any(arch in directory for directory in lib_directories):
                arch_list.append(arch)
    return arch_list

def check_urls(engine_hashes):
    for engine_hash in engine_hashes:
        response = requests.head(zip_file_url.format(engine_hash.decode('utf-8')))
        if response.status_code == 200:
            return engine_hash.decode('utf-8')
    return None

def is_boring_ssl_used(file_data):
    data = file_data
    match = re.findall(b'x509\.cc\x00', data)
    if match:
        return "Yes"
    return "No"

def extract_libapp_hashes(file_data):
    app_snapshot_hashes = re.findall(b'\x00([a-fA-F\d]{32})', file_data)
    return app_snapshot_hashes

def extract_libflutter_hashes(file_data):
        engine_sha_hashes = re.findall(b'\x00([a-f\\d]{40})(?=\x00)', file_data)
        snapshot_hashes = re.findall(b'\x00([a-fA-F\d]{32})\x00', file_data)
        return engine_sha_hashes, snapshot_hashes

def extract_info(apk_file, is_without_libapp=False):
    start_byte = 0 
    end_byte = 4096 
    lib_files = ['libapp.so', 'libflutter.so']

    lib_contents = extract_libs_from_apk(apk_file, lib_files)

    if not lib_contents:
        print("[Error] No libraries found")
        return None
    
    if is_without_libapp == False:
        if 'libapp.so' not in lib_contents:
            print("[Error] Is there lipapp.so in you APK ? try --without-libapp argument")
            return None
        
        app_snapshot_hash = extract_libapp_hashes(lib_contents.get('libapp.so'))
        if not app_snapshot_hash:
            print("[Error] No hash found in libapp !")
            return None
    
    engine_sha_hashes, libflutter_snapshot_hash = extract_libflutter_hashes(lib_contents.get('libflutter.so'))
    if not engine_sha_hashes:
        print("[Error] No hash found in libflutter.so!")
        return None
    
    if is_without_libapp == False:
        if app_snapshot_hash[0] != libflutter_snapshot_hash[0]:
            print("[Info] The libapp and libflutter are not from the same app. The engine version could not be correct !")
        
    valid_hash = check_urls(engine_sha_hashes)
    if valid_hash is None:
        print("[Info] This APK maybe was modified ! no valid hash found")
        return None

    dart_version = get_offline_dart_version(lib_contents.get('libflutter.so'))
    if dart_version:
        dart_revision = get_online_dart_version(zip_file_url.format(valid_hash), start_byte, end_byte, file_type='rev')
    else:
        dart_version, dart_revision = get_online_dart_version(zip_file_url.format(valid_hash), start_byte, end_byte, file_type='all')

    if isinstance(dart_version, bytes):
        dart_version = dart_version.decode('utf-8')

    can_by_bypassed = is_boring_ssl_used(lib_contents.get('libflutter.so'))

    if is_without_libapp == False:
        return dart_version, dart_revision.decode('utf-8'), app_snapshot_hash[0].decode('utf-8'), can_by_bypassed
    else:
        return dart_version, dart_revision.decode('utf-8'), None, can_by_bypassed

def get_offline_dart_version(libflutter_data):
    index = libflutter_data.find(b'(stable)')
    if index and index != -1:
        dart_version = re.sub(b'[^0-9.]', b'', libflutter_data[index-10:index])
        pattern = r'\b0*(\d+\.\d+\.\d+)\b'
        match = re.search(pattern, dart_version.decode('utf-8'))
        if match:
            dart_version = match.group(1)
        return dart_version
    return None

def get_online_dart_version(url, start_byte, end_byte, file_type='all'):

    dart_version = None
    dart_revision = None

    search_options = {
        'all': [b'revision', b'version'],
        'rev': [b'revision'],
        'ver': [b'version']
    }

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

        for option in search_options.get(file_type, []):
            if option in filename:
                filename = filename.strip()
                if option == b'revision' and file_type in ['all','rev']:
                    dart_revision = zlib.decompress(data, wbits=-zlib.MAX_WBITS).strip() # -zlib.MAX_WBITS => Automatic detection
                    if file_type == 'rev':
                        return dart_revision
                elif option == b'version' and file_type in ['all','ver']:
                    dart_version = zlib.decompress(data, wbits=-zlib.MAX_WBITS).strip() # -zlib.MAX_WBITS => Automatic detection
                    if file_type == 'ver':
                        return dart_version

        if file_type == 'all' and dart_version and dart_revision:
            return dart_version, dart_revision

    return None

def get_all_infos(url, dart_version, channel="stable"):
    json_response = requests.get(url)
    if json_response.status_code == 200:
        json_data = json_response.json()
        filtered_releases = [
            release for release in json_data['releases'] 
            if release['channel'] == channel and 
                (dart_version in release.get('dart_sdk_version', '') or 
                dart_version in release['version'])
            ]
        return filtered_releases
    else:
        print("No items found matching the criteria.")

def main():
    flutter_releases_url = "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json"

    parser = argparse.ArgumentParser(description="Process an APK file.")
    parser.add_argument("apk_file", help="Path to the APK file to process")
    parser.add_argument('--without-libapp', action='store_true', help="Exclude libapp.so")
    args = parser.parse_args()

    title()

    if args.apk_file is not None:
        result = extract_info(args.apk_file, args.without_libapp)

        if result is not None:
            dart_version, commit_id, snapshot_hash, can_be_bypassed = result
            releases = get_all_infos(flutter_releases_url, dart_version)
            if not releases:
                releases = get_all_infos(flutter_releases_url, dart_version, channel="beta")

            console = Console()
            table = Table(show_header=True, header_style="bold blue", box=box.ROUNDED)
    
            table.add_column("Engine Versions", style="dim", width=7, justify="left")
            table.add_column("Dart SDK Version", style="dim", width=20, justify="left")
            table.add_column("Channel", style="dim", width=7, justify="left")
            table.add_column("Archive", style="dim", width=55, justify="left")
            table.add_column("Possible SSL bypass ?", style="dim", width=8, justify="left")

            pattern = r'(\d+\.\d+\.\d+)'
            if releases:
                for release in releases:
                    match = re.search(pattern, release["version"])
                    if match:
                        engine_version = match.group(1)

                    table.add_row(
                        engine_version,
                        dart_version,
                        release["channel"],
                        release["archive"],
                        can_be_bypassed,
                    )
            else:
                table.add_row(
                        'Unknown',
                        dart_version,
                        'Unknown',
                        'Unknown',
                        can_be_bypassed,
                    )
            console.print(table)

            table = Table(show_header=True, header_style="bold blue", box=box.ROUNDED)
            table.add_column("Snapshot Hash", style="dim", width=40, justify="left")
            if not args.without_libapp:
                table.add_column("Engine SHA commit", style="dim", width=45, justify="left")
                table.add_row(snapshot_hash, commit_id)
            else:
                table.add_row(commit_id)
            console.print(table)

            table = Table(show_header=True, header_style="bold blue", box=box.ROUNDED)
            table.add_column("Supported CPUs", style="dim", width=20, justify="left")
            table.add_row(", ".join(get_arch(args.apk_file)))
            console.print(table)
    else:
        print("No APK file provided.")
        
if __name__ == "__main__":
    main()
