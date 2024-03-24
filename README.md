# Fluvver

![image](https://github.com/warber0x/Fluvver/assets/7810067/68defe8f-2af8-45ad-8077-ca4f49fa0597)

### Script Overview:

The provided script facilitates the extraction of pertinent information regarding the SDK and flutter engine utilized within Flutter mobile apps.

### Purpose:

This script was developed in response to the challenges encountered while attempting to reverse-engineer a Flutter mobile app. The primary aim was to find the specific SDK and Flutter engine versions employed. Additionally, it was necessary to circumvent SSL and accommodate varying architectures. The key objective was to identify the version details and conduct reconnaissance effectively.

### Utility:

While this script is intended for integration into another project, it may also prove beneficial as a standalone tool for individuals seeking insights into Flutter APKs and getting more info about its internals.

## How to use

```
pip install -r requirements.txt
python detect_versions.py <Flutter_mobile_app_file> [--without-libapp]
```

## Exceptions:
Some apps do not contain `libapp.so`. If you get this error:

![image](https://github.com/warber0x/Fluvver/assets/7810067/44eb3ab3-6e9f-45bc-9b54-015c78a43056)

Bypass it by adding the `--without-libapp` argument.

## Technical details
- Extract the snapshot_hash from libapp.so and libflutter.so.
- Extract the SHA hash in libflutter.so necessary to identify the engine release.
- Extract Dart SDK version.
- Detect if libapp.so and libflutter.so are from the same APK and have not been tampered with by comparing the snapshot hashes
- Detect Dart version in offline mode; otherwise, retrieve it using online mode.

## Additional Features:
- Detection of Boring SSL: The script can identify the presence of Boring SSL within the APK.

## To Do:
- [x] Check supported CPUs.
- [ ] Suuport IPA apps. 
- [x] Bypass libapp.so check

## Requirements:
- Rich
- Requests

## License

[MIT](LICENSE.md) © [warber0x](https://https://github.com/warber0x)
