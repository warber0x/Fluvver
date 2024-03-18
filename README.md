# Fluvver

![image](https://github.com/warber0x/Fluvver/assets/7810067/917ce9e2-85b2-4003-bad8-c2c897443a26)

### Script Overview:

The provided script facilitates the extraction of pertinent information regarding the SDK and flutter engine utilized within Flutter APKs.

### Purpose:

This script was developed in response to the challenges encountered while attempting to reverse-engineer a Flutter APK. The primary aim was to find the specific SDK and Flutter engine versions employed. Additionally, it was necessary to circumvent SSL and accommodate varying architectures. The key objective was to identify the version details and conduct reconnaissance effectively.

### Utility:

While this script is intended for integration into another project, it may also prove beneficial as a standalone tool for individuals seeking insights into Flutter APKs and getting more info about its internals.



## How to use

```
pip install -m requirements.txt
python detect_versions.py <Flutter APK File>
```

## Technical details
- Extract the snapshot_hash from libapp.so and libflutter.so.
- Extract the SHA hash in libflutter.so necessary to identify the engine release.
- Extract Dart SDK version.
- Detect if libapp.so and libflutter.so are from the same APK and have not been tampered with by comparing the snapshot hashes
- Detect Dart version in offline mode; otherwise, retrieve it using online mode.

## Additional Features:

- Detection of Boring SSL: The script can identify the presence of Boring SSL within the APK.
- Detection of Non-Genuine Flutter APKs: Certain APKs may be tampered with, resulting in a differences between the snapshot_hash values in libapp.so and libflutter.so, compared to those utilized by the Dart SDK and Flutter Engine. The script can automatically detect such anomalies by identifying invalid hashes.

## License

[MIT](LICENSE.md)
