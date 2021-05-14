# metadefender_scan
---

This program allows to scan files and folders using MetaDefender server.


## Requirements

- Python>=3.6

## Installation

Install Python on target machine and execute following command to add required modules:
```
pip install -r requirements.txt
```


## CLI Arguments

Command short | Command long | Description | Default
:-- | :-- | :-- | :--
-r | --recursive | Scan files from subdirectories if specified file is a directory itself | False
-i | --extension-include | Specify comma-separated list of file extensions. Only files with specified extensions will be scanned | None
-e | --extension-exclude | Specify comma-separated list of file extensions. Files with specified extensions will not be scanned | None
-o | --output | Specify file which scanning results will be saved to | None
-s | --server | Specify URL of MetaDefender server | http://metadefender.example.com
-k | --api-key | Specify API Key for MetaDefender server | None
\- | --force | Send file to server even if there is cached result for this file | False
-h | --help | Print this help message | 
-j | --jobs | Specify how many concurrent jobs should be started. Works only if scanning directory | 5
-v | --verbose | Print what is currently being done to STDOUT | False

## Examples

Show help:
```
python3 metadefender_scan.py -h
```

General usage:
```
python3 metadefender_scan.py [OPTIONS] [FILES]
```

Scan files **test_file1.exe**, **test_file2.exe** and all files in test_dir:
```
python3 metadefender_scan.py -s http://metadefender.example.com test_file1.exe test_file2.exe test_dir
```

Scan files from **test_dir** and all subdirectories, without files with excension: __*.o__, __*.pyc__, __*.tmp__, __*.txt__, __*.doc__:
```
python3 metadefender_scan.py -s http://metadefender.example.com -r -e o,pyc,tmp,txt,doc test_dir
```

Scan only __*.exe__ files from **test_dir** directory and all subdirectories:
```
python3 metadefender_scan.py -s http://metadefender.example.com -r -i exe test_dir
```

Scan files **test_file1.exe**, **test_file2.exe** and save output to file **results.html**:
```
python3 metadefender_scan.py -s http://metadefender.example.com -o results.html test_file1.exe test_file2.exe test_dir
```


## TODO

- Add configuration file (ini/toml format)
- Add batch processing
- Add processing of files secured with passwords
- Test authentication (credentails/API key) - wasn't possible with sever I have access to
- Add changelog/release notes
- Add tests


## Author

mkot02
