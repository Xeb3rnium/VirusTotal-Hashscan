# Application Security Assignment - Malicious File Detection Tool
This tool was an assignment for an AppSec module.
<br>
Python script that will generate SHA-256 hashes of files in a given directory and query them with VirusTotal


## How to use

### Install dependencies
```shell
pip install -r requirements.txt
```

### Usage
```shell
$ ./hashscan.py
```
User prompts will appear asking for directory path and a file wildcard, defaults are current directory and * all mask if backspace is entered

### Example
```shell
Enter directory path [.]: /home/user/Downloads/
Enter file wildcard [*]: *py


Scanning Directory: ████████████████████████████████ 100%
Querying VirusTotal: ████████████████████████████████ 100%


Malicious files detected


File Reports: 

EICAR TEST: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f		63/66
WannaCry: ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa		66/71
```
Note: VirusTotal scans can get very slow at one scan every 15seconds to comply with rate limits


## Platforms
 * OSX/Unix
 * Linux
 * Windows (May work on Powershell but probably breaks colours, better to use WSL)


## Python Compatibility
 * 3.x (recommended)
