# VT Tools
VirusTotal Python tools

To use, first create `~/.yamjam/config.yaml` containing the following settings:

```
vt-tools:
    apikey: VT_API_key
```

## vt-report.py
Query [VirusTotal](http://virustotal.com) for reports based on one or more hashes, either piped in from another command, as a set of hash values provided on the commandline, or by specifying a file containing hashes using the `--input <filename>` parameter. Output goes to stdout by default unless an output file is specified using `--output <filename>`. 

**Note**: As free VirusTotal accounts have a 4 query per minute limitation queries are separated by a 16-second delay.

```
$ python vt-report.py --help
usage: vt-report.py [-h] [--input FINPUT] [--output FOUTPUT]
                    [hashes [hashes ...]]

VirusTotal report query based on one or more hash values.

positional arguments:
  hashes            hash values (MD5, SHA1, SHA256)

optional arguments:
  -h, --help        show this help message and exit
  --input FINPUT    input file containing hash values
  --output FOUTPUT  output file
```
