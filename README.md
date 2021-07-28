# VT Tools
## vt-report.py
Query [VirusTotal](http://virustotal.com) for reports based on one or more hashes, either piped in from another command, as a set of hash values provided on the commandline, or by specifying a file containing hashes using the `--input <filename>` parameter. Output goes to stdout by default unless an output file is specified using `--output <filename>`.

**Note**: As free VirusTotal accounts have a 4 query per minute limitation queries are separated by a 16-second delay.

```
$ python vt-report.py --help
Usage: vt-report.py [OPTIONS] [HASHES]...

  Retrieve VirusTotal analysis information for a set of hash values.

Options:
  --infile TEXT   Input file containing hash values.
  --outfile TEXT  CSV output filename, default outfile.csv.
  --apikey TEXT   VirusTotal API key, default VTAPIKEY env var.
  --fast          Disable request throttling.
  --help          Show this message and exit.
```
