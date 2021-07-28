#!/usr/bin/env python3

import os
import re
import sys
import time
import requests
import csv
import click


class VTReport:
    """VirusTotal report object"""

    _VT_API_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
    _FIELDS = [
        'resource',
        'positives',
        'total',
        'scan_date',
        'md5',
        'sha1',
        'sha256',
        'permalink'
    ]

    def __init__(self, apikey, resource):
        self._apikey = apikey
        self._resource = resource
        self.update()

    def update(self):
        """Execute HTTP request and save response"""
        params = {
            'apikey': self._apikey,
            'resource': self._resource
        }
        self._response = requests.get(
            self._VT_API_REPORT_URL,
            params=params
        )

    @property
    def http_status_code(self):
        """Return the HTTP request status code"""
        return self._response.status_code

    @property
    def http_reason(self):
        """Return the HTTP request textual reason"""
        return self._response.reason

    @property
    def json(self):
        """Return the response JSON data"""
        return self._response.json()

    @property
    def resource(self):
        """Return the resource"""
        return self._resource

    @resource.setter
    def resource(self, resource):
        """Set the resource value and update"""
        self._resource = resource
        self.update()

    def __repr__(self):
        return "VTReport()"

    def __str__(self):
        str_ = ""
        json = self._response.json()
        detectionfmt = "{key}: {positives}/{total}" + os.linesep
        standardfmt = "{key}: {value}" + os.linesep
        for field in self._FIELDS:
            if field == 'positives':
                str_ += detectionfmt.format(
                    key=field,
                    positives=json['positives'],
                    total=json['total']
                )
            elif field != 'total':
                str_ += standardfmt.format(
                    key=field,
                    value=json[field]
                )
        return str_


def get_reports(hashes, apikey, fast):
    """Retrieve VT data for a list of hashes"""
    reports = []
    delay = 1 if fast else 16

    for idx, h in enumerate(hashes):
        print("{}/{} - {}".format(idx + 1, len(hashes), h), end="", flush=True)

        # Skip the request if the hash is invalid
        if not validate_hash(h):
            print(" (Invalid hash, skipping)")
            continue

        report = VTReport(apikey, h)

        if report.http_status_code == 200:
            if report.json['response_code'] == 1:
                reports.append(report)
                print(' (OK)')
            else:
                print(" ({})".format(report.json['verbose_msg']))
        else:
            print(" ({}: {})".format(
                report.http_status_code,
                report.http_reason
            ))

        # Sleep
        if idx < len(hashes) - 1:
            countdown(delay, 'Sleeping: ')
        else:
            print('')

    return reports


def read_hash_from_file(fname):
    """Read hashes from a file"""
    file_hashes = []

    try:
        if fname is not None:
            with open(fname) as f:
                file_hashes = f.read().splitlines()
    except IOError as e:
        print("I/O error({0}): {1}".format(e.errno, e.strerror))

    return file_hashes


def read_hash_from_stdin():
    """Read hashes from a piped input"""
    piped_hashes = []

    if not sys.stdin.isatty():
        for line in sys.stdin.readlines():
            piped_hashes.append(line.strip())

    return piped_hashes


def validate_hash(h):
    """Validate hash value and return hash type"""
    hash_type = None
    if re.match(r'^[a-fA-F0-9]{32,64}$', h):
        if len(h) == 32:
            hash_type = "MD5"
        elif len(h) == 40:
            hash_type = "SHA1"
        elif len(h) == 64:
            hash_type = "SHA256"
    return hash_type


def output_reports(reports, filename=None):
    """Print reports to stdout or save to filename"""
    if filename is None:
        for report in reports:
            print(report)
    else:
        headers = [
            'resource',
            'positives',
            'total',
            'scan_date',
            'md5',
            'sha1',
            'sha256',
            'permalink'
        ]
        f = open(filename, "w")
        writer = csv.writer(f)
        writer.writerow(headers)
        for report in reports:
            row = []
            for header in headers:
                row.append(report.json[header])
            writer.writerow(row)
        f.close()


def countdown(t, label):
    """Countdown timer with label"""
    while t:
        mins, secs = divmod(t, 60)
        timeformat = '{}{:02d}:{:02d}'.format(label, mins, secs)
        print(timeformat, end='\r')
        time.sleep(1)
        t -= 1


@click.command()
@click.argument('hashes', nargs=-1)
@click.option('--infile', help='Input file containing hash values.')
@click.option('--outfile', default='output.csv', help='CSV output filename, default outfile.csv.')
@click.option('--apikey', envvar='VTAPIKEY', help='VirusTotal API key, default VTAPIKEY env var.')
@click.option('--fast', is_flag=True, help='Disable request throttling.')
def app(hashes, infile, outfile, apikey, fast):
    """Retrieve VirusTotal analysis information for a set of hash values."""
    if not apikey:
        raise Exception('Error: no VirusTotal API key provided.')

    # Build hash list and remove empty strings and duplicates
    hashlist = list(hashes)
    hashlist.extend(read_hash_from_stdin())
    hashlist.extend(read_hash_from_file(infile))
    hashlist = list(filter(None, hashlist))
    hashlist = list(dict.fromkeys(hashlist))

    # Get VirusTotal reports
    if len(hashlist) > 0:
        reports = get_reports(hashlist, apikey, fast)
        output_reports(reports, outfile)
    else:
        print('No hash values provided.')


if __name__ == '__main__':
    app()
