#!/usr/bin/env python3
"""
webcve - A simple framework for sending test payloads for known web CVEs.
"""

import os
import sys
import json
import argparse
import requests
import urllib3
from termcolor import cprint


# suppress insecure warnings (urllib3):
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DETECTED_CODE = 406
TESTS_PATH = 'tests/'
CVE_TESTS = os.listdir(TESTS_PATH)
RESULTS = []

def get_data_file(localfile, mode='r'):
    """
    Get data file contents
    """
    with open(localfile, mode=mode) as datafile:
        contents = datafile.read()

    return contents

if __name__ == '__main__':
    PARSER = argparse.ArgumentParser(description='Web CVE Tests.')
    PARSER.add_argument('-v',
                        '--verbose',
                        help='Dsiplay verbose output',
                        default=False,
                        action="store_true")
    PARSER.add_argument('-u',
                        '--url',
                        help='Target URL to send payloads to, e.g. https://mytest-site.com.',
                        required=False)
    PARSER.add_argument('-s',
                        '--status-code',
                        help='The server response status code that indicates the payload was \
                              succesfully detected.',
                        default="403")
    PARSER.add_argument('-c',
                        '--cve',
                        help='Test specified CVE only, format: CVE-XXXX-XXXXX.')
    PARSER.add_argument('-g',
                        '--group',
                        help='Test group of CVEs (groups defined in groups.json). \
                              This will override --cve')
    PARSER.add_argument('-t',
                        '--type',
                        help='Test type of CVEs (types defined in groups.json). \
                              This will ovverride --group')
    PARSER.add_argument('-l',
                        '--list',
                        help='List available groups or types.',
                        choices=['group', 'type'])
    PARSER.add_argument('-j',
                        '--json',
                        help='Write output in JSON format to file.',)
    PARSER.add_argument('-i',
                        '--insecure',
                        help='Allow insecure connections (do not verify TLS certificates).',
                        action='store_false',
                        default=True)
    ARGS = PARSER.parse_args()

    BASE_URL = ARGS.url

    if ARGS.list is not None:
        if not os.path.isfile('groups.json'):
            cprint("groups.json not found!", "red")
            sys.exit(1)

        with open('groups.json') as f:
            GROUPS = json.load(f)

        DEDUP = []

        for group in GROUPS:
            if ARGS.list == 'group':
                value = group['name']
            if ARGS.list == 'type':
                value = group['type']

            if value not in DEDUP:
                print(value)

            DEDUP.append(value)

        sys.exit()

    if ARGS.status_code is not None:
        DETECTED_CODE = ARGS.status_code

    if ARGS.cve is not None:
        CVE_TESTS = [ARGS.cve]

    if ARGS.group is not None:
        CVE_TESTS.clear()

        if not os.path.isfile('groups.json'):
            cprint("groups.json not found!", "red")
            sys.exit(1)

        with open('groups.json') as f:
            GROUPS = json.load(f)

        for group in GROUPS:
            if group['name'] == ARGS.group.lower():
                CVE_TESTS.extend(group['cves'])

    if ARGS.type is not None:
        CVE_TESTS.clear()

        if not os.path.isfile('groups.json'):
            cprint("groups.json not found!", "red")
            sys.exit(1)

        with open('groups.json') as f:
            GROUPS = json.load(f)

        for group in GROUPS:
            if group['type'] == ARGS.type.lower():
                CVE_TESTS.extend(group['cves'])

    for name in CVE_TESTS:
        if ARGS.url is None:
            PARSER.print_help()
            print('webcve.py: error: the following arguments are required: -u/--url')
            sys.exit(1)

        description = ''
        reference = ''

        cprint("{}".format(name), "yellow")
        result = {}
        result[name] = []

        if ARGS.verbose is True:
            if os.path.isfile('tests/{}/description.txt'.format(name)):
                with open('tests/{}/description.txt'.format(name)) as f:
                    description = f.read()

                    cprint(description, "white")

        if not os.path.isfile('tests/{}/test.json'.format(name)):
            cprint("\tTests not found for {}".format(name), "red")

        else:
            with open('tests/{}/test.json'.format(name)) as f:
                tests = json.load(f)

            for test in tests:
                if test['Method'].upper() == 'POST':

                    if 'Data' in test:
                        data = test['Data']

                    if 'Data-File' in test:
                        data = get_data_file('tests/{}/{}'.format(name,
                                                                  test['Data-File']))

                    if 'Data-Binary-File' in test:
                        data = get_data_file('tests/{}/{}'.format(name,
                                                                  test['Data-Binary-File']), 'rb')

                    if 'File-Upload-File' in test:
                        data = get_data_file('tests/{}/{}'.format(name,
                                                                  test['File-Upload-File']))

                        response = requests.post('{}{}'.format(BASE_URL, test['URI']),
                                                 headers=test['Headers'],
                                                 files={'files[]': (test['File-Upload-Name'],
                                                                    data)},
                                                 allow_redirects=False,
                                                 verify=ARGS.insecure)
                    else:
                        response = requests.post('{}{}'.format(BASE_URL, test['URI']),
                                                 headers=test['Headers'],
                                                 data=data,
                                                 allow_redirects=False,
                                                 verify=ARGS.insecure)

                elif test['Method'].upper() == 'GET':

                    if 'Data-File' in test:
                        data = get_data_file('tests/{}/{}'.format(name, test['Data-File']))

                        response = requests.get('{}{}'.format(BASE_URL, test['URI']),
                                                headers=test['Headers'],
                                                data=data,
                                                allow_redirects=False,
                                                verify=ARGS.insecure)
                    else:
                        response = requests.get('{}{}'.format(BASE_URL, test['URI']),
                                                headers=test['Headers'],
                                                allow_redirects=False,
                                                verify=ARGS.insecure)

                if response.status_code == int(DETECTED_CODE):
                    cprint("\tTest passed ({})".format(response.status_code), "green")
                    result[name].append("Pass")
                else:
                    cprint("\tTest failed ({})".format(response.status_code), "red")
                    result[name].append("Fail")

            RESULTS.append(result)

    if ARGS.json is not None:
        with open(ARGS.json, "w") as outfile:
            json.dump(RESULTS, outfile)
