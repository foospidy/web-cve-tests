# web-cve-tests

[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)

The goal of this tool is to send PoC payloads to verify server-side attack detection solutions. If detected, the server side should return a specified HTTP status code.

__This tool is not intended to actually exploit the vulnerability or to test for the existence of the vulnerability.__

## Usage

Basic:

```shell
./webcve.py --url https://target-site.com
```

Specify detected response code (default is 403):

```shell
./webcve.py --url https://target-site.com --status-code 406
```

Verbose (output CVE descriptions):

```shell
./webcve.py --url https://target-site.com -v
```

Test a single CVE (with example output):

```shell
./webcve.py --url https://target-site.com --status-code 406 --cve CVE-2017-9791 -v
CVE-2017-9791
The Struts 1 plugin in Apache Struts 2.3.x might allow remote code execution
via a malicious field value passed in a raw message to the ActionMessage.
        Test passed (406)
        Test passed (406)
        Test passed (406)
        Test passed (406)
```

Test for a group of CVEs. Groups are defined in [groups.json](groups.json).

```shell
./webcve.py --url https://target-site.com --group struts
```

Test for a group type of CVEs. Types are defined in [groups.json](groups.json).

```shell
./webcve.py --url https://target-site.com --type cms
```

List available groups or types.

```shell
./webcve.py --list group
```

```shell
./webcve.py --list type
```

## Contributions

Pull requests are welcome. Please use the existing CVE directories as examples of how you should structure your submission.
