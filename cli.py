#!/usr/bin/env python3

from cve_lookup import parse_dbs, get_package_dict, get_vulns
import argparse
import csv
import jinja2
import sys
import traceback


# NIST url to link to CVEs
NIST_URL = 'https://web.nvd.nist.gov/view/vuln/detail?vulnId={}'


def _main():
    """ Main entry point.
    """

    try:
        parser = argparse.ArgumentParser(description='Compare a list of packages to the NVD and generate a vulnerability report.')

        parser.add_argument('packages', help='The list of packages to scan for vulnerabilities.')
        parser.add_argument('cve_loc', help='The folder that holds the CVE XLM database files.', type=str)
        parser.add_argument('output', help='The output html file to write.')
        parser.add_argument('-f', '--format', help='The format of the package list.', choices=['swid', 'rpm', 'yocto', 'ls'])
        parser.add_argument('-t', '--severity_threshold', help='Value [0-10] over which CVEs will be considered important.', type=float, default=3)
        parser.add_argument('-i', '--ignore_file', help=('CSV containing a list of specific CVEs to ignore. '
                                                         'These CVEs will show up as ignored in the report.'))

        args = parser.parse_args()

        with open(args.packages) as ff:
            errors, packages = get_package_dict(ff.read(), args.format)

        root = parse_dbs(args.cve_loc)
        cves = get_vulns(packages, root)

        ignore_source = {}
        if args.ignore_file is not None:
            with open(args.ignore_file) as ff:
                # First column is CVE ID, second column is human readable description of mitigation
                # eg: CVE-2015-7696, Device shall never allow decompression of arbitrary zip files
                reader = csv.reader(ff)
                ignore_source = {rr[0]: rr[1] for rr in reader}

        high_vulns = []
        low_vulns = []
        ignored_vulns = []
        for package_name, info in cves.items():
            for ii in info:
                data = {
                    'id': ii['id'],
                    'package': package_name,
                    'severity': float(ii['impact']['baseMetricV2']['cvssV2']['baseScore']),
                    'published': ii['published'],
                    'link': NIST_URL.format(ii['id']),
                    'patch_available': ii['patch_available']
                }

                try:
                    data['description'] = ii['description']
                except TypeError:
                    # Sometimes there are multiple descriptions, just try to use the first one.
                    data['description'] = ii['desc']['descript'][0]['#text']
                except Exception:
                    data['description'] = ''

                if data['id'] in ignore_source:
                    data['ignored'] = True
                    data['mitigation'] = ignore_source[data['id']]
                    ignored_vulns.append(data)
                else:
                    if data['severity'] > args.severity_threshold:
                        high_vulns.append(data)
                    else:
                        low_vulns.append(data)

        for vuln_list in [high_vulns, low_vulns, ignored_vulns]:
            vuln_list.sort(key=lambda ii: ii['severity'], reverse=True)

        jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader('templates'),
                                       autoescape=jinja2.select_autoescape(['html', 'xml']))

        template = jinja_env.get_template('output.html')
        html = template.render(severity_threshold=args.severity_threshold,
                               high_vulns=high_vulns,
                               low_vulns=low_vulns,
                               ignored_vulns=ignored_vulns)

        with open(args.output, 'w') as ff:
            ff.write(html)

    except Exception:
        print('-' * 60)
        print('Runtime exception caught:')
        traceback.print_exc()
        return 1

    else:
        return 0


if __name__ == '__main__':
    """ Called if this script is invoked directly.
    """

    sys.exit(_main())
