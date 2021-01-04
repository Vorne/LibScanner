import sys
import re
from distutils.version import LooseVersion
from collections import defaultdict

# preload XML
import defusedxml.cElementTree as DET
import glob
import os
import json


xmlstring = []


def parse_dbs(folder):
    """
    parse the XML dbs and build an in-memory lookup
    :param folder: the folder full of *.xml files
    :return:
    """
    root = dict()
    for filename in glob.glob(folder + '/*.json'):
        with open(filename, encoding='utf-8') as ff:
            cve_dict = json.load(ff)

            print("Processing file " + filename)

            for cve_item in cve_dict['CVE_Items']:
                patch_available = False
                try:
                    refs = cve_item['cve']['references']['reference_data']
                    for reference in refs:
                        for tag in reference['tags']:
                            if tag == 'Patch':
                                patch_available = True
                except Exception:
                    pass

                vuln = {
                    'details': {
                        'id': str(cve_item['cve']['CVE_data_meta']['ID']),
                        'description': cve_item['cve']['description']['description_data'][0]['value'],
                        'impact': cve_item['impact'],
                        'published': cve_item['publishedDate'],
                        'patch_available': patch_available
                    },
                    'vers': [],
                }

                # Figure out vulnerable versions.
                for node in cve_item['configurations']['nodes']:
                    for cpe in node.get('cpe_match', []):
                        if cpe['vulnerable'] is True:
                            cpe23 = cpe['cpe23Uri'].split(':')
                            # vendor = cpe23[3]
                            product = cpe23[4]
                            version = cpe23[5]

                            if product not in root:
                                root[product] = []

                            if version != '*' and version != '-':
                                # Single version number
                                vuln['vers'].append({'num': version, 'prev': False})
                            if 'versionEndIncluding' in cpe:
                                # Inclusive end version (like <= 1.2.3)
                                vuln['vers'].append({'num': cpe['versionEndIncluding'], 'prev': True})

                root[product].append(vuln)

    return root


def get_packages_swid(package_list):
    """
    Get the packages from a swid string
    :param package_strs:
    :return:
    """
    packages = defaultdict(set)
    errors = []
    for xml_doc in package_list.split("\n"):
        try:
            # remove the <? ?> if any
            xml_doc = re.sub('<\?[^>]+\?>', '', xml_doc)
            # use DET since this is untrusted data
            data = DET.fromstring(xml_doc)
            name, version = data.attrib['name'], data.attrib['version']
            version = version.split("-")[0]
            packages[name].add(version)

        except Exception as e:
            errors.append(str(e))

    return errors, packages


def get_packages_rpm(package_list):
    """
    Get the packages from an rpm string
    :param package_strs:
    :return:
    """
    package_strs = package_list.split("\n")
    packages = defaultdict(set)
    errors = []
    for x in package_strs:
        m = re.search(r'(.*/)*(.*)-(.*)-(.*?)\.(.*)', x)
        if m:
            (path, name, version, release, platform) = m.groups()
            packages[name].add(version)
            # print "\t".join([path, name, verrel, version, release, platform])
        else:
            errors.append('ERROR: Invalid name: %s\n' % x)

    return errors, packages


def get_packages_yocto(package_list):
    """ Get packages from a Bitbake build history, which look like
        systemd_1:242+0+07f0549ffe-r0_armhf.deb
    """

    package_strs = package_list.split("\n")
    packages = defaultdict(set)
    errors = []

    for ii in package_strs:

        # (.*/)*(.*?)_    Grab everything up to the first underscore (e.g., "" and "systemd")
        #                 Anything before the last / is a path, the rest is the name
        # (?:[0-9]+:)?    Non-capturing group that ignores "Package Epoch" (e.g., "1:")
        # (.?)            Version string (e.g., "242")
        # (?:\+.*)?       Non-capturing group for optional patch commits (e.g., "+0+07f0549ffe")
        # -(r[0-9]+)_     Release number (e.g., "r0")
        # ([^\.]*).(.*)   Platform and file extension (e.g., "armhf" and "deb")
        mm = re.search(r'(.*/)*(.*?)_(?:[0-9]+:)?(.*?)(?:\+.*)?-(r[0-9.]+)_([^\.]*).(.*)', ii)
        if mm:
            path, name, version, release, platform, extension = mm.groups()
            packages[name].add(version)
        else:
            errors.append('ERROR: Invalid name: {}\n'.format(ii))

    return errors, packages


def get_packages_ls(package_list):
    """
    Get the packages from a string generated by ls in /lib or /usr/lib
    :param package_list:
    :return:
    """
    package_strs = re.split(r"[\t\n ]+", package_list)
    packages = defaultdict(set)
    errors = []
    for x in package_strs:
        m = re.search(r'(.+)\.so\.([\d\.]+).*', os.path.basename(x))
        if m:
            (name, version) = m.groups()
            # remove 'lib' prefix
            if name.startswith("lib"):
                name = name[3:]
            packages[name].add(version)

            print(name, version)
            # print "\t".join([path, name, verrel, version, release, platform])
        else:
            errors.append('ERROR: Invalid name: %s\n' % x)

    return errors, packages


def get_packages_wmic(package_list):
    """
    Get packages from a windows system using wmic
    :param package_lis:
    :return:
    """
    package_strs = re.split(r"\r?\n+", package_list)
    packages = defaultdict(set)
    errors = []

    def add_package(name, version):
        """
        Some packages are labeled in the NVD by package name WITHOUT the vendor name prepended
        but wmic, gives us the full package name with the Vendor name (e.g. we're given 'Adobe Flash Player' and the
        NVD wants 'flash_player'.

        TODO: Maybe also look at CPE? That could solve a lot of these issues with naming

        :param packages:
        :param name:
        :param version:
        :return:
        """
        # add the name itself
        packages[name].add(version)
        # now try and trip out vendor name
        try:
            # vendors always put their name first because they're egotistical like that
            vendor, stripped_name = name.split(" ", 1)
            # replace space with _, everything to lowercase and trim it
            stripped_name = stripped_name.strip().lower().replace(" ", "_")
            packages[stripped_name].add(version)
        except ValueError:  # thrown if there was <2 words in the string
            pass

    for line in package_strs:
        try:
            columns = line.split(",")

            name, version = columns[1].strip(), columns[5]
            # remove any version numbers from name
            # TODO: Sometimes the version number pulled from here is different from the one reported
            # TODO: Let's include both right now, just in case
            version_re = re.search(r'([0-9.]+)\W*$', name)
            if version_re is not None:
                other_version = version_re.groups()[0]
                name = re.sub(r'[0-9.]+\W*$', '', name).rstrip()
                add_package(name, other_version)

            add_package(name, version)
        except Exception as e:
            print(e)
            errors.append('ERROR: Invalid line: %s\n' % line)

    print(packages)
    return errors, packages


formats = {"swid": get_packages_swid, "rpm": get_packages_rpm, "yocto": get_packages_yocto,
           "ls": get_packages_ls, "wmic": get_packages_wmic}


def get_package_dict(package_list, list_format=None):
    """
    Get the packages from the string
    :param package_list:
    :param list_format: The format of package_list
    :return:
    """
    # strip extraneous whitespace
    package_list = package_list.strip()
    # if format is none, try and auto-detect
    if list_format is None:
        # if we're XML, then we're probably swid
        if package_list.startswith("<?xml"):
            return get_packages_swid(package_list)
        # if the output is text, followed by comma, then more text, it's probably
        # output from wmic (see http://helpdeskgeek.com/how-to/generate-a-list-of-installed-programs-in-windows/)
        elif re.match(r'[a-zA-Z0-9_]+,+[a-zA-Z0-9_]+,', package_list):
            return get_packages_wmic(package_list)
        # if it starts with a /, then it's probably a dump from ls
        elif package_list.startswith("/"):
            return get_packages_ls(package_list)
        else:
            return get_packages_rpm(package_list)

    else:
        return formats[list_format](package_list)


def get_vulns(packages, root):
    """
    Get the vulns from a list of packages returned by get_package_dict()
    :param packages:
    :return:
    """
    result = defaultdict(list)

    for name, installed_vers in packages.items():
        if name in root:
            prod = root[name]
            for vuln in prod:
                reported = False
                for v in vuln['vers']:
                    if reported is True:
                        # We only want to report each vulnerability once, no matter how many
                        # vulnerable versions there are in the list.
                        break

                    version_number, prev = v['num'], v['prev']
                    loose_version_number = LooseVersion(version_number)
                    intersection = set()
                    for iv in installed_vers:
                        try:
                            if iv == version_number or (prev and LooseVersion(iv) <= loose_version_number):
                                intersection.add(iv)
                        except Exception:
                            print('Error parsing version for package.', file=sys.stderr)
                            print('    name: {}'.format(prod), file=sys.stderr)
                            print('    Installed Version: {}'.format(installed_vers), file=sys.stderr)

                        if len(intersection) > 0:
                            si = ' - ' + ','.join(intersection)
                            result[name + si].append(vuln['details'])
                            reported = True

    return result
