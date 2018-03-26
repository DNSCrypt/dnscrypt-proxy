#! /usr/bin/env python

# run with python generate-domains-blacklist.py > list.txt.tmp && mv -f list.txt.tmp list

import argparse
import re
import sys
import urllib2


def parse_list(content, trusted=False):
    rx_comment = re.compile(r'^(#|$)')
    rx_inline_comment = re.compile(r'\s*#\s*[a-z0-9-].*$')
    rx_u = re.compile(r'^@*\|\|([a-z0-9.-]+[.][a-z]{2,})\^?(\$(popup|third-party))?$')
    rx_l = re.compile(r'^([a-z0-9.-]+[.][a-z]{2,})$')
    rx_h = re.compile(r'^[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}\s+([a-z0-9.-]+[.][a-z]{2,})$')
    rx_mdl = re.compile(r'^"[^"]+","([a-z0-9.-]+[.][a-z]{2,})",')
    rx_b = re.compile(r'^([a-z0-9.-]+[.][a-z]{2,}),.+,[0-9: /-]+,')
    rx_dq = re.compile(r'^address=/([a-z0-9.-]+[.][a-z]{2,})/.')
    rx_trusted = re.compile(r'^([*a-z0-9.-]+)$')

    names = set()
    rx_set = [rx_u, rx_l, rx_h, rx_mdl, rx_b, rx_dq]
    if trusted:
        rx_set = [rx_trusted]
    for line in content.splitlines():
        line = str.lower(str.strip(line))
        if rx_comment.match(line):
            continue
        line = rx_inline_comment.sub('', line)
        for rx in rx_set:
            matches = rx.match(line)
            if not matches:
                continue
            name = matches.group(1)
            names.add(name)
    return names


def load_from_url(url):
    sys.stderr.write("Loading data from [{}]\n".format(url))
    req = urllib2.Request(url)
    trusted = False
    if req.get_type() == "file":
        trusted = True
    response = None
    try:
        response = urllib2.urlopen(req, timeout=int(args.timeout))
    except urllib2.URLError as err:
        raise Exception("[{}] could not be loaded: {}\n".format(url, err))
    if trusted is False and response.getcode() != 200:
        raise Exception("[{}] returned HTTP code {}\n".format(url, response.getcode()))
    content = response.read()

    return (content, trusted)


def name_cmp(name):
    parts = name.split(".")
    parts.reverse()
    return str.join(".", parts)


def has_suffix(names, name):
    parts = str.split(name, ".")
    while parts:
        parts = parts[1:]
        if str.join(".", parts) in names:
            return True

    return False


def whitelist_from_url(url):
    if not url:
        return set()
    content, trusted = load_from_url(url)

    return parse_list(content, trusted)


def blacklists_from_config_file(file, whitelist, time_restricted_url, ignore_retrieval_failure):
    blacklists = {}
    whitelisted_names = set()
    all_names = set()
    unique_names = set()

    # Load conf & blacklists
    with open(file) as fd:
        for line in fd:
            line = str.strip(line)
            if str.startswith(line, "#") or line == "":
                continue
            url = line
            try:
                content, trusted = load_from_url(url)
                names = parse_list(content, trusted)
                blacklists[url] = names
                all_names |= names
            except Exception as e:
                sys.stderr.write(e.message)
                if not ignore_retrieval_failure:
                    exit(1)

    # Time-based blacklist
    if time_restricted_url and not re.match(r'^[a-z0-9]+:', time_restricted_url):
        time_restricted_url = "file:" + time_restricted_url

    if time_restricted_url:
        time_restricted_content, trusted = load_from_url(time_restricted_url)
        time_restricted_names = parse_list(time_restricted_content)

        if time_restricted_names:
            print("########## Time-based blacklist ##########\n")
            for name in time_restricted_names:
                print(name)

        # Time restricted names should be whitelisted, or they could be always blocked
        whitelisted_names |= time_restricted_names

    # Whitelist
    if whitelist and not re.match(r'^[a-z0-9]+:', whitelist):
        whitelist = "file:" + whitelist

    whitelisted_names |= whitelist_from_url(whitelist)

    # Process blacklists
    for url, names in blacklists.items():
        print("\n\n########## Blacklist from {} ##########\n".format(url))
        ignored, whitelisted = 0, 0
        list_names = list()
        for name in names:
            if has_suffix(all_names, name) or name in unique_names:
                ignored = ignored + 1
            elif has_suffix(whitelisted_names, name) or name in whitelisted_names:
                whitelisted = whitelisted + 1
            else:
                list_names.append(name)
                unique_names.add(name)

        list_names.sort(key=name_cmp)
        if ignored:
            print("# Ignored duplicates: {}\n".format(ignored))
        if whitelisted:
            print("# Ignored entries due to the whitelist: {}\n".format(whitelisted))
        for name in list_names:
            print(name)


argp = argparse.ArgumentParser(description="Create a unified blacklist from a set of local and remote files")
argp.add_argument("-c", "--config", default="domains-blacklist.conf",
    help="file containing blacklist sources")
argp.add_argument("-w", "--whitelist", default="domains-whitelist.txt",
    help="file containing a set of names to exclude from the blacklist")
argp.add_argument("-r", "--time-restricted", default="domains-time-restricted.txt",
    help="file containing a set of names to be time restricted")
argp.add_argument("-i", "--ignore-retrieval-failure", action='store_true',
    help="generate list even if some urls couldn't be retrieved")
argp.add_argument("-t", "--timeout", default=30,
    help="URL open timeout")
args = argp.parse_args()

conf = args.config
whitelist = args.whitelist
time_restricted = args.time_restricted
ignore_retrieval_failure = args.ignore_retrieval_failure

blacklists_from_config_file(conf, whitelist, time_restricted, ignore_retrieval_failure)
