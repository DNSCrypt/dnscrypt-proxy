#! /usr/bin/env python

# Use the following command ensure the right encoding:
# python generate-domains-blacklist.py -o list.txt.tmp && mv -f list.txt.tmp list

import argparse
import re
import sys

try:
    import urllib2 as urllib

    URLLIB_NEW = False
except (ImportError, ModuleNotFoundError):
    import urllib.request as urllib
    from urllib.request import Request

    URLLIB_NEW = True


def parse_time_restricted_list(content):
    rx_comment = re.compile(r"^(#|$)")
    rx_inline_comment = re.compile(r"\s*#\s*[a-z0-9-].*$")
    rx_trusted = re.compile(r"^([*a-z0-9.-]+)\s*(@\S+)?$")

    names = set()
    time_restrictions = {}
    rx_set = [rx_trusted]
    for line in content.splitlines():
        line = str.lower(str.strip(line))
        if rx_comment.match(line):
            continue
        line = rx_inline_comment.sub("", line)
        for rx in rx_set:
            matches = rx.match(line)
            if not matches:
                continue
            name = matches.group(1)
            names.add(name)
            time_restriction = matches.group(2)
            if time_restriction:
                time_restrictions[name] = time_restriction
    return names, time_restrictions


def parse_trusted_list(content):
    names, _time_restrictions = parse_time_restricted_list(content)
    time_restrictions = {}
    return names, time_restrictions


def parse_list(content, trusted=False):
    rx_comment = re.compile(r"^(#|$)")
    rx_inline_comment = re.compile(r"\s*#\s*[a-z0-9-].*$")
    rx_u = re.compile(
        r"^@*\|\|([a-z0-9][a-z0-9.-]*[.][a-z]{2,})\^?(\$(popup|third-party))?$")
    rx_l = re.compile(r"^([a-z0-9][a-z0-9.-]*[.][a-z]{2,})$")
    rx_h = re.compile(
        r"^[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}\s+([a-z0-9][a-z0-9.-]*[.][a-z]{2,})$"
    )
    rx_mdl = re.compile(r'^"[^"]+","([a-z0-9][a-z0-9.-]*[.][a-z]{2,})",')
    rx_b = re.compile(r"^([a-z0-9][a-z0-9.-]*[.][a-z]{2,}),.+,[0-9: /-]+,")
    rx_dq = re.compile(r"^address=/([a-z0-9][a-z0-9.-]*[.][a-z]{2,})/.")

    if trusted:
        return parse_trusted_list(content)

    names = set()
    time_restrictions = {}
    rx_set = [rx_u, rx_l, rx_h, rx_mdl, rx_b, rx_dq]
    for line in content.splitlines():
        line = str.lower(str.strip(line))
        if rx_comment.match(line):
            continue
        line = rx_inline_comment.sub("", line)
        for rx in rx_set:
            matches = rx.match(line)
            if not matches:
                continue
            name = matches.group(1)
            names.add(name)
    return names, time_restrictions


# basic check if the line contains any regex specific char
def is_regex(line):
    regex_chars = "*[]?}{"
    return any(char in line for char in regex_chars)


def parse_regex(names):
    regexes = set()
    for line in names:
        # skip lines without regex characters:
        if not is_regex(line):
            continue
        # convert to python regex:
        line=line.replace(".", "\.")
        line=line.replace("*", ".*")
        line = "^"+line+"$"
        # check if resulting regex is valid:
        try:
            if re.compile(line):
                regexes.add(line)
        except re.error:
            sys.stderr.write("Invalid regex: {} [{}]\n".format(line, re.error))
            continue
    return regexes


def print_restricted_name(name, time_restrictions):
    if name in time_restrictions:
        print("{}\t{}".format(name, time_restrictions[name]))
    else:
        print(
            "# ignored: [{}] was in the time-restricted list, "
            "but without a time restriction label".format(name)
        )


def load_from_url(url):
    sys.stderr.write("Loading data from [{}]\n".format(url))
    req = urllib.Request(url=url, headers={"User-Agent": "dnscrypt-proxy"})
    trusted = False

    if URLLIB_NEW:
        req_type = req.type
    else:
        req_type = req.get_type()
    if req_type == "file":
        trusted = True

    response = None
    try:
        response = urllib.urlopen(req, timeout=int(args.timeout))
    except urllib.URLError as err:
        raise Exception("[{}] could not be loaded: {}\n".format(url, err))
    if trusted is False and response.getcode() != 200:
        raise Exception("[{}] returned HTTP code {}\n".format(
            url, response.getcode()))
    content = response.read()
    if URLLIB_NEW:
        content = content.decode("utf-8", errors="replace")

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


# check if a line matches with any of the collected regexes:
def covered_by_regex(line, regexes):

    # only check lines that aren't regexes themselves:
    if not is_regex(line):
        for regex in regexes:
            if re.match(regex, line):
                return True

    return False


def whitelist_from_url(url):
    if not url:
        return set()
    content, trusted = load_from_url(url)

    names, _time_restrictions = parse_list(content, trusted)
    return names


def blacklists_from_config_file(
    file, whitelist, time_restricted_url, ignore_retrieval_failure, output_file
):
    blacklists = {}
    whitelisted_names = set()
    all_regexes = set()
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
                names, _time_restrictions = parse_list(content, trusted)
                blacklists[url] = names
                all_names |= names
                all_regexes |= parse_regex(names)

            except Exception as e:
                sys.stderr.write(str(e))
                if not ignore_retrieval_failure:
                    exit(1)

    # Time-based blacklist
    if time_restricted_url and not re.match(r"^[a-z0-9]+:", time_restricted_url):
        time_restricted_url = "file:" + time_restricted_url

    if time_restricted_url:
        time_restricted_content, _trusted = load_from_url(time_restricted_url)
        time_restricted_names, time_restrictions = parse_time_restricted_list(
            time_restricted_content
        )

        if time_restricted_names:
            print("########## Time-based blacklist ##########\n")
            for name in time_restricted_names:
                print_restricted_name(name, time_restrictions)

        # Time restricted names should be whitelisted, or they could be always blocked
        whitelisted_names |= time_restricted_names

    # Whitelist
    if whitelist and not re.match(r"^[a-z0-9]+:", whitelist):
        whitelist = "file:" + whitelist

    whitelisted_names |= whitelist_from_url(whitelist)
    
    # redirect output to output_file if provided
    output = StringIO() if output_file else sys.stdout

    # Process blacklists
    for url, names in blacklists.items():
        print("########## Blacklist from {} ##########\n".format(url), file=output)
        ignored, whitelisted = 0, 0
        list_names = list()
        for name in names:
            if has_suffix(all_names, name) or name in unique_names or covered_by_regex(name, all_regexes):
                ignored = ignored + 1
            elif has_suffix(whitelisted_names, name) or name in whitelisted_names:
                whitelisted = whitelisted + 1
            else:
                list_names.append(name)
                unique_names.add(name)

        list_names.sort(key=name_cmp)
        if ignored:
            print("# Ignored duplicates: {}\n".format(ignored), file=output)
        if whitelisted:
            print("# Ignored entries due to the whitelist: {}\n".format(whitelisted), file=output)
        for name in list_names:
            print(name, file=output)
        print("\n\n", file=output)
        
    # if provided, save content from output buffer to file all at once
    if output_file:
        f = open(output_file, "w", encoding='utf8')
        f.write(output.getvalue())
        f.close()
        output.close()


argp = argparse.ArgumentParser(
    description="Create a unified blacklist from a set of local and remote files"
)
argp.add_argument(
    "-c",
    "--config",
    default="domains-blacklist.conf",
    help="file containing blacklist sources",
)
argp.add_argument(
    "-w",
    "--whitelist",
    default="domains-whitelist.txt",
    help="file containing a set of names to exclude from the blacklist",
)
argp.add_argument(
    "-r",
    "--time-restricted",
    default="domains-time-restricted.txt",
    help="file containing a set of names to be time restricted",
)
argp.add_argument(
    "-i",
    "--ignore-retrieval-failure",
    action="store_true",
    help="generate list even if some urls couldn't be retrieved",
)
argp.add_argument(
    "-o",
    "--output-file",
    default=None,
    help="save generated blacklist to a text file with the provided file name",
)
argp.add_argument("-t", "--timeout", default=30, help="URL open timeout")
args = argp.parse_args()

conf = args.config
whitelist = args.whitelist
time_restricted = args.time_restricted
ignore_retrieval_failure = args.ignore_retrieval_failure
output_file = args.output_file

blacklists_from_config_file(
    conf, whitelist, time_restricted, ignore_retrieval_failure, output_file)

