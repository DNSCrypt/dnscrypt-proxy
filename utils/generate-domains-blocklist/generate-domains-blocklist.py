#! /usr/bin/env python3

# run with python generate-domains-blocklist.py > list.txt.tmp && mv -f list.txt.tmp list

from __future__ import print_function

import argparse
import re
import sys
import fnmatch
import concurrent.futures
import time

try:
    import urllib2 as urllib

    URLLIB_NEW = False
except (ImportError, ModuleNotFoundError):
    import urllib.request as urllib
    from urllib.request import Request

    URLLIB_NEW = True


def setup_logging(output_file=None):
    log_info = sys.stdout if output_file else sys.stderr
    log_err = sys.stderr
    return log_info, log_err


def parse_trusted_list(content):
    rx_comment = re.compile(r"^(#|$)")
    rx_inline_comment = re.compile(r"\s*#\s*[a-z0-9-].*$")
    rx_trusted = re.compile(r"^([*a-z0-9.-]+)\s*(@\S+)?$")
    rx_timed = re.compile(r".+\s*@\S+$")

    names = set()
    time_restrictions = {}
    globs = set()
    rx_set = [rx_trusted]
    for line in content.splitlines():
        line = str.lower(str.strip(line))
        if rx_comment.match(line):
            continue
        line = str.strip(rx_inline_comment.sub("", line))
        if is_glob(line) and not rx_timed.match(line):
            globs.add(line)
            names.add(line)
            continue
        for rx in rx_set:
            matches = rx.match(line)
            if not matches:
                continue
            name = matches.group(1)
            names.add(name)
            time_restriction = matches.group(2)
            if time_restriction:
                time_restrictions[name] = time_restriction
    return names, time_restrictions, globs


def parse_list(content, trusted=False):
    if trusted:
        return parse_trusted_list(content)

    rx_comment = re.compile(r"^(#|$)")
    rx_inline_comment = re.compile(r"\s*#\s*[a-z0-9-].*$")
    rx_u = re.compile(
        r"^@*\|\|([a-z0-9][a-z0-9.-]*[.][a-z]{2,})\^?(\$(popup|third-party))?$"
    )
    rx_l = re.compile(r"^([a-z0-9][a-z0-9.-]*[.][a-z]{2,})$")
    rx_lw = re.compile(r"^[*][.]([a-z0-9][a-z0-9.-]*[.][a-z]{2,})$")
    rx_h = re.compile(
        r"^[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}\s+([a-z0-9][a-z0-9.-]*[.][a-z]{2,})$"
    )
    rx_mdl = re.compile(r'^"[^"]+","([a-z0-9][a-z0-9.-]*[.][a-z]{2,})",')
    rx_b = re.compile(r"^([a-z0-9][a-z0-9.-]*[.][a-z]{2,}),.+,[0-9: /-]+,")
    rx_dq = re.compile(r"^address=/([a-z0-9][a-z0-9.-]*[.][a-z]{2,})/.")

    names = set()
    time_restrictions = {}
    globs = set()
    rx_set = [rx_u, rx_l, rx_lw, rx_h, rx_mdl, rx_b, rx_dq]
    for line in content.splitlines():
        line = str.lower(str.strip(line))
        if rx_comment.match(line):
            continue
        line = str.strip(rx_inline_comment.sub("", line))
        for rx in rx_set:
            matches = rx.match(line)
            if not matches:
                continue
            name = matches.group(1)
            names.add(name)
    return names, time_restrictions, globs


def print_restricted_name(output_fd, name, time_restrictions):
    if name in time_restrictions:
        print("{}\t{}".format(name, time_restrictions[name]), file=output_fd, end="\n")
    else:
        print(
            "# ignored: [{}] was in the time-restricted list, "
            "but without a time restriction label".format(name),
            file=output_fd,
            end="\n",
        )


def load_from_url(url, timeout):
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
        response = urllib.urlopen(req, timeout=int(timeout))
        content = response.read() # "The read operation timed out"
    except Exception as err:
        raise Exception("[{}] could not be loaded: {}".format(url, err))
    if trusted is False and response.getcode() != 200:
        raise Exception("[{}] returned HTTP code {}".format(url, response.getcode()))
    if URLLIB_NEW:
        content = content.decode("utf-8", errors="replace")

    return content, trusted


def name_cmp(name):
    parts = name.split(".")
    parts.reverse()
    return str.join(".", parts)


def is_glob(pattern):
    maybe_glob = False
    for i in range(len(pattern)):
        c = pattern[i]
        if c == "?" or c == "[":
            maybe_glob = True
        elif c == "*" and i != 0:
            if i < len(pattern) - 1 or pattern[i - 1] == ".":
                maybe_glob = True
    if maybe_glob:
        try:
            fnmatch.fnmatch("example", pattern)
            return True
        except:
            pass
    return False


def covered_by_glob(globs, name):
    if name in globs:
        return False
    for glob in globs:
        try:
            if fnmatch.fnmatch(name, glob):
                return True
        except:
            pass
    return False


def has_suffix(names, name):
    parts = str.split(name, ".")
    while parts:
        parts = parts[1:]
        if str.join(".", parts) in names:
            return True
    return False


def allowlist_from_url(url, timeout):
    if not url:
        return set()
    content, trusted = load_from_url(url, timeout)

    names, _time_restrictions, _globs = parse_list(content, trusted)
    return names

STOP_RETRY = False

def load_url_with_retry(url, timeout, tries=3, retry_delay=2):
    log_info, log_err = setup_logging()
    for attempt in range(tries):
        try_msg = f"try: {attempt + 1}/{tries}"
        try:
            log_info.write(f"[{try_msg}] Loading data from [{url}]\n")
            content, trusted = load_from_url(url, timeout)
            log_err.write(f"[{try_msg}] [{url}] OK\n")
            return content, trusted
        except Exception as e:
            log_err.write(f"[{try_msg}] {e}\n")
            if STOP_RETRY:
                break
            if attempt < tries - 1:
                time.sleep(retry_delay)
            else:
                raise e


def load_blocklists_parallel(urls, timeout, ignore_retrieval_failure):
    log_info, log_err = setup_logging()
    blocklists = {}
    all_names = set()
    all_globs = set()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {
            executor.submit(load_url_with_retry, url, timeout): url
            for url in urls
        }

        # Useful for bad network situations
        return_when = concurrent.futures.FIRST_EXCEPTION
        if ignore_retrieval_failure:
            return_when = concurrent.futures.ALL_COMPLETED
        finished, unfinished = concurrent.futures.wait(future_to_url, None, return_when)
        # Return early
        if len(unfinished) > 0:
            # Cancel unstarted tasks
            for f in unfinished:
                if not f.done():
                    f.cancel()
            # Stop retries
            global STOP_RETRY
            STOP_RETRY = True
            # Threads won't be terminated forcibly
            if not ignore_retrieval_failure:
                sys.exit(1)

        for future in finished:
            url = future_to_url[future]
            try:
                content, trusted = future.result()
                names, _time_restrictions, globs = parse_list(content, trusted)
                blocklists[url] = names
                all_names |= names
                all_globs |= globs
            except Exception as e:
                log_err.write(f"{e}\n")
                if not ignore_retrieval_failure:
                    sys.exit(1)

    return blocklists, all_names, all_globs


def blocklists_from_config_file(
    file, allowlist, time_restricted_url, ignore_retrieval_failure, output_file, timeout
):
    log_info, log_err = setup_logging(output_file)

    # Get URLs from config file
    urls = []
    with open(file) as fd:
        for line in fd:
            line = str.strip(line)
            if str.startswith(line, "#") or line == "":
                continue
            urls.append(line)

    # Load blocklists in parallel
    blocklists, all_names, all_globs = load_blocklists_parallel(
        urls, timeout, ignore_retrieval_failure
    )

    # Load allowed names
    allowed_names = set()

    # Time-based blocklist
    if time_restricted_url and not re.match(r"^[a-z0-9]+:", time_restricted_url):
        time_restricted_url = "file:" + time_restricted_url

    output_fd = sys.stdout
    if output_file:
        output_fd = open(output_file, "w")

    if time_restricted_url:
        try:
            time_restricted_content, _trusted = load_from_url(
                time_restricted_url, timeout
            )
            time_restricted_names, time_restrictions, _globs = parse_trusted_list(
                time_restricted_content
            )

            if time_restricted_names:
                print(
                    "########## Time-based blocklist ##########\n",
                    file=output_fd,
                    end="\n",
                )
                for name in time_restricted_names:
                    print_restricted_name(output_fd, name, time_restrictions)

            # Time restricted names should be allowed, or they could be always blocked
            allowed_names |= time_restricted_names
        except Exception as e:
            log_err.write(f"Error loading time-restricted list: {str(e)}\n")

    # Allowed list
    if allowlist and not re.match(r"^[a-z0-9]+:", allowlist):
        allowlist = "file:" + allowlist

    try:
        allowed_names |= allowlist_from_url(allowlist, timeout)
    except Exception as e:
        log_err.write(f"Error loading allowlist: {str(e)}\n")

    # Process blocklists
    unique_names = set()
    for url, names in blocklists.items():
        print(
            "\n\n########## Blocklist from {} ##########\n".format(url),
            file=output_fd,
            end="\n",
        )
        ignored, glob_ignored, allowed = 0, 0, 0
        list_names = []
        for name in names:
            if covered_by_glob(all_globs, name):
                glob_ignored = glob_ignored + 1
            elif has_suffix(all_names, name) or name in unique_names:
                ignored = ignored + 1
            elif has_suffix(allowed_names, name) or name in allowed_names:
                allowed = allowed + 1
            else:
                list_names.append(name)
                unique_names.add(name)

        list_names.sort(key=name_cmp)
        if ignored:
            print("# Ignored duplicates: {}".format(ignored), file=output_fd, end="\n")
        if glob_ignored:
            print(
                "# Ignored due to overlapping local patterns: {}".format(glob_ignored),
                file=output_fd,
                end="\n",
            )
        if allowed:
            print(
                "# Ignored entries due to the allowlist: {}".format(allowed),
                file=output_fd,
                end="\n",
            )
        if ignored or glob_ignored or allowed:
            print(file=output_fd, end="\n")
        for name in list_names:
            print(name, file=output_fd, end="\n")

    output_fd.close()


def main():
    argp = argparse.ArgumentParser(
        description="Create a unified blocklist from a set of local and remote files"
    )
    argp.add_argument(
        "-c",
        "--config",
        default="domains-blocklist.conf",
        help="file containing blocklist sources",
    )
    argp.add_argument(
        "-w",
        "--whitelist",
        help=argparse.SUPPRESS,
    )
    argp.add_argument(
        "-a",
        "--allowlist",
        default="domains-allowlist.txt",
        help="file containing a set of names to exclude from the blocklist",
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
        help="save generated blocklist to a text file with the provided file name",
    )
    argp.add_argument("-t", "--timeout", default=30, help="URL open timeout in seconds")
    argp.add_argument(
        "-p",
        "--progress",
        action="store_true",
        help="show download progress information",
    )

    args = argp.parse_args()

    whitelist = args.whitelist
    if whitelist:
        print(
            "The option to provide a set of names to exclude from the blocklist has been changed from -w to -a\n"
        )
        argp.print_help()
        exit(1)

    start_time = time.time()

    log_info, _ = setup_logging(args.output_file)
    if args.progress:
        log_info.write("Starting blocklist generation...\n")

    blocklists_from_config_file(
        args.config,
        args.allowlist,
        args.time_restricted,
        args.ignore_retrieval_failure,
        args.output_file,
        args.timeout,
    )

    if args.progress:
        duration = time.time() - start_time
        log_info.write(f"Blocklist generation completed in {duration:.2f} seconds\n")


if __name__ == "__main__":
    main()
