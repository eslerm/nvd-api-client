#!/usr/bin/env python3

"""
nvd-api-client: download and maintain NVD's CVE dataset


Configure path to local NVD mirror by creating an INI file located in
~/.config/nvd-api-client.conf similar to:

    [DEFAULT]
    nvd_path=/home/eslerm/mirrors/nvd/

Make sure to create this directory!


nvd-api-client has three primary modes:

  --init

    To initialize the mirror by downloading NVD's CVE dataset, run:
      ./scripts/nvd_api_client --init
    and follow the prompt.

  --maintain-since

    To maintain your NVD CVE dataset mirror, run the following command with the
    date set to the last time maintenance was ran:
      ./scripts/nvd_api_client --maintain-since 2022-12-25
    The above command will download all CVEs since December 25th 2022 UCT until
    now.

    ISO-8601 datetime is also allowed as maintenance input:
      ./scripts/nvd_api_client --maintain-since 2023-08-01T00:00:00
      ./scripts/nvd_api_client --maintain-since 2023-08-01T00:00:00.000001+00:00

    The --maintain-since value must be within 120 days of today. (This is an
    undocumented API restriction.)

  --auto

    To automatically maintain your dataset (without needing to know when
    maintenance was last ran) run:
      ./scripts/nvd_api_client --auto

All modes accept --debug or --verbose which print information in stderr.
  nb: use these options to monitor update progress
"""


__author__ = "Mark Esler"
__copyright__ = "Copyright (C) 2023 Canonical Ltd."
__license__ = "GPL-3.0-only"
__version__ = "1.0-git"


import argparse
import configparser
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time
from typing import Optional
import urllib.parse
import requests


# API Client Headers
HEADERS = {"Accept-Language": "en-US", "User-Agent": "nvd-api-client"}

# seconds to wait after a request
# maximally efficient timing isn't critical
# NVD's public rate limit is 5 requests in a rolling 30 second window
# public default based on 5 / 30 * 2 = 12, round down to 10 requests a minute
# sleeping 6.0 seconds aligns with NVD's Best Practices
# a smaller value can be used and will be set further down if an API key is provided
RATE_LIMIT = 6.0


# requests timeout
TIMEOUT = 30.0


def debug(msg: str) -> None:
    """print to stderr"""
    print("DEBUG: " + msg, file=sys.stderr)


def find_conf() -> Path:
    """find configuration file"""
    filename = ".config/nvd-api-client.conf"
    path = Path.home() / filename
    if path.is_file():
        return path
    raise ValueError(f"No configuration file. Create {Path.home()}/{filename}")


def load_config() -> dict:
    """read configuration file."""
    conf_path = find_conf()
    config = configparser.ConfigParser()
    config_d = {"path":None, "api_key":None}
    try:
        # nb: encoding is unset
        with open(conf_path) as file:
            config.read_file(file)
    except OSError as exc:
        msg = f"error reading {conf}"
        raise OSError(msg) from exc
    try:
        path = Path(config["DEFAULT"]["nvd_path"])
        config_d["path"] = path
    except KeyError as exc:
        raise KeyError("nvd_path not defined in configuration file") from exc
    if "api_key" in config["DEFAULT"]:
        config_d["api_key"] = config["DEFAULT"]["api_key"]
    return config_d


def verify_dirs() -> Path:
    """create directory structure if needed and return local NVD mirror path"""
    if args.path:
        nvd_path = Path(args.path)
    else:
        nvd_path = load_config()["path"]

    if DEBUG:
        debug(f"local NVD mirror path is {nvd_path}")

    nvd_path.mkdir(parents=True, exist_ok=True)

    current_year = int(time.strftime("%Y", time.gmtime()))
    for i in range(1999, current_year + 1):
        Path(nvd_path / str(i)).mkdir(parents=True, exist_ok=True)

    return nvd_path


def get_url(url: str) -> requests.models.Response:
    """
    return a url response after sleeping

    NOTE: could be modified for https://github.com/tomasbasham/ratelimit
    """
    if VERBOSE:
        debug(f"requesting {url}")
    response = requests.get(url, timeout=TIMEOUT, headers=HEADERS)

    if response.status_code != 200:
        msg = f"API response: {response.status_code}"
        raise Exception(msg)

    time.sleep(RATE_LIMIT)

    return response


def save_cve(page_json: dict, nvd_path: Path) -> None:
    """save all  json files from a page"""
    for i in page_json["vulnerabilities"]:
        cve = i["cve"]
        year = cve["id"][4:8]
        file_path = Path(f'{nvd_path / year / cve["id"]}.json')
        if VERBOSE:
            debug(f'saving {cve["id"]}')
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(cve, file, indent=PRETTY)


def save_pages(date_range: Optional[tuple] = None) -> None:
    """
    get all pages of CVE results and save them

    see https://nvd.nist.gov/developers/vulnerabilities for parameters
    """

    nvd_path = verify_dirs()

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    start_index = 0
    results_per_page = 2000
    total_results = results_per_page + 1

    api_key = load_config().get("api_key", None)

    while start_index < total_results:

        p = {"resultsPerPage": results_per_page, "startIndex": start_index}
        if date_range:
            p["lastModStartDate"] = date_range[0]
            p["lastModEndDate"] = date_range[1]
        if api_key:
            p["apiKey"] = api_key
        params = urllib.parse.urlencode(p)
        url = f"{base_url}?{params}"

        page = get_url(url)
        page_json = page.json()
        page.close()

        save_cve(page_json, nvd_path)

        total_results = page_json["totalResults"]

        if DEBUG:
            if total_results == 0:
                debug("no new updates from NVD")
            elif (start_index + results_per_page) >= total_results:
                debug(
                    f"saved results {start_index} through {total_results}"
                    + f" of {total_results}"
                )
            else:
                debug(
                    f"saved results {start_index} through {start_index + results_per_page}"
                    + f" of {total_results}"
                )

        start_index += results_per_page


def nvd_init() -> None:
    """
    create initial NVD dataset

    NVD's Best Practices for Initial Data Population state:
      - Users should start by calling the API beginning with a startIndex of 0
      - Iterative requests should increment the startIndex by the value of
        resultsPerPage until the response's startIndex has exceeded the value
        in totalResults
    NVD text accessed Aug 1st 2023
      - https://nvd.nist.gov/developers/start-here
    """
    res = input(
        'Are you certain that you want to download all NVD data? Enter "Yes" to agree: '
    )
    if res == "Yes":
        save_pages()


def nvd_maintain(since: datetime) -> None:
    """
    maintain NVD dataset

    set the since datetime to the time that NVD dataset was last maintained

    it is not recommended to run this function more than once every two hours

    large organizations should use a single requester

    see https://nvd.nist.gov/developers/vulnerabilities for parameters

    NVD's Best Practices for Maintaining Data state:
      - After initial data population has occurred, the last modified date
        parameters provide an efficient way to update a user's local
        repository and stay within the API rate limits. No more than once
        every two hours, automated requests should include a range where
        lastModStartDate equals the time of the last CVE or CPE received and
        lastModEndDate equals the current time.
      - It is recommended that users "sleep" their scripts for six seconds
        between requests.
      - It is recommended to use the default resultsPerPage value as this value
        has been optimized for the API response.
      - Enterprise scale development should enforce these practices through a
        single requestor to ensure all users are in sync and have the latest
        CVE, Change History, CPE, and CPE match criteria information.
    NVD text accessed Aug 1st 2023
      - https://nvd.nist.gov/developers/start-here
    """
    start_date = since.isoformat()
    end_date = datetime.now(timezone.utc).isoformat()

    if DEBUG:
        debug(f"searching for modified NVD CVEs between {start_date} and {end_date}")

    save_pages((start_date, end_date))


def check_last_modified(last_modified: datetime) -> None:
    """raise error if an unallowed lastModified date is requested"""
    delta = last_modified - datetime.now(timezone.utc)
    if delta.days < -120:
        msg = "NVD API does not allow searching lastModified dates greater than 120 days ago"
        raise argparse.ArgumentTypeError(msg)


# https://stackoverflow.com/questions/25470844/specify-date-format-for-python-
# argparse-input-arguments
def format_date(date_str: str) -> datetime:
    """
    verify and format a date string into a datetime for NVD's API

    always returns UTC

    note that converting the datetime to a string requires .replace("+", "%2B")
    before running get_url()
    """
    try:
        # API requires microseconds
        date = datetime.strptime(date_str, "%Y-%m-%d").replace(
            tzinfo=timezone.utc, microsecond=1
        )
    except ValueError:
        try:
            date = datetime.fromisoformat(date_str).replace(tzinfo=timezone.utc)
        except ValueError as exc:
            msg = f"not a valid date: {date_str}"
            raise argparse.ArgumentTypeError(msg) from exc
    return date


def nvd_last_modified_file() -> datetime:
    """
    search local dataset for most recent lastModified value

    inefficiency is fine if user does not know when maintenance was last ran
    """
    nvd_path = verify_dirs()
    if DEBUG:
        debug("searching NVD dataset for most recent lastModified value")
    # compare strings instead of datetimes
    last_modified_string = "0"
    for path in nvd_path.rglob("*.json"):
        if path.is_dir():
            continue
        try:
            # nb: encoding is unset
            with open(path) as file:
                data = json.load(file)
        except OSError as exc:
            msg = f"error reading {path}"
            raise OSError(msg) from exc
        if data["lastModified"] > last_modified_string:
            last_modified_string = data["lastModified"]
    if DEBUG:
        debug(f"most recent lastModified value is: {last_modified_string}")
    last_modified = format_date(last_modified_string)
    check_last_modified(last_modified)
    return last_modified


def nvd_auto() -> None:
    """run nvd_maintain with most recent lastModified value in dataset"""
    last_modified = nvd_last_modified_file()
    check_last_modified(last_modified)
    nvd_maintain(last_modified)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NVD API Client")
    parser.add_argument(
        "--init",
        help="initialize mirror of NVD dataset",
        action="store_true",
    )
    parser.add_argument(
        "-s",
        "--maintain-since",
        help="maintain NVD dataset since YY-MM-DD or ISO-8601 datetime",
        type=format_date,
    )
    parser.add_argument("--path", help="set path", type=Path)
    parser.add_argument("--auto", help="automated maintenance", action="store_true")
    parser.add_argument("--debug", help="add debug info", action="store_true")
    parser.add_argument("--verbose", help="add verbose debug info", action="store_true")
    parser.add_argument(
        "--pretty", help="pretty json output", default=True, action="store_true"
    )

    args = parser.parse_args()

    if load_config().get("api_key", None):
        # 50 requests in a rolling 30 second window
        RATE_LIMIT = 0.60

    if args.verbose:
        VERBOSE = True
        DEBUG = True
    elif args.debug:
        VERBOSE = False
        DEBUG = True
    else:
        VERBOSE = False
        DEBUG = False

    if args.pretty:
        PRETTY = 4
    else:
        PRETTY = None

    if args.init:
        nvd_init()
    elif args.auto:
        nvd_auto()
    elif args.maintain_since:
        nvd_maintain(args.maintain_since)
    else:
        raise ValueError("an argument is needed, see --help")

    if DEBUG:
        debug("NVD sync complete \\o/")
