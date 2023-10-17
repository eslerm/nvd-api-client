# nvd-api-client

NVD API 2.0 client for CVE based on suggested NVD's *Best Practices*: [https://nvd.nist.gov/developers/start-here](https://nvd.nist.gov/developers/start-here)

# Configuration

Configure path to local NVD mirror by creating an INI file located in `~/.config/nvd-api-client.conf` similar to:

```ini
[DEFAULT]
nvd_path=/home/eslerm/mirrors/nvd/
```

As of 2023-10-17 a local mirror requires 1.3G of space.

# Example

```bash
$ python3 nvd_api_client.py --help
usage: nvd_api_client.py [-h] [--init] [-s MAINTAIN_SINCE] [--auto] [--debug] [--verbose]

NVD API Client

options:
  -h, --help            show this help message and exit
  --init                initialize mirror of NVD dataset
  -s MAINTAIN_SINCE, --maintain-since MAINTAIN_SINCE
                        maintain NVD dataset since YY-MM-DD or ISO-8601 datetime
  --auto                automated maintenance
  --debug               add debug info
  --verbose             add verbose debug info
```
```bash
$ python3 nvd_api_client.py --auto --verbose
DEBUG: local NVD mirror path is /home/eslerm/mirrors/nvd
DEBUG: searching NVD dataset for most recent lastModified value
DEBUG: most recent lastModified value is: 2023-10-17T20:43:40.507
DEBUG: searching for modified NVD CVEs between 2023-10-17T20:43:40.507000+00:00 and 2023-10-17T21:32:45.909885+00:00
DEBUG: local NVD mirror path is /home/eslerm/mirrors/nvd
DEBUG: requesting https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=2023-10-17T20:43:40.507000%2B00:00&lastModEndDate=2023-10-17T21:32:45.909885%2B00:00&resultsPerPage=2000&startIndex=0
DEBUG: saving CVE-2022-25187
DEBUG: saving CVE-2022-25319
DEBUG: saving CVE-2022-25321
DEBUG: saving CVE-2022-29528
DEBUG: saving CVE-2023-43794
DEBUG: saved results 0 through 5 of 5
DEBUG: NVD sync complete \o/
```
