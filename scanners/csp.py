import logging
import requests
from scanners import utils

###
# CSP Scanner - check the presence of CSP headers
#


# Set a default number of workers for a particular scan type.
# Overridden by a --workers flag.
workers = 2


# default to a custom user agent, can be overridden
user_agent = "github.com/18f/domain-scan, csp.py"


def init_domain(domain, environment, options):
    cache_dir = options.get("_", {}).get("cache_dir", "./cache")
    # If we have data from pshtt, skip if it's not a live domain.
    if utils.domain_not_live(domain, cache_dir=cache_dir):
        logging.debug("\tSkipping, domain not reachable during inspection.")
        return False

    # If we have data from pshtt, skip if it's just a redirector.
    if utils.domain_is_redirect(domain, cache_dir=cache_dir):
        logging.debug("\tSkipping, domain seen as just an external redirector during inspection.")
        return False

    # requests needs a URL, not just a domain.
    url = None
    url = (
        domain
        if (domain.startswith('http://') or domain.startswith('https://'))
        else utils.domain_canonical(domain, cache_dir=cache_dir)
        or f'https://{domain}'
    )

    return {'url': url}


def scan(domain, environment, options):
    logging.debug(f"CSP Check called with options: {options}")
    url = environment.get("url", domain)
    logging.debug("URL: %s", url)
    response = requests.get(url)
    csp_set = "content-security-policy" in response.headers
    logging.warning("Complete!")
    return {
        'csp_set': csp_set
    }


# Required CSV row conversion function. Usually one row, can be more.
#
# Run locally.
def to_rows(data):
    return [
        [data['csp_set']]
    ]


# CSV headers for each row of data. Referenced locally.
headers = ["CSP Set for domain"]
