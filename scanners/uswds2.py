import logging
import requests
import re
from lxml import html
import math

###
# Scanner to search for uswds compliance.  It is just scraping the front page
# and CSS files and searching for particular content.


# Set a default number of workers for a particular scan type.
# Overridden by a --workers flag. XXX not actually overridden?
workers = 50


# Required scan function. This is the meat of the scanner, where things
# that use the network or are otherwise expensive would go.
#
# Runs locally or in the cloud (Lambda).
def scan(domain: str, environment: dict, options: dict) -> dict:
    results = {i: 0 for i in headers}
    results['uswdsversion'] = ""

    # Get the url
    try:
        response = requests.get(f"http://{domain}", timeout=5)
    except Exception:
        logging.debug("got error while querying %s", domain)
        results["domain"] = domain
        results["status_code"] = -1
        return results

    if res := re.findall(r'class.*"usa-', response.text):
        results["usa_classes_detected"] = round(math.sqrt(len(res))) * 5

    if res := re.findall(r'uswds', response.text):
        results["uswds_detected"] = len(res)

    if res := re.findall(r'\.usa-', response.text):
        results["usa_detected"] = len(res)

    if res := re.findall(r'favicon-57.png', response.text):
        results["flag_detected"] = 20

    if res := re.findall(r'<table ', response.text):
        results["tables"] = len(res) * -10

    # check for things in CSS files
    try:
        tree = html.fromstring(response.content)
        csspages = tree.xpath('/html/head/link[@rel="stylesheet"]/@href')
    except Exception:
        csspages = []

    for csspage in csspages:
        if res := re.findall(r'^http.?://', csspage, re.IGNORECASE):
            url = csspage
        else:
            url = f"https://{domain}{csspage}"

        try:
            cssresponse = requests.get(url, timeout=5, stream=True)
        except Exception:
            logging.debug("got error while querying for css page %s", url)
            continue

        # This is to try to not run out of memory.  This provides a sliding window
        # so that if one of the patterns spans a chunk boundary, we will not miss it.
        lastbody = ''
        for nextbody in cssresponse.iter_content(chunk_size=20480):
            nextbody = str(nextbody)
            cssbody = lastbody + nextbody
            lastbody = nextbody

            if res := re.findall(r'[sS]ource ?[Ss]ans', cssbody):
                results["sourcesansfont_detected"] = 5

            if res := re.findall(r'[Mm]erriweather', cssbody):
                results["merriweatherfont_detected"] = 5

            if res := re.findall(r'[Pp]ublic ?[Ss]ans', cssbody):
                results["publicsansfont_detected"] = 20

            if res := re.findall(r'uswds', cssbody):
                results["uswdsincss_detected"] = 20

            if res := re.findall(r'uswds v[0-9.]* ', cssbody):
                vstuff = res[0].split(' ')
                results["uswdsversion"] = str(vstuff[1])
                results["total_score"] = results["total_score"] + 20

            if res := re.findall(r'favicon-57.png', cssbody):
                results["flagincss_detected"] = 20

                    # # check for standard USWDS 1.x colors in css
                    # # (testing showed that this did not detect more, and it also caused FPs)
                    # res = re.findall(r'#0071bc|#205493|#112e51|#212121|#323a45|#aeb0b5', cssbody)
                    # if res:
                    #     results["stdcolors_detected"] += len(res)

    # generate a final score
    # The quick-n-dirty score is to add up all the number of things we found.
    for i, value in results.items():
        if isinstance(value, int) and i != 'total_score':
            results["total_score"] += results[i]
    results["total_score"] = max(results["total_score"], 0)
    # add the status code and domain
    results["status_code"] = response.status_code
    results["domain"] = domain

    logging.warning("uswds2 %s Complete!", domain)

    return results


# Required CSV row conversion function. Usually one row, can be more.
#
# Run locally.
def to_rows(data):
    row = []
    for i in headers:
        row.extend([data[i]])
    return [row]


# CSV headers for each row of data. Referenced locally.
headers = [
    "domain",
    "status_code",
    "usa_classes_detected",
    # "official_website_detected",
    "uswds_detected",
    "usa_detected",
    "flag_detected",
    "flagincss_detected",
    "sourcesansfont_detected",
    "uswdsincss_detected",
    "merriweatherfont_detected",
    "publicsansfont_detected",
    "uswdsversion",
    "tables",
    "total_score"
]
