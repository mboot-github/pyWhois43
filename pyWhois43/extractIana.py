#! /usr/bin/env python3
# extract all tld's from https://www.iana.org/domains/root/db and find the whois server (if any)

from typing import (
    Dict,
    Any,
    # List,
    Match,
    Optional,
)

import sys
import os
import re
import tempfile
import json
import socket

import urllib.request

# queries to the iana web page terminate with 503 frequently ,
# when queying all tld's sleep and restart untill all done


class IanaRootDbWhoisExtractor:
    URL: str = "https://www.iana.org/domains/root/db"
    BASE_CACHE_PATH: str = ""

    verbose: bool = False
    domains: Dict[str, Any] = {}

    def reportFuncName(self) -> None:
        if not self.verbose:
            return

        frame = sys._getframe(1)
        if frame is None:
            return

        message = (
            "{} {}".format(
                frame.f_code.co_filename,
                frame.f_code.co_name,
            ),
        )
        print(message, file=sys.stderr)

    def makeCacheBase(self) -> None:
        self.reportFuncName()

        aa = [tempfile.gettempdir(), self.__class__.__name__, "tld"]
        z = ""
        for p in aa:
            z = os.path.join(z, p)
        self.BASE_CACHE_PATH = z

    def makePathIfNotExists(self, path: str) -> None:
        self.reportFuncName()

        if not os.path.exists(path):
            os.makedirs(path)

    def __init__(self, verbose: bool = False) -> None:
        self.verbose = verbose

        self.reportFuncName()

        self.makeCacheBase()
        self.makePathIfNotExists(self.BASE_CACHE_PATH)

    def makeCachePath(self, tld: str) -> None:
        self.reportFuncName()

        directory = tld
        parent_dir = self.BASE_CACHE_PATH
        path = os.path.join(parent_dir, directory)
        os.makedirs(path)

    def extractWhoisServer(self, tld: str, html: str) -> None:
        self.reportFuncName()

        zz = re.findall(r"<b>WHOIS Server:</b> ([-\.\w]+)", str(html))
        if zz:
            whois = zz[0]
            self.domains[tld]["whois"] = whois

    def verifyWhoisServer(self, tld: str) -> None:
        self.reportFuncName()

        whois = self.domains[tld].get("whois")
        if whois:
            try:
                socket.getaddrinfo(whois, 43)
            except Exception as e:
                print(f"cannot connect to: {whois}, {e}", file=sys.stderr)

    def fetchOneRootInfo(self, tld: str) -> None:
        self.reportFuncName()

        item = self.domains.get(tld)
        if item is None:
            print(f"cannot find tld: {tld}", file=sys.stderr)
            return

        url = self.domains[tld].get("url")
        if url is None:
            print(f"cannot find url for tld: {tld}", file=sys.stderr)
            return

        with urllib.request.urlopen(url) as response:
            html = response.read()

            zz = re.findall(r"<b>WHOIS Server:</b> ([-\.\w]+)", str(html))
            if zz:
                whois = zz[0]
                self.domains[tld]["whois"] = whois

    def writeTldJsonFile(self, tld: str) -> None:
        self.reportFuncName()

        pTld = os.path.join(self.BASE_CACHE_PATH, tld)
        self.makePathIfNotExists(pTld)

        # Directly from dictionary
        fileName = f"{tld}.json"
        fPath = os.path.join(pTld, fileName)
        with open(fPath, "w") as outfile:
            json.dump(self.domains[tld], outfile)

    def fetchOneIanaRootDbTld(self, a: str) -> None:
        self.reportFuncName()

        xTld: Optional[Match[str]] = re.search(r"/domains/root/db/([-\w]+)\.html", a)
        if xTld is None:
            return

        tld = xTld[1]
        self.domains[tld] = {"url": "https://www.iana.org" + a}

        pTld = os.path.join(self.BASE_CACHE_PATH, tld)
        jPath = os.path.join(pTld, f"{tld}.json")

        if not os.path.exists(jPath):  # if older then (48 hours + random) refresh
            self.fetchOneRootInfo(tld)
            self.writeTldJsonFile(tld)
        else:
            try:
                with open(jPath) as f:
                    self.domains[tld] = json.load(f)
            except Exception as e:
                print(f"{tld}, {jPath}, {e}", file=sys.stderr)
                return

        if self.domains[tld].get("whois"):
            print(f"dns verify: {tld}, {self.domains[tld].get('whois')}")
            self.verifyWhoisServer(tld)

    def fetchAllIanaRootDB(self) -> None:
        self.reportFuncName()

        url = self.URL
        with urllib.request.urlopen(url) as response:
            html = response.read()
            nn = re.findall(r'<a\s+href="([^"]+)">', str(html))
            for a in nn:
                if "/domains/root/db/" not in a:
                    continue
                self.fetchOneIanaRootDbTld(a)


if __name__ == "__main__":
    verbose = True
    irdwe = IanaRootDbWhoisExtractor(
        verbose=verbose,
    )
    irdwe.fetchAllIanaRootDB()
    print(irdwe.domains)

"""
import random
from datetime import datetime, timedelta
days2 = 60*60*24*2
rand12 = random.randrange(-12*60*60,12*60*60) # between -12 hours and + 12 hours
two_days_ago = datetime.now() - (60*60*24*2) + rand12 # 48 hours with +or- 12 hours
filetime = datetime.fromtimestamp(path.getmtime(file_path)) # m modified, c created

if filetime < two_days_ago:
if filetime < two_days_ago:
  print "File is more than two days old.


<h2>Registry Information</h2>
<p>
    <b>URL for registration services:</b> <a href="http://www.nic.ac/">http://www.nic.ac/</a><br/>
    <b>WHOIS Server:</b> whois.nic.ac
</p>
<p><i>
Record last updated 2023-03-07.
Registration date 1997-12-19.
</i></p>

whois -h whois.iana.org <tld> nl
domain:       NL
whois:        whois.domain-registry.nl
status:       ACTIVE
remarks:      Registration information: https://www.sidn.nl/
created:      1986-04-25
changed:      2023-07-18
source:       IANA
"""
