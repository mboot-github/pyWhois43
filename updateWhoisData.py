#! /usr/bin/env python3

"""
Read the raw file, and store it in a dbm file

https://github.com/rfc1036/whois/blob/next/new_gtlds_list
https://github.com/rfc1036/whois/blob/next/tld_serv_list
https://github.com/rfc1036/whois/blob/next/servers_charset_list
https://github.com/rfc1036/whois/blob/next/nic_handles_list

"""

import sys
import dbm
import json
from typing import (
    Dict,
)
from urllib.request import urlopen


class WhoisServerUpdater:
    FILE_WHOIS_NIC_TLD = "whois_nic_tld.dbm"

    # a simple file one line mentioning the tld
    URL_WHOIS_NEW_GTLDS_LIST = "https://raw.githubusercontent.com/rfc1036/whois/next/new_gtlds_list"

    # a complicated file .<tld> <optional option> <server or NONE, server may be http> <optional comment starting with #>
    URL_WHOIS_TLD_SERV_LIST = "https://raw.githubusercontent.com/rfc1036/whois/next/tld_serv_list"

    def __init__(
        self,
        verbose: bool = False,
    ) -> None:
        self.verbose = verbose

    def getDbFileName(self) -> str:
        return self.FILE_WHOIS_NIC_TLD

    def getAllDataFromUrl(
        self,
        url: str,
    ) -> str:
        allData: str = urlopen(url).read().decode("utf-8")
        return allData

    def showAllData(
        self,
    ) -> None:
        with dbm.open(self.getDbFileName(), "r") as db:
            for tld in sorted(db.keys()):
                s = db[tld]
                s2: str = s.decode("utf-8")
                print(f"{str(tld)}: {s2}")

    def addOneTldServer(self, tld: str, server: str) -> None:
        data: Dict[str, str] = {}

        if tld in self.db:
            data = json.loads(self.db[tld].decode("utf-8"))
        else:
            data["server"] = server
        self.db[tld] = json.dumps(data)

    def refreshNewGtldsList(self) -> None:
        allData: str = self.getAllDataFromUrl(
            self.URL_WHOIS_NEW_GTLDS_LIST,
        )

        with dbm.open(self.getDbFileName(), "c") as self.db:
            for line in allData.split("\n"):
                line = line.strip()
                if line == "" or line[0] == "#":
                    continue

                tld: str = line
                self.addOneTldServer(tld, f"whois.nic.{tld}")

    def refreshAll(self) -> None:
        self.refreshNewGtldsList()


if __name__ == "__main__":

    def testSimple(wsu: WhoisServerUpdater) -> None:
        with dbm.open(wsu.getDbFileName(), "r") as db:
            for tld in ["aaa", "abc", "zuerich", "none"]:
                try:
                    s = db[tld].decode("utf-8")
                    print(f"{tld}: {s}")
                except Exception as e:
                    print(f"missing tld: {tld} -> {e}", file=sys.stderr)

    def showAll(wsu: WhoisServerUpdater) -> None:
        with dbm.open(wsu.getDbFileName(), "r") as db:
            for tld in sorted(db.keys()):
                s = db[tld]
                s2: str = s.decode("utf-8")
                print(f"{str(tld)}: {s2}")

    def xMain() -> None:
        wsu = WhoisServerUpdater()
        wsu.refreshAll()

        testSimple(wsu)
        showAll(wsu)

    xMain()
