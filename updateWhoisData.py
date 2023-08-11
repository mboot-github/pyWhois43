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
    List,
)
from urllib.request import urlopen


class WhoisServerUpdater:
    FILE_WHOIS_NIC_TLD = "whois_nic_tld.dbm"

    # a simple file one line mentioning the tld
    URL_WHOIS_NewGtldsList = "https://raw.githubusercontent.com/rfc1036/whois/next/new_gtlds_list"

    # a complicated file .<tld> <optional option> <server or NONE, server may be http> <optional comment starting with #>
    URL_WHOIS_TldServList = "https://raw.githubusercontent.com/rfc1036/whois/next/tld_serv_list"

    URL_WHOIS_ServersCharsetList = "https://raw.githubusercontent.com/rfc1036/whois/next/servers_charset_list"

    def __init__(
        self,
        verbose: bool = False,
    ) -> None:
        self.verbose = verbose
        self.serversCharsetList: Dict[str, str] = {}

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

    def getServersCharsetList(self) -> None:
        allData: str = self.getAllDataFromUrl(
            self.URL_WHOIS_ServersCharsetList,
        )

        for line in allData.split("\n"):
            line = line.strip()
            if line == "" or line[0] == "#":
                continue
            z = line.split()
            print(z)

    def refreshNewGtldsList(self) -> None:
        allData: str = self.getAllDataFromUrl(
            self.URL_WHOIS_NewGtldsList,
        )

        with dbm.open(self.getDbFileName(), "c") as self.db:
            for line in allData.split("\n"):
                line = line.strip()
                if line == "" or line[0] == "#":
                    continue

                tld: str = line
                self.addOneTldServer(tld, f"whois.nic.{tld}")

    def refreshTldServList(self) -> None:
        allData: str = self.getAllDataFromUrl(
            self.URL_WHOIS_TldServList,
        )

        with dbm.open(self.getDbFileName(), "c") as self.db:
            for line in allData.split("\n"):
                line = line.strip()
                if line == "" or line[0] == "#":
                    continue

                fields: List[str] = line.split()
                if fields[0][0] == ".":
                    fields[0] = fields[0][1:]

                if fields[1].lower() in ["none", "web", "arpa", "ip6"]:
                    continue

                if "." not in fields[1] and "." in fields[2]:
                    z = fields[1]
                    fields[1] = fields[2]
                    fields[2] = z

                if "." not in fields[1]:
                    continue

                print(fields)

                self.addOneTldServer(fields[0], fields[1])

    def refreshAll(self) -> None:
        self.getServersCharsetList()
        self.refreshNewGtldsList()
        self.refreshTldServList()


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
                if isinstance(tld, bytes):
                    z = tld.decode("utf-8")
                else:
                    z = tld

                print(f"{str(z)}: {s2}")

    def xMain() -> None:
        wsu = WhoisServerUpdater()
        wsu.refreshAll()

        testSimple(wsu)
        showAll(wsu)

    xMain()
