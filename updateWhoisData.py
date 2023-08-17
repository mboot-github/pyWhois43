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
    Optional,
    cast,
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
        self.charHintMap : Dict[str,str] = {}

    def getDbFileName(self) -> str:
        return self.FILE_WHOIS_NIC_TLD

    def getRaw(self, keyString: str) -> Optional[str]:
        with dbm.open(self.getDbFileName(), "r") as db:
            try:
                if keyString in db:
                    return db[keyString].decode("utf-8")
            except Exception as e:
                print(f"error for: {keyString} -> {e}", file=sys.stderr)

            return None

    def exists(self, keyString: str) -> bool:
        with dbm.open(self.getDbFileName(), "r") as db:
            return keyString in db

    def get(self, keyString: str) -> Dict[str, str]:
        data = self.getRaw(keyString)
        if data is None:
            return {}

        s = json.loads(data)

        return cast(Dict[str, str], s)

    def put(self, keyString: str, data: Dict[str, str]) -> Dict[str, str]:
        with dbm.open(self.getDbFileName(), "c") as db:
            db[keyString] = json.dumps(data)
        return data

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

                if isinstance(tld, bytes):
                    z = tld.decode("utf-8")
                else:
                    z = str(tld)

                print(f"{str(z)}: {s2}")

    def addOneTldServer(self, tld: str, server: str) -> None:
        data: Dict[str, str] = {}

        if self.exists(tld):
            data = self.get(tld)
        else:
            data["server"] = server
        self.put(tld, data)

        if server in self.charHintMap:
            self.addOneServerCharacterSetHint(tld,server,self.charHintMap[server])


    def addOneServerCharacterSetHint(self, tld: str, server: str, hint: str) -> None:
        data: Dict[str, str] = {}

        if self.verbose:
            print(tld, server, hint)

        if self.exists(tld):
            data = self.get(tld)
            if data['server'] == server:
                data['charSetHint'] = hint
                self.put(tld, data)

    def getServersCharsetList(self) -> None:
        allData: str = self.getAllDataFromUrl(
            self.URL_WHOIS_ServersCharsetList,
        )

        self.charHintMap = {}

        for line in allData.split("\n"):
            line = line.strip()
            if line == "" or line[0] == "#":
                continue

            z = line.split()
            self.charHintMap[z[0]] = z[1]
            if len(z) > 2:
                self.charHintMap[z[0]] += "; " + " ".join(z[2:])

        if self.verbose:
            print(self.charHintMap)

    def refreshNewGtldsList(self) -> None:
        allData: str = self.getAllDataFromUrl(
            self.URL_WHOIS_NewGtldsList,
        )

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

            if self.verbose:
                print(fields)

            self.addOneTldServer(fields[0], fields[1])

    def refreshAll(self) -> None:
        self.getServersCharsetList()
        self.refreshNewGtldsList()
        self.refreshTldServList()


if __name__ == "__main__":

    def testSimple(wsu: WhoisServerUpdater) -> None:
        for tld in ["aaa", "abc", "zuerich", "none"]:
            data = wsu.get(tld)
            print(f"{tld}, {data}")

    def xMain() -> None:
        wsu = WhoisServerUpdater()
        wsu.refreshAll()
        wsu.showAllData()
        # testSimple(wsu)

    xMain()
