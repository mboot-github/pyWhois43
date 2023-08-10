#! /usr/bin/env python3

"""
Read the raw file, and store it in a dbm file
"""

import sys
import dbm
from urllib.request import urlopen

WHOIS_NIC_TLD_URL: str = (
    "https://raw.githubusercontent.com/rfc1036/whois/next/new_gtlds_list"
)
WHOIS_NIC_TLD_FILE: str = "whois_nic_tld.dbm"


def updateDbFile() -> None:
    data = urlopen(WHOIS_NIC_TLD_URL).read().decode("utf-8")
    with dbm.open(WHOIS_NIC_TLD_FILE, "c") as db:
        for line in data.split("\n"):
            line = line.strip()
            if line == "" or line[0] == "#":
                continue
            db[line] = f"whois.nic.{line}"


if __name__ == "__main__":
    updateDbFile()
    with dbm.open(WHOIS_NIC_TLD_FILE, "r") as db:
        for tld in ["aaa", "abc", "zuerich", "none"]:
            try:
                s = db[tld].decode("utf-8")
                print(f"{tld}: {s}")
            except Exception as e:
                print(f"missing tld: {tld} -> {e}", file=sys.stderr)

        for tld in sorted(db.keys()):
            tld = tld.decode("utf-8")
            s = db[tld].decode("utf-8")
            print(f"{tld}: {s}")
