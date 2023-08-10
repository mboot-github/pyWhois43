#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# interesting:
# https://github.com/rfc1036/whois/blob/next/tld_serv_list
# https://github.com/rfc1036/whois/blob/next/new_gtlds_list

"""
Whois client for python

a heavvy refactored python3 implementation from:
  https://github.com/richardpenman/whois/whois.py
based on original python2/3 implementation of:
<quote>
    transliteration of:
        http://www.opensource.apple.com/source/adv_cmds/adv_cmds-138.1/whois/whois.c

    Copyright (c) 2010 Chris Wolf

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    THE SOFTWARE.
</quote>
"""

import optparse
import sys


from typing import (
    List,
    Dict,
    Any,
    Optional,
)

from pyWhoisClient import PyWhoisClient


class PyWhoisCli(PyWhoisClient):
    def __init__(
        self,
        verbose: bool = False,
    ):
        super().__init__(verbose=verbose)
        self.reportFuncName()

    def whois_lookup(
        self,
        domain: str = "",
        options: Dict[str, Any] = {},
        flags: int = 0,
        quiet: bool = False,
    ) -> Optional[str]:
        self.reportFuncName()

        self.domain = domain
        self.options = options
        self.flags = flags
        self.quiet = quiet

        self.nichost = None
        self.use_qnichost = False
        self.data: List[str] = []

        """
        Main entry point:

        Perform initial lookup on TLD whois server,
        or other server to get region-specific whois server,
        then if quick flag is false,
        perform a second lookup on the region-specific server for contact records.

        If `quiet` is `True`,
        no message will be printed to STDOUT when a socket error is encountered.
        """

        nichost: Optional[str] = None

        if options.get("whoishost") is None:
            self.use_qnichost = True  # use verisign as default
            options["whoishost"] = PyWhoisClient.NIC_HOST

            if not (flags & PyWhoisClient.WHOIS_QUICK):
                flags |= PyWhoisClient.WHOIS_RECURSE

        if self.use_qnichost:
            nichost = self.chooseServer(domain)
        else:
            nichost = options["whoishost"]

        if not nichost:
            return ""

        zz = self.whois(
            query=domain,
            hostname=nichost,
            flags=flags,
            many_results=False,
        )
        return zz

    def parseMyArgs(
        self,
        argv: List[str],
    ) -> Any:
        self.reportFuncName()

        """
        Options handling mostly follows the UNIX whois(1) man page,
          except long-form options can also be used.
        """
        usage = "usage: %prog [options] name"

        parser = optparse.OptionParser(
            add_help_option=False,
            usage=usage,
        )
        # port
        parser.add_option(
            "-p",
            "--port",
            action="store",
            type="int",
            dest="port",
            help="Lookup using specified tcp port",
        )

        # explicitly request a whoishost <server>
        parser.add_option(
            "-h",
            "--host",
            action="store",
            type="string",
            dest="whoishost",
            help="Lookup using specified whois host",
        )

        # generic
        parser.add_option(
            "-Q",
            "--quick",
            action="store_true",
            dest="b_quicklookup",
            help="Perform quick lookup",
        )

        parser.add_option(
            "-?",
            "--help",
            action="help",
        )

        return parser.parse_args(argv)


if __name__ == "__main__":
    verbose = True

    flags = 0

    nc = PyWhoisCli(verbose=verbose)
    options, args = nc.parseMyArgs(sys.argv)
    if options.b_quicklookup:
        flags = flags | PyWhoisCli.WHOIS_QUICK

    data = nc.whois_lookup(
        'google.com',
    )
    print(data)
