#! /usr/bin/env python3
# -*- coding: utf-8 -*-

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

import os
import optparse
import socket
import sys
import re
import inspect

from typing import (
    # cast,
    # Optional,
    List,
    Dict,
    # Tuple,
    Any,
    # Callable,
)


class PyWhoisClient:
    # better lookup directly on iana and cache the results
    # whois <tld no dot> -h whois.iana.org
    # ----------------------------------------
    DEFAULT_PORT_NAME: str = "nicname"  # /etc/services port 43
    DEFAULT_PORT_NR: int = 43
    MAX_READ_BUF: int = 4096
    # ----------------------------------------
    ABUSE_HOST: str = "whois.abuse.net"
    AI_HOST: str = "whois.nic.ai"
    ANIC_HOST: str = "whois.arin.net"
    APP_HOST: str = "whois.nic.google"
    AR_HOST: str = "whois.nic.ar"
    BNIC_HOST: str = "whois.registro.br"
    BW_HOST: str = "whois.nic.net.bw"
    BY_HOST: str = "whois.cctld.by"
    CA_HOST: str = "whois.ca.fury.ca"
    CHAT_HOST: str = "whois.nic.chat"
    CL_HOST: str = "whois.nic.cl"
    CR_HOST: str = "whois.nic.cr"
    DE_HOST: str = "whois.denic.de"
    DENIC_HOST: str = "whois.denic.de"
    DETI_HOST: str = "whois.nic.xn--d1acj3b"
    DEV_HOST: str = "whois.nic.google"
    DK_HOST: str = "whois.dk-hostmaster.dk"
    DNIC_HOST: str = "whois.nic.mil"
    DO_HOST: str = "whois.nic.do"
    GAMES_HOST: str = "whois.nic.games"
    GDD_HOST: str = "whois.dnrs.godaddy"
    GNIC_HOST: str = "whois.nic.gov"
    GOOGLE_HOST: str = "whois.nic.google"
    GROUP_HOST: str = "whois.namecheap.com"
    HK_HOST: str = "whois.hkirc.hk"
    HN_HOST: str = "whois.nic.hn"
    HR_HOST: str = "whois.dns.hr"
    IANA_HOST: str = "whois.iana.org" # <<=
    IDS_HOST: str = "whois.identitydigital.services"
    INIC_HOST: str = "whois.networksolutions.com"
    IST_HOST: str = "whois.afilias-srs.net"
    JOBS_HOST: str = "whois.nic.jobs"
    JP_HOST: str = "whois.jprs.jp"
    KZ_HOST: str = "whois.nic.kz"
    LAT_HOST: str = "whois.nic.lat"
    LI_HOST: str = "whois.nic.li"
    LNIC_HOST: str = "whois.lacnic.net"
    LT_HOST: str = "whois.domreg.lt"
    MARKET_HOST: str = "whois.nic.market"
    MNIC_HOST: str = "whois.ra.net"
    MONEY_HOST: str = "whois.nic.money"
    MOSKVA_HOST: str = "whois.registry.nic.xn--80adxhks"
    MX_HOST: str = "whois.mx"
    NG_HOST: str = "whois.nic.net.ng"
    NIC_HOST: str = "whois.crsnic.net"
    NL_HOST: str = "whois.domain-registry.nl"
    NORID_HOST: str = "whois.norid.no"
    ONLINE_HOST: str = "whois.nic.online"
    OOO_HOST: str = "whois.nic.ooo"
    PAGE_HOST: str = "whois.nic.page"
    PANDI_HOST: str = "whois.pandi.or.id"
    PE_HOST: str = "kero.yachay.pe"
    PIR_HOST: str = "whois.publicinterestregistry.org"
    PNIC_HOST: str = "whois.apnic.net"
    PPUA_HOST: str = "whois.pp.ua"
    RF_HOST: str = "whois.registry.tcinet.ru"
    RNIC_HOST: str = "whois.ripe.net"
    RU_HOST: str = "whois.nic.ru"
    SHOP_HOST: str = "whois.nic.shop"
    SNIC_HOST: str = "whois.6bone.net"
    STORE_HOST: str = "whois.centralnic.com"
    TN_HOST: str = "whois.ati.tn"
    UKR_HOST: str = "whois.dotukr.com"
    WEBSITE_HOST: str = "whois.nic.website"
    ZA_HOST: str = "whois.registry.net.za"

    # DNS: The name tld.whois-servers.net is a CNAME to the appropriate whois-server.
    # Somewhat unclear who actually maintains this.
    # from: https://serverfault.com/questions/343941/how-can-i-find-the-whois-server-for-any-tld
    # 2023-07-23: whois whois-servers.net
    # [Querying whois.verisign-grs.com]
    # [Redirected to whois.tucows.com]
    # [Querying whois.tucows.com]
    # [whois.tucows.com]
    # This feature depends on which whois client you use.
    # Not all of them do that, for good or bad reason.
    #  whois-servers.net is still not an official service,
    #  just something done on a best effort case.

    # ----------------------------------------
    QNICHOST_HEAD: str = "whois.nic." # try whois.nic.<tld>
    QNICHOST_TAIL: str = ".whois-servers.net" # try <tld>.whois-server.net

    # ----------------------------------------
    WHOIS_RECURSE: int = 0x01
    WHOIS_QUICK: int = 0x02

    # ----------------------------------------
    ip_whois: List[str] = [
        LNIC_HOST,
        RNIC_HOST,
        PNIC_HOST,
        BNIC_HOST,
        PANDI_HOST,
    ]

    # ----------------------------------------
    verbose: bool = False

    domain: str
    options: Dict[str, Any] = {}
    flags: int = 0
    quiet: bool = False
    use_qnichost: bool = False
    data: List[str] = []

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        if self.verbose:
            print(inspect.currentframe().f_code.co_name, file=sys.stderr)

    def maptable(self, tld):
        if self.verbose:
            print(inspect.currentframe().f_code.co_name, file=sys.stderr)

        table: Dict[str, str] = {
            "ai": self.AI_HOST,
            "app": self.APP_HOST,
            "ar": self.AR_HOST,
            "bw": self.BW_HOST,
            "by": self.BY_HOST,
            "bz": self.RU_HOST,  # ??
            "ca": self.CA_HOST,
            "chat": self.CHAT_HOST,
            "city": self.RU_HOST,  # ??
            "cl": self.CL_HOST,
            "cr": self.CR_HOST,
            "de": self.DE_HOST,
            "design": self.RU_HOST,  # ??
            "dev": self.DEV_HOST,
            "direct": self.IDS_HOST,
            "do": self.DO_HOST,
            "fashion": self.GDD_HOST,
            "games": self.GAMES_HOST,
            "google": self.GOOGLE_HOST,
            "goog": self.GOOGLE_HOST,
            "group": self.GROUP_HOST,
            # "group": self.IDS_HOST, # is double in the original code
            "hk": self.HK_HOST,
            "hn": self.HN_HOST,
            "immo": self.IDS_HOST,
            "ist": self.IST_HOST,
            "jobs": self.JOBS_HOST,
            "jp": self.JP_HOST,
            "kz": self.KZ_HOST,
            "lat": self.LAT_HOST,
            "life": self.IDS_HOST,
            "li": self.LI_HOST,
            "lt": self.LT_HOST,
            "market": self.MARKET_HOST,
            "money": self.MONEY_HOST,
            "mx": self.MX_HOST,
            "ng": self.NG_HOST,
            "nl": self.NL_HOST,
            "online": self.ONLINE_HOST,
            "ooo": self.OOO_HOST,
            "page": self.PAGE_HOST,
            "pe": self.PE_HOST,
            "ru": self.RU_HOST,
            "shop": self.SHOP_HOST,
            "store": self.STORE_HOST,
            "studio": self.RU_HOST,  # ??
            "style": self.RU_HOST,  # ??
            "su": self.RU_HOST,
            "tn": self.TN_HOST,
            "vip": self.GDD_HOST,
            "website": self.WEBSITE_HOST,
            "xn--80adxhks": self.MOSKVA_HOST,
            "xn--c1avg": self.PIR_HOST,
            "xn--d1acj3b": self.DETI_HOST,
            "xn--j1amh": self.UKR_HOST,
            "xn--p1acf": self.RU_HOST,
            "xn--p1ai": self.RF_HOST,
            "za": self.ZA_HOST,
            "дети": self.DETI_HOST,
            "москва": self.MOSKVA_HOST,
            "орг": self.PIR_HOST,
            "рус": self.RU_HOST,
            "рф": self.RF_HOST,
            "укр": self.UKR_HOST,
        }
        return table.get(tld)

    def findWhoisServerInResponse(
        self,
        response: str,
        hostname: str,
        query: str,
    ):
        if self.verbose:
            print(inspect.currentframe().f_code.co_name, file=sys.stderr)

        """
        Search the initial TLD lookup results
          for the regional-specific whois server
          for getting contact details.
        """
        match = re.compile(
            f"Domain Name: {query}" + r"\s*.*?Whois Server: (.*?)\s",
            flags=re.IGNORECASE | re.DOTALL,
        ).search(response)

        nhost = None
        if match:
            nhost = match.groups()[0]
            if nhost.count("/") > 0:
                # if the whois address is domain.tld/something
                # then s.connect((hostname, self.DEFAULT_PORT_NR)) does not work
                nhost = None
            return nhost

        if hostname == self.ANIC_HOST:
            for nichost in self.ip_whois:
                if response.find(nichost) != -1:
                    nhost = nichost
                    break

        return nhost

    def makeSocketWithOptionalSocksProxy(self):
        if self.verbose:
            print(inspect.currentframe().f_code.co_name, file=sys.stderr)

        if "SOCKS" in os.environ:
            try:
                import socks
            except ImportError as e:
                msg = "You need to install the Python socks module. Install PIP "
                "(https://bootstrap.pypa.io/get-pip.py) and then 'pip install PySocks'"
                raise e(msg)

            socks_user, socks_password = None, None
            if "@" in os.environ["SOCKS"]:
                creds, proxy = os.environ["SOCKS"].split("@")
                socks_user, socks_password = creds.split(":")
            else:
                proxy = os.environ["SOCKS"]

            socksproxy, port = proxy.split(":")
            socks_proto = socket.AF_INET

            if socket.AF_INET6 in [
                sock[0]
                for sock in socket.getaddrinfo(
                    socksproxy,
                    port,
                )
            ]:
                socks_proto = socket.AF_INET6

            s = socks.socksocket(socks_proto)
            s.set_proxy(
                socks.SOCKS5,
                socksproxy,
                int(port),
                True,
                socks_user,
                socks_password,
            )
        else:
            s = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )

        return s

    def decodeQuery(self, query: str) -> str:
        if self.verbose:
            print(inspect.currentframe().f_code.co_name, file=sys.stderr)

        try:
            query = query.decode("utf-8")
        except UnicodeEncodeError:
            pass  # Already Unicode (python2's error)
        except AttributeError:
            pass  # Already Unicode (python3's error)

        return query

    def makeQueryBytes(
        self,
        hostname: str,
        query: str,
        many_results: bool,
    ):
        if self.verbose:
            print(inspect.currentframe().f_code.co_name, file=sys.stderr)

        if hostname == self.DENIC_HOST:
            return "-T dn,ace -C UTF-8 " + query

        if hostname == self.DK_HOST:
            return " --show-handles " + query

        if hostname.endswith(self.QNICHOST_TAIL) and many_results is True:
            return "=" + query

        return query

    def testServerExists(
        self,
        tld: str,
    ):
        if self.verbose:
            print(inspect.currentframe().f_code.co_name, file=sys.stderr)

        server = tld + self.QNICHOST_TAIL
        try:
            socket.gethostbyname(server)  # effectivly force a dns lookup
            return server
        except socket.gaierror:
            # your given host name <server> is invalid (gai stands for getaddrinfo()).
            return self.QNICHOST_HEAD + tld

    def testEndsWith(
        self,
        domain: str,
    ):
        if self.verbose:
            print(inspect.currentframe().f_code.co_name, file=sys.stderr)

        if domain.endswith("-NORID"):
            return self.NORID_HOST

        if domain.endswith("id"):
            return self.PANDI_HOST

        if domain.endswith("hr"):
            return self.HR_HOST

        if domain.endswith(".pp.ua"):
            return self.PPUA_HOST

        return None

    def decodeDomain(self, domain: str) -> str:
        if self.verbose:
            print(inspect.currentframe().f_code.co_name, file=sys.stderr)

        try:
            domain = self.domain.encode("idna").decode("utf-8")
        except TypeError:  # py2
            domain = self.domain.decode("utf-8").encode("idna").decode("utf-8")
        except AttributeError:  # py3
            domain = self.domain.decode("utf-8").encode("idna").decode("utf-8")

        return domain

    def chooseServer(
        self,
    ):
        if self.verbose:
            print(inspect.currentframe().f_code.co_name, file=sys.stderr)

        """
        Choose initial lookup NIC host
        """
        domain = self.decodeDomain(self.domain)
        rr = self.testEndsWith(domain)
        if rr:
            return rr

        domain = domain.split(".")
        if len(domain) < 2:
            return None

        tld = domain[-1]
        if tld[0].isdigit():
            return self.ANIC_HOST

        rr = self.maptable(tld)
        if rr is not None:
            return rr

        return self.testServerExists(tld)

    def doSocketRead(
        self,
        s,
        hostname: str,
        query_bytes: str,
    ) -> (str, bool):
        if self.verbose:
            print(inspect.currentframe().f_code.co_name, file=sys.stderr)

        response: str = b""

        try:
            # in order to allow things like:
            #   looping whois on different domains without stopping on timeouts
            # see:
            #   https://stackoverflow.com/questions/25447803/python-socket-connection-exception

            s.connect((hostname, self.DEFAULT_PORT_NR))
            s.send(bytes(query_bytes, "utf-8") + b"\r\n")

            # recv returns bytes
            while True:
                d = s.recv(self.MAX_READ_BUF)
                response += d
                if not d:
                    break

            s.close()

            return response.decode("utf-8", "replace"), False

        except socket.error as exc:
            # 'response' is assigned a value (also a str) even on socket timeout
            msg = f"Error trying to connect to socket: closing socket - {exc}"
            print(msg, file=sys.stderr)

            s.close()
            return f"Socket not responding: {exc}", True

    def whois(
        self,
        query: str,
        hostname: str,
        flags: int,
        many_results: bool = False,
    ):
        if self.verbose:
            print(inspect.currentframe().f_code.co_name, file=sys.stderr)

        msg = f"[[{query} via {hostname}]]"
        print(msg)

        """
        Perform initial lookup with TLD whois server then,
          if the quick flag is false,
          search that result for the region-specific whois server
          and do a lookup there for contact details.
        If `quiet` is `True`,
          will not send a message to stderr when a socket error is encountered.
        """

        s = self.makeSocketWithOptionalSocksProxy()
        s.settimeout(10)

        query = self.decodeQuery(query)
        query_bytes = self.makeQueryBytes(
            hostname,
            query,
            many_results,
        )

        response, final = self.doSocketRead(s, hostname, query_bytes)
        if final:
            return response

        if 'with "=xxx"' in response:
            return self.whois(
                query,
                hostname,
                flags,
                many_results=True,
            )

        nhost = None
        if flags & self.WHOIS_RECURSE and nhost is None:
            nhost = self.findWhoisServerInResponse(
                response,
                hostname,
                query,
            )

        if nhost is not None:
            response += self.whois(
                query,
                nhost,
                0,
            )

        return response

    def initOneQuery(
        self,
        domain: str,
        options: Dict[str, Any] = {},
        flags: int = 0,
        quiet=False,
    ):
        if self.verbose:
            print(inspect.currentframe().f_code.co_name, file=sys.stderr)

        self.domain = domain
        self.options = options
        self.flags = flags
        self.quiet = quiet

        self.nichost = None
        self.use_qnichost = False
        self.data: List[str] = []

    def whois_lookup(
        self,
        domain: str = "",
        options: Dict[str, Any] = {},
        flags: int = 0,
        quiet: bool = False,
    ):
        if self.verbose:
            print(inspect.currentframe().f_code.co_name, file=sys.stderr)

        self.initOneQuery(
            domain=domain,
            options=options,
            flags=flags,
            quiet=quiet,
        )

        """
        Main entry point:
            Perform initial lookup on TLD whois server,
            or other server to get region-specific whois server,
            then if quick flag is false,
            perform a second lookup on the region-specific server for contact records.
        If `quiet` is `True`,
            no message will be printed to STDOUT when a socket error is encountered.
        """

        if (
            self.options.get("whoishost") is None
            and self.options.get("country") is None
        ):
            self.use_qnichost = True
            self.options["whoishost"] = self.NIC_HOST
            if not (self.flags & self.WHOIS_QUICK):
                self.flags |= self.WHOIS_RECURSE

        if self.options.get("country"):
            self.options["country"] + self.QNICHOST_TAIL,
            return self.whois(
                self.domain,
                self.options,
                self.flags,
            )

        if self.use_qnichost:
            self.nichost = self.chooseServer()
            if self.nichost is None:
                return ""

            return self.whois(
                self.domain,
                self.nichost,
                self.flags,
            )

        return self.whois(
            self.domain,
            self.options["whoishost"],
            self.flags,
        )

    def parseMyArgs(
        self,
        argv: Dict[str, str],
    ):
        if self.verbose:
            print(inspect.currentframe().f_code.co_name, file=sys.stderr)

        """
        Options handling mostly follows the UNIX whois(1) man page,
          except long-form options can also be used.
        """
        usage = "usage: %prog [options] name"

        parser = optparse.OptionParser(
            add_help_option=False,
            usage=usage,
        )

        parser.add_option(
            "-a",
            "--arin",
            action="store_const",
            const=PyWhoisClient.ANIC_HOST,
            dest="whoishost",
            help="Lookup using host " + PyWhoisClient.ANIC_HOST,
        )
        parser.add_option(
            "-A",
            "--apnic",
            action="store_const",
            const=PyWhoisClient.PNIC_HOST,
            dest="whoishost",
            help="Lookup using host " + PyWhoisClient.PNIC_HOST,
        )
        parser.add_option(
            "-b",
            "--abuse",
            action="store_const",
            const=PyWhoisClient.ABUSE_HOST,
            dest="whoishost",
            help="Lookup using host " + PyWhoisClient.ABUSE_HOST,
        )
        parser.add_option(
            "-c",
            "--country",
            action="store",
            type="string",
            dest="country",
            help="Lookup using country-specific NIC",
        )
        parser.add_option(
            "-d",
            "--mil",
            action="store_const",
            const=PyWhoisClient.DNIC_HOST,
            dest="whoishost",
            help="Lookup using host " + PyWhoisClient.DNIC_HOST,
        )
        parser.add_option(
            "-g",
            "--gov",
            action="store_const",
            const=PyWhoisClient.GNIC_HOST,
            dest="whoishost",
            help="Lookup using host " + PyWhoisClient.GNIC_HOST,
        )
        parser.add_option(
            "-h",
            "--host",
            action="store",
            type="string",
            dest="whoishost",
            help="Lookup using specified whois host",
        )
        parser.add_option(
            "-i",
            "--nws",
            action="store_const",
            const=PyWhoisClient.INIC_HOST,
            dest="whoishost",
            help="Lookup using host " + PyWhoisClient.INIC_HOST,
        )
        parser.add_option(
            "-I",
            "--iana",
            action="store_const",
            const=PyWhoisClient.IANA_HOST,
            dest="whoishost",
            help="Lookup using host " + PyWhoisClient.IANA_HOST,
        )
        parser.add_option(
            "-l",
            "--lcanic",
            action="store_const",
            const=PyWhoisClient.LNIC_HOST,
            dest="whoishost",
            help="Lookup using host " + PyWhoisClient.LNIC_HOST,
        )
        parser.add_option(
            "-m",
            "--ra",
            action="store_const",
            const=PyWhoisClient.MNIC_HOST,
            dest="whoishost",
            help="Lookup using host " + PyWhoisClient.MNIC_HOST,
        )
        parser.add_option(
            "-p",
            "--port",
            action="store",
            type="int",
            dest="port",
            help="Lookup using specified tcp port",
        )
        parser.add_option(
            "-Q",
            "--quick",
            action="store_true",
            dest="b_quicklookup",
            help="Perform quick lookup",
        )
        parser.add_option(
            "-r",
            "--ripe",
            action="store_const",
            const=PyWhoisClient.RNIC_HOST,
            dest="whoishost",
            help="Lookup using host " + PyWhoisClient.RNIC_HOST,
        )
        parser.add_option(
            "-R",
            "--ru",
            action="store_const",
            const="ru",
            dest="country",
            help="Lookup Russian NIC",
        )
        parser.add_option(
            "-6",
            "--6bone",
            action="store_const",
            const=PyWhoisClient.SNIC_HOST,
            dest="whoishost",
            help="Lookup using host " + PyWhoisClient.SNIC_HOST,
        )
        parser.add_option(
            "-n",
            "--ina",
            action="store_const",
            const=PyWhoisClient.PANDI_HOST,
            dest="whoishost",
            help="Lookup using host " + PyWhoisClient.PANDI_HOST,
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

    nc = PyWhoisClient(verbose=verbose)
    options, args = nc.parseMyArgs(sys.argv)
    if options.b_quicklookup:
        flags = flags | PyWhoisClient.WHOIS_QUICK

    data = nc.whois_lookup(
        args[1],
        options.__dict__,
        flags,
    )
    print(data)
