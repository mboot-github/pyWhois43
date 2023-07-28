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

import os
import optparse
import socket
import sys
import re

# import inspect

from typing import List, Dict, Any, Optional, Tuple


class PyWhoisClient:
    # ----------------------------------------
    DEFAULT_PORT_NAME: str = "nicname"  # /etc/services port 43
    DEFAULT_PORT_NR: int = 43
    MAX_READ_BUF: int = 4096
    DEFAULT_SOCKET_TIMEOUT: int = 10
    # ----------------------------------------
    ABUSE_HOST: str = "whois.abuse.net"
    ANIC_HOST: str = "whois.arin.net"
    BNIC_HOST: str = "whois.registro.br"
    BW_HOST: str = "whois.nic.net.bw"
    BY_HOST: str = "whois.cctld.by"
    CA_HOST: str = "whois.ca.fury.ca"
    DE_HOST: str = "whois.denic.de"
    DENIC_HOST: str = "whois.denic.de"
    DETI_HOST: str = "whois.nic.xn--d1acj3b"
    DK_HOST: str = "whois.dk-hostmaster.dk"
    GDD_HOST: str = "whois.dnrs.godaddy"
    HK_HOST: str = "whois.hkirc.hk"
    HR_HOST: str = "whois.dns.hr"
    IANA_HOST: str = "whois.iana.org"  # <<=
    IDS_HOST: str = "whois.identitydigital.services"
    INIC_HOST: str = "whois.networksolutions.com"
    IST_HOST: str = "whois.afilias-srs.net"
    JP_HOST: str = "whois.jprs.jp"
    LNIC_HOST: str = "whois.lacnic.net"
    LT_HOST: str = "whois.domreg.lt"
    MNIC_HOST: str = "whois.ra.net"
    MOSKVA_HOST: str = "whois.registry.nic.xn--80adxhks"
    MX_HOST: str = "whois.mx"
    NG_HOST: str = "whois.nic.net.ng"
    NIC_HOST: str = "whois.crsnic.net"
    NL_HOST: str = "whois.domain-registry.nl"
    NORID_HOST: str = "whois.norid.no"
    PANDI_HOST: str = "whois.pandi.or.id"
    PE_HOST: str = "kero.yachay.pe"
    PIR_HOST: str = "whois.publicinterestregistry.org"
    PNIC_HOST: str = "whois.apnic.net"
    PPUA_HOST: str = "whois.pp.ua"
    RF_HOST: str = "whois.registry.tcinet.ru"
    RNIC_HOST: str = "whois.ripe.net"
    RU_HOST: str = "whois.nic.ru"
    SNIC_HOST: str = "whois.6bone.net"
    STORE_HOST: str = "whois.centralnic.com"
    TN_HOST: str = "whois.ati.tn"
    UKR_HOST: str = "whois.dotukr.com"
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
    QNICHOST_HEAD: str = "whois.nic."  # try whois.nic.<tld>
    QNICHOST_TAIL: str = ".whois-servers.net"  # try <tld>.whois-server.net

    # ----------------------------------------
    WHOIS_RECURSE: int = 0x01
    WHOIS_QUICK: int = 0x02

    # ----------------------------------------
    ip_whois: List[str] = [LNIC_HOST, RNIC_HOST, PNIC_HOST, BNIC_HOST, PANDI_HOST]

    # ----------------------------------------
    verbose: bool = False

    domain: str
    options: Dict[str, Any] = {}
    flags: int = 0
    quiet: bool = False
    use_qnichost: bool = False
    data: List[str] = []

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

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.reportFuncName()

    def maptable(self, tld: str) -> Optional[str]:
        self.reportFuncName()

        # we can remove anythging that works via whois.nic.<tld> or
        table: Dict[str, str] = {
            "bw": self.BW_HOST,
            "by": self.BY_HOST,
            "ca": self.CA_HOST,
            "de": self.DE_HOST,
            "direct": self.IDS_HOST,
            "fashion": self.GDD_HOST,
            "hk": self.HK_HOST,
            "immo": self.IDS_HOST,
            "ist": self.IST_HOST,
            "jp": self.JP_HOST,
            "life": self.IDS_HOST,
            "lt": self.LT_HOST,
            "mx": self.MX_HOST,
            "ng": self.NG_HOST,
            "nl": self.NL_HOST,
            "pe": self.PE_HOST,
            "ru": self.RU_HOST,
            "store": self.STORE_HOST,
            "studio": self.RU_HOST,  # ??
            "style": self.RU_HOST,  # ??
            "su": self.RU_HOST,
            "tn": self.TN_HOST,
            "vip": self.GDD_HOST,
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
    ) -> Optional[str]:
        self.reportFuncName()

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

        if hostname == self.ANIC_HOST:  # "whois.arin.net"
            for nichost in self.ip_whois:
                if response.find(nichost) != -1:
                    nhost = nichost
                    return nhost

        return nhost

    def makeSocketWithOptionalSocksProxy(self) -> Any:
        self.reportFuncName()

        if "SOCKS" in os.environ:
            try:
                import socks  # type: ignore
            except ImportError as e:
                msg: str = (
                    f"{e}: You need to install the Python socks module. Install PIP "
                )
                "(https://bootstrap.pypa.io/get-pip.py) and then 'pip install PySocks'"
                raise Exception(msg)

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
        self.reportFuncName()

        # You are trying to decode an object that is already decoded.
        # You have a str, there is no need to decode from UTF-8 anymore.
        # Simply drop the .decode('utf-8') part:

        return query

    def makeQueryBytes(
        self,
        hostname: str,
        query: str,
        many_results: bool,
    ) -> str:
        self.reportFuncName()

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
    ) -> str:
        self.reportFuncName()

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
    ) -> Optional[str]:
        self.reportFuncName()

        if domain.endswith("-NORID"):
            return self.NORID_HOST  # "whois.norid.no"

        if domain.endswith("id"):
            return self.PANDI_HOST  # "whois.pandi.or.id"

        # whois.nic.hr now also exists , no need for a special case
        # if domain.endswith("hr"):
        #    return self.HR_HOST # "whois.dns.hr"

        if domain.endswith(".pp.ua"):
            # https://support.nic.ua/en-us/article/335-pp-ua-domains-restrictions
            # test with zzz.pp.ua
            return self.PPUA_HOST  # "whois.pp.ua"

        return None

    def decodeDomain(
        self,
        domain: str,
    ) -> str:
        self.reportFuncName()

        return str(self.domain.encode("idna"))

    def chooseServer(
        self,
    ) -> Optional[str]:
        self.reportFuncName()

        """
        Choose initial lookup NIC host
        """
        domain = self.decodeDomain(self.domain)
        rr = self.testEndsWith(domain)
        if rr:
            return rr

        dList: List[str] = domain.split(".")
        if len(dList) < 2:
            return None

        tld = dList[-1]
        if tld[0].isdigit():
            return self.ANIC_HOST  # "whois.arin.net"

        rr = self.maptable(tld)
        if rr is not None:
            return rr

        return self.testServerExists(tld)

    def doSocketRead(
        self,
        s: Any,
        hostname: str,
        query_bytes: str,
    ) -> Tuple[str, bool]:
        self.reportFuncName()

        response: bytes = b""

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

            return str(response), False

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
    ) -> Optional[str]:
        self.reportFuncName()

        msg = f"[[{query} via {hostname}]]"
        print(msg, file=sys.stderr)

        """
        Perform initial lookup with TLD whois server then,
          if the quick flag is false,
          search that result for the region-specific whois server
          and do a lookup there for contact details.
        If `quiet` is `True`,
          will not send a message to stderr when a socket error is encountered.
        """

        s = self.makeSocketWithOptionalSocksProxy()
        s.settimeout(self.DEFAULT_SOCKET_TIMEOUT)

        query = self.decodeQuery(query)
        query_bytes = self.makeQueryBytes(
            hostname,
            query,
            many_results,
        )

        response, final = self.doSocketRead(
            s,
            hostname,
            query_bytes,
        )
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
            r2: Optional[str] = self.whois(
                query,
                nhost,
                0,
            )
            if r2 is not None:
                response += r2

        return response

    def initOneQuery(
        self,
        domain: str,
        options: Dict[str, Any] = {},
        flags: int = 0,
        quiet: bool = False,
    ) -> None:
        self.reportFuncName()

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
    ) -> Optional[str]:
        self.reportFuncName()

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

        nichost = None
        # whoud happen when this function is called by other than main
        if options is None:
            options = {}

        if options.get("country"):
            return self.whois(
                domain,
                options["country"] + PyWhoisClient.QNICHOST_TAIL,
                flags=flags,
            )

        if (options.get("whoishost") is None) and (options.get("country") is None):
            self.use_qnichost = True  # use verisign as default
            options["whoishost"] = PyWhoisClient.NIC_HOST

            if not (flags & PyWhoisClient.WHOIS_QUICK):
                flags |= PyWhoisClient.WHOIS_RECURSE

        if self.use_qnichost:
            nichost = self.chooseServer()
            if nichost:
                return self.whois(
                    domain,
                    nichost,
                    flags=flags,
                )
            return ""

        return self.whois(
            domain,
            options["whoishost"],  # here we possibly use the default we set earlier
            flags=flags,
        )

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

        # explicitly request a country and use: <country>".whois-servers.net as whoishost"
        parser.add_option(
            "-c",
            "--country",
            action="store",
            type="string",
            dest="country",
            help="Lookup using country-specific NIC",
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
