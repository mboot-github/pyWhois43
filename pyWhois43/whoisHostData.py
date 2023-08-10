import socket
import sys

from typing import (
    List,
    Dict,
    Optional,
)

from hasReporting import HasReporting


class WhoisHostData(HasReporting):
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

    QNICHOST_TAIL: str = ".whois-servers.net"  # try <tld>.whois-server.net
    # ----------------------------------------
    QNICHOST_HEAD: str = "whois.nic."  # try whois.nic.<tld>

    # ----------------------------------------
    ip_whois: List[str] = [
        LNIC_HOST,
        RNIC_HOST,
        PNIC_HOST,
        BNIC_HOST,
        PANDI_HOST,
    ]

    def __init__(
        self,
        verbose: bool = False,
    ):
        super().__init__(verbose=verbose)

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

    def testServerExists(
        self,
        tld: str,
    ) -> str:
        self.reportFuncName()

        server = tld + self.QNICHOST_TAIL
        if self.verbose:
            print(f"try: {server}", file=sys.stderr)
        try:
            socket.gethostbyname(server)  # effectivly force a dns lookup
            if self.verbose:
                print(f"{server}", file=sys.stderr)

            return server
        except socket.gaierror:
            if self.verbose:
                print(f"force {self.QNICHOST_HEAD + tld}", file=sys.stderr)
            # your given host name <server> is invalid (gai stands for getaddrinfo()).
            return str(self.QNICHOST_HEAD + tld)

    def testEndsWith(
        self,
        domain: str,
    ) -> Optional[str]:
        self.reportFuncName()

        if domain.endswith("-NORID"):
            return self.NORID_HOST  # "whois.norid.no"

        if domain.endswith("id"):
            return self.PANDI_HOST  # "whois.pandi.or.id"

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

        zz = domain.encode("idna").decode("utf-8")
        if self.verbose:
            print(f"{domain}; {zz}", file=sys.stderr)

        return zz

    def chooseServer(
        self,
        domain: str,
    ) -> Optional[str]:
        self.reportFuncName()

        if self.verbose:
            print(f"{domain}", file=sys.stderr)

        """
        Choose initial lookup NIC host
        """
        domain = self.decodeDomain(domain)
        rr = self.testEndsWith(domain)
        if rr:
            if self.verbose:
                print(f"{domain} {rr}", file=sys.stderr)
            return rr

        dList: List[str] = domain.split(".")
        if len(dList) < 2:
            return None

        tld = dList[-1]
        if tld[0].isdigit():
            return self.ANIC_HOST  # "whois.arin.net"

        rr = self.maptable(tld)
        if rr is not None:
            if self.verbose:
                print(f"{domain} {rr}", file=sys.stderr)
            return rr

        if self.verbose:
            print(f"{domain} {tld}", file=sys.stderr)

        return self.testServerExists(tld)
