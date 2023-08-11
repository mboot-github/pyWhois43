import os
import socket
import sys
import re


from typing import (
    Any,
    List,
    Optional,
    Tuple,
)

from whoisHostData import WhoisHostData


class PyWhoisClient(WhoisHostData):
    # ----------------------------------------
    DEFAULT_PORT_NAME: str = "nicname"  # /etc/services port 43
    DEFAULT_PORT_NR: int = 43
    MAX_READ_BUF: int = 4096
    DEFAULT_SOCKET_TIMEOUT: int = 10
    # ----------------------------------------

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
    WHOIS_RECURSE: int = 0x01
    WHOIS_QUICK: int = 0x02

    # domain: str
    # options: Dict[str, Any] = {}
    # flags: int = 0
    # quiet: bool = False
    # use_qnichost: bool = False
    # data: List[str] = []

    def __init__(
        self,
        verbose: bool = False,
    ):
        super().__init__(verbose=verbose)
        self.reportFuncName()

    def makeSocketWithOptionalSocksProxy(self) -> Any:
        self.reportFuncName()

        if "SOCKS" in os.environ:
            try:
                import socks  # type: ignore
            except ImportError as e:
                msg: str = f"{e}: You need to install the Python socks module. Install PIP "
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

    def makeQueryBytes(
        self,
        query: str,
        hostname: str,
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

    def doSocketRead(
        self,
        s: Any,
        hostname: str,
        query_bytes: str,
    ) -> Tuple[str, bool]:
        self.reportFuncName()

        if self.verbose:
            print(f"{hostname} {self.DEFAULT_PORT_NR}", file=sys.stderr)

        try:
            # in order to allow things like:
            #   looping whois on different domains without stopping on timeouts
            #   https://stackoverflow.com/questions/25447803/python-socket-connection-exception

            s.connect((hostname, self.DEFAULT_PORT_NR))
            s.send(bytes(query_bytes, "utf-8") + b"\r\n")

        except socket.error as exc:
            msg = f"Error trying to connect to socket: closing socket - {exc}"
            print(msg, file=sys.stderr)
            s.close()
            return f"Socket not responding: {exc}", True

        response: bytes = b""
        try:
            while True:
                d = s.recv(self.MAX_READ_BUF)
                response += d
                if not d:
                    break

            s.close()
        except Exception as e:
            print(f"{e}", file=sys.stderr)

        return response.decode("utf-8"), False  # allow for partial response

    def queryOneServer(
        self,
        query: str,
        hostname: str,
        many_results: bool = False,
    ) -> Tuple[str, bool]:
        self.reportFuncName()

        if self.verbose:
            print(f"query: {query}, hostname: {hostname}", file=sys.stderr)

        s = self.makeSocketWithOptionalSocksProxy()
        s.settimeout(self.DEFAULT_SOCKET_TIMEOUT)

        query_bytes: str = self.makeQueryBytes(
            query,
            hostname,
            many_results,
        )

        return self.doSocketRead(
            s,
            hostname,
            query_bytes,
        )

    def haveMatch(self, nhost: str) -> Optional[str]:

        if self.verbose:
            print(f"{nhost}", file=sys.stderr)

        if nhost.count("/") > 0:
            # if the whois address is domain.tld/something
            # then s.connect((hostname, self.DEFAULT_PORT_NR)) does not work
            return None

        if self.verbose:
            print(f"{nhost}", file=sys.stderr)

        return nhost

    def findWhoisServerInResponse(
        self,
        query: str,
        hostname: str,
        response: str,
    ) -> Optional[str]:
        self.reportFuncName()

        """
        Search the initial TLD lookup results
          for the regional-specific whois server
          for getting contact details.
        """

        r1 = f"domain name: {query}"
        if re.search(r1, response, re.IGNORECASE):
            r2 = r"\s*.*?whois server:\s*([\.\w]+)"
            match = re.search(r2, response, re.IGNORECASE)
            if match:
                return self.haveMatch(nhost=match.groups()[0])

        nhost: Optional[str] = None
        if hostname == self.ANIC_HOST:  # "whois.arin.net"
            for nichost in self.ip_whois:
                if response.find(nichost) != -1:
                    nhost = nichost
                    return nhost

        return nhost

    def whois(
        self,
        query: str,
        hostname: str,
        flags: int,
        many_results: bool = False,
    ) -> str:
        self.reportFuncName()
        data: List[str] = []

        # ---------------------------------
        meta = f"[[query: {query} using {hostname}; flags: {flags}, many: {many_results} ]]"
        data.append(meta)
        response, final = self.queryOneServer(
            query,
            hostname,
            many_results,
        )
        data.append(response)
        # ---------------------------------

        if final:
            return "\n".join(data)

        # this redoes the query above,
        # not sure if that is actually needed still
        #   rfc1036/whois has no special treatment for "=xxx"
        if 'with "=xxx"' in response:
            response = self.whois(
                query,
                hostname,
                flags=flags,
                many_results=True,
            )
            data.append(response)
            return "\n".join(data)

        nhost = None
        if flags & self.WHOIS_RECURSE and nhost is None:
            nhost = self.findWhoisServerInResponse(
                query,
                hostname,
                response,
            )

        if nhost is not None:
            response = self.whois(
                query,
                hostname=nhost,
                flags=0,
            )
            data.append(response)

        return "\n".join(data)
