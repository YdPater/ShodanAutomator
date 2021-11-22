from shodan import Shodan
from shodan.exception import APIError
from argparse import ArgumentParser
import logging

__version__ = 0.1

banner = f'''
   _____ __              __            ___         __                        __            
  / ___// /_  ____  ____/ /___ _____  /   | __  __/ /_____  ____ ___  ____ _/ /_____  _____
  \__ \/ __ \/ __ \/ __  / __ `/ __ \/ /| |/ / / / __/ __ \/ __ `__ \/ __ `/ __/ __ \/ ___/
 ___/ / / / / /_/ / /_/ / /_/ / / / / ___ / /_/ / /_/ /_/ / / / / / / /_/ / /_/ /_/ / /    
/____/_/ /_/\____/\__,_/\__,_/_/ /_/_/  |_\__,_/\__/\____/_/ /_/ /_/\__,_/\__/\____/_/     
                                                                                           
Version: {__version__}

'''

logFormatter = logging.Formatter(
    "[%(levelname)s] - [%(asctime)s]: %(message)s")
rootLogger = logging.getLogger()
rootLogger.level = logging.INFO

fileHandler = logging.FileHandler("shodanautomator.log")
fileHandler.setFormatter(logFormatter)
rootLogger.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
rootLogger.addHandler(consoleHandler)


class MissingHostOrHosts(Exception):
    """The uses failed to submit a single host or supply a list of hosts"""
    def __init__(self, _message="No host or hostfile submitted!") -> None:
        self.message = _message
        super().__init__(self.message)
        rootLogger.error(self.message)


class ShodanHostResult:
    def __init__(self, ip: str, ports: list, hostnames: list) -> None:
        self._ip = ip
        self._ports = ports
        self._hostnames = hostnames

    @property
    def ip(self) -> str:
        return self._ip

    @property
    def ports(self) -> list:
        return self._ports

    @property
    def hostnames(self) -> list:
        return self._hostnames

    @ip.setter
    def ip(self, ip) -> None:
        if not isinstance(ip, str):
            raise ValueError("IP must be of type string")
        self._ip = ip

    @ports.setter
    def port(self, ports) -> None:
        if not isinstance(ports, list):
            raise ValueError("Ports must be of type list containing dicts")
        self._ports = ports

    @hostnames.setter
    def hostnames(self, hostnames) -> None:
        if not isinstance(hostnames, list):
            raise ValueError("Hostnames must be of type list")
        self._hostnames = hostnames

    def __repr__(self) -> str:
        return f"Shodan host result - IP: {self.ip}; Ports: {self.ports}; Hostnames: {self.hostnames}"


class ShodanScanner:
    def __init__(self, api_key: str, hosts: list) -> None:
        self._api_key = api_key
        self._hosts = hosts

    @property
    def api_key(self) -> str:
        return self._api_key

    @property
    def hosts(self) -> list:
        return self._hosts

    @api_key.setter
    def api_key(self, api_key) -> None:
        if not isinstance(api_key, str):
            raise ValueError("The API key must be a string.")
        self._api_key = api_key

    @hosts.setter
    def hosts(self, hosts):
        if not isinstance(hosts, list):
            raise ValueError("The hosts input must be a list.")
        self._hosts = hosts

    def __repr__(self) -> str:
        return f"Scanner object: api_key: {self.api_key}, hosts: {self._hosts}"

    def scan_hosts(self) -> list:
        shodan_hosts = []
        api = Shodan(self.api_key)
        for h in self.hosts:
            result = None
            try:
                result = api.host(h)
            except APIError as error_message:
                rootLogger.error(
                    f"API error occured for {h}, reason: {error_message}")
                continue

            ports = []
            for data_item in result['data']:
                p = {
                    "portnumber": data_item['port'],
                    "transport": data_item['transport']
                }
                ports.append(p)
            try:
                shodan_hosts.append(
                    ShodanHostResult(result["ip_str"], ports,
                                     result['hostnames']))
            except ValueError as v:
                rootLogger.error(
                    f"ValueError occured while creating new host result: {v}")

        return shodan_hosts


if __name__ == "__main__":
    print(banner)
    parser = ArgumentParser(
        description=
        "ShodanAutomator automates the search of hosts from an input list. More to come."
    )
    parser.add_argument("API_KEY",
                        type=str,
                        help="Submit your Shodan API key. This is required.")
    parser.add_argument("--host", type=str, help="Input a single host")
    parser.add_argument("--host-file",
                        type=str,
                        help="Input a file with hosts. Each on a new line.")
    parser.add_argument("--verbose",
                        "-v",
                        action="store_true",
                        help="Enable verbose ouptput (debug logging)")
    args = parser.parse_args()

    if not args.host and not args.host_file:
        raise MissingHostOrHosts()

    if args.verbose:
        rootLogger.level = logging.DEBUG

    _hosts = []
    if args.host:
        h = args.host.strip()
        _hosts.append(h)

    if args.host_file:
        with open(args.host_file, "r") as infile:
            for line in infile:
                line = line.strip()
                _hosts.append(line)

    scanner = ShodanScanner(api_key=args.API_KEY, hosts=_hosts)
    rootLogger.info("Scanner configured! Staring scan...")
    output = scanner.scan_hosts()
    for r in output:
        rootLogger.info(f"[*] - {r}")
    rootLogger.info("Scanner finished.")
