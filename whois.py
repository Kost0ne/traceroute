from ipwhois import IPWhois


class Whois:
    def __init__(self, destination: str):
        self.destination = destination
        self.ip_rdap_result = self.__get_ip_rdap_result()

    def __get_ip_rdap_result(self) -> dict:
        whois = IPWhois(self.destination)
        return whois.lookup_rdap(depth=1)

    @property
    def asn(self) -> str:
        return self.ip_rdap_result['asn'].split(' ')[0]
