import logging

import requests
from requests import RequestException

log = logging.getLogger("passleak_loader")


class LeaksLoader:
    def __init__(self, conf):
        self._session = None
        self._is_connected = False
        self.already_processed = False
        self._domains = []
        self._leaks_by_domain = {}

        self._proxy_config = conf.get("proxy")
        self._passleak_config = conf

        self._CON_TIMEOUT = (conf.get("contimeout", 10), conf.get("readtimeout", 20))
        self._CON_RETRY = conf.get("retry", 2)

        self.base_url:str = conf["baseurl"]
        self.apikey: str = conf["apikey"]

    def init_connection(self):
        """
        Try to connect to cloud
        :return: None
        """
        self._is_connected = False
        proxy = None
        if self._proxy_config:
            proxy = {self._proxy_config["type"]: self._proxy_config["url"].strip()}
        for i in range(1, self._CON_RETRY + 1):
            log.debug(
                "Try (" + str(i) + ") connect to: " + self._passleak_config["baseurl"]
            )
            if proxy:
                log.debug("Using proxy: " + str(proxy))

            if self._try_connect(
                proxy=proxy,
            ):
                self._is_connected = True
                log.debug("Try(" + str(i) + "). Connection succeed")
                break
        if not self._is_connected:
            raise Exception("Cannot connect: " + self._passleak_config["baseurl"])

    def _try_connect(self, proxy=None):
        """
        Connection worker
        :param proxy: Requests proxies dict
        :return: True - if connection succeed
        """
        self._session = requests.Session()
        self._session.headers = {"Accept": "*/*", "Token": self.apikey}
        self._session.proxies = proxy
        self._session.verify = False
        api_url = self.base_url + "domains"
        try:
            log.debug(f"Trying GET {api_url}")
            r = self._session.get(url=api_url.format(), timeout=self._CON_TIMEOUT)
            if r.status_code != 200:
                raise Exception(
                    'Test exec code not 200: {0!s}. Server msg: "{1!s}"'.format(
                        r.status_code, r.text
                    )
                )
            else:
                log.info("Connection to API checked")
        except RequestException as e:
            log.error("Error: " + str(e))
            return False
        return True

    def download_leaks_data(self, state) -> dict:
        self.__download_domains()
        for domain in self._domains:
            log.debug(f"loading leaks for domain id={domain['id']} host={domain['host']}")
            self.__download_domain_leaks(domain['id'], domain['host'], state)
        return self._leaks_by_domain

    def __download_domains(self):
        api_url = self.base_url + "domains"
        r = self._session.get(url=api_url.format(), timeout=self._CON_TIMEOUT)
        if r.status_code != 200:
            raise Exception("cannot load domains list")
        try:
            req_res = r.json()
            domains_res = req_res['items']
            log.info(f"received domains: {domains_res}")
            for dm in domains_res:
                if not dm.get('approved'):
                    log.debug(f"not approved domain {dm}")
                    continue
                self._domains.append(dm)
        except Exception as e:
            raise Exception(f"cannot process domains list: {e}")

    def __download_domain_leaks(self, domain_id, host: str, state):
        api_url = self.base_url + "monitoring"
        req_data = {
            "domain": domain_id,
        }
        r = self._session.get(url=api_url.format(), params=req_data, timeout=self._CON_TIMEOUT)
        if r.status_code != 200:
            raise Exception("cannot load domains list")
        try:
            req_res = r.json()
            last_record = state.get(host)
            if last_record is not None:
                domain_leaks = []
                for leak in req_res['items']:
                    if leak['record_id'] == last_record:
                        break
                    domain_leaks.append(leak)
                if len(domain_leaks) > 0:
                    self._leaks_by_domain[host] = domain_leaks
            else:
                self._leaks_by_domain[host] = req_res['items']
        except Exception as e:
            raise Exception(f"Cannot load leaks for domain id={domain_id}")


