import logging

import requests
from requests import RequestException

log = logging.getLogger("passleak_loader")

_PAGE_SIZE = 200


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

        self.base_url: str = conf["baseurl"].rstrip("/") + "/"
        self.apikey: str = conf["apikey"]

    def init_connection(self):
        self._is_connected = False
        proxy = None
        if self._proxy_config:
            proxy = {self._proxy_config["type"]: self._proxy_config["url"].strip()}
        for i in range(1, self._CON_RETRY + 1):
            log.debug(f"Try ({i}) connect to: {self._passleak_config['baseurl']}")
            if proxy:
                log.debug(f"Using proxy: {proxy}")
            if self._try_connect(proxy=proxy):
                self._is_connected = True
                log.debug(f"Try({i}). Connection succeed")
                break
        if not self._is_connected:
            raise Exception(f"Cannot connect: {self._passleak_config['baseurl']}")

    def _try_connect(self, proxy=None):
        self._session = requests.Session()
        self._session.headers = {"Accept": "*/*", "Token": self.apikey}
        self._session.proxies = proxy
        self._session.verify = False
        api_url = self.base_url + "domains"
        try:
            log.debug(f"Trying GET {api_url}")
            r = self._session.get(url=api_url, timeout=self._CON_TIMEOUT)
            if r.status_code != 200:
                raise Exception(
                    f"Test exec code not 200: {r.status_code}. Server msg: {r.text!r}"
                )
            log.info("Connection to API checked")
        except RequestException as e:
            log.error(f"Error: {e}")
            return False
        return True

    def download_leaks_data(self, state: dict) -> dict:
        """Загружает новые события мониторинга для всех одобренных доменов.

        state: {host: {"offset": N}} — позиция последнего прочитанного элемента.
        Возвращает {host: {"items": [...], "new_offset": M}}.
        """
        self.__download_domains()
        for domain in self._domains:
            log.debug(f"loading leaks for domain id={domain['id']} host={domain['host']}")
            self.__download_domain_leaks(domain["id"], domain["host"], state)
        return self._leaks_by_domain

    def __download_domains(self):
        api_url = self.base_url + "domains"
        r = self._session.get(url=api_url, timeout=self._CON_TIMEOUT)
        if r.status_code != 200:
            raise Exception(f"Cannot load domains list: {r.status_code}")
        try:
            domains_res = r.json()["items"]
            log.info(f"Received {len(domains_res)} domains")
            for dm in domains_res:
                if not dm.get("approved"):
                    log.debug(f"Skipping not-approved domain: {dm}")
                    continue
                self._domains.append(dm)
        except Exception as e:
            raise Exception(f"Cannot process domains list: {e}")

    def __download_domain_leaks(self, domain_id: str, host: str, state: dict):
        """Постранично загружает события начиная с сохранённого offset."""
        api_url = self.base_url + "monitoring"

        stored = state.get(host)
        # Backward compat: старый формат хранил record_id (str), новый — dict с offset
        if isinstance(stored, dict):
            start_offset = stored.get("offset", 0)
        else:
            start_offset = 0

        new_items = []
        offset = start_offset

        while True:
            params = {"domain": domain_id, "offset": offset, "limit": _PAGE_SIZE}
            r = self._session.get(url=api_url, params=params, timeout=self._CON_TIMEOUT)
            if r.status_code != 200:
                raise Exception(
                    f"Cannot load monitoring for domain {domain_id}: {r.status_code} {r.text!r}"
                )
            try:
                data = r.json()
                items = data.get("items", [])
                paging = data.get("paging", {})
            except Exception as e:
                raise Exception(f"Cannot parse monitoring response for domain {domain_id}: {e}")

            new_items.extend(items)

            if not paging.get("has_more") or not items:
                break
            offset += len(items)

        if new_items:
            log.info(
                f"Domain {host}: {len(new_items)} new events "
                f"(offset {start_offset} → {start_offset + len(new_items)})"
            )
            self._leaks_by_domain[host] = {
                "items": new_items,
                "new_offset": start_offset + len(new_items),
            }
        else:
            log.info(f"Domain {host}: no new events")
