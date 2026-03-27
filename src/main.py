import os
import sys
import time
import traceback
import uuid
from datetime import datetime
from typing import List

import stix2
import yaml
from pycti import (
    Identity,
    OpenCTIConnectorHelper,
    get_config_variable,
)
from passleak import (
    LeaksLoader,
    read_state,
    write_state,
)

SCO_DET_ID_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")


def uuid_from_string(val: str) -> str:
    return str(uuid.uuid5(SCO_DET_ID_NAMESPACE, val))


class PasslekLeaks:
    def __init__(self):
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )

        self.helper = OpenCTIConnectorHelper(config)

        self.interval = self.get_config("interval", config, 86400)
        self._state_dir = self.get_config("dirs_tmp", config, "/tmp")
        self._downloader_config = {
            "baseurl": self.get_config("baseurl", config, "https://api.passleak.com/"),
            "apikey": self.get_config("api_key", config, None),
            "contimeout": int(self.get_config("contimeout", config, 30)),
            "readtimeout": int(self.get_config("readtimeout", config, 60)),
            "retry": int(self.get_config("retry", config, 5)),
        }

    @staticmethod
    def get_config(name: str, config, default=None):
        env_name = "PASSLEAK_{}".format(name.upper())
        result = get_config_variable(env_name, ["passleak-leaks", name], config)
        return result if result is not None else default

    def get_interval(self) -> int:
        return int(self.interval)

    def run(self):
        self.helper.log_info("Starting PassLeak connector")

        while True:
            try:
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    last_run_str = datetime.utcfromtimestamp(last_run).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    self.helper.log_info(f"Connector's last run: {last_run_str}")
                else:
                    last_run = None
                    self.helper.log_info("Connector's first run")

                if last_run is None or ((timestamp - last_run) > self.get_interval()):
                    self._process_leaks()
                    self.helper.set_state({"last_run": timestamp})
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        f"Connector will not run. Next run in: {round(new_interval, 2)} seconds."
                    )
            except (KeyboardInterrupt, SystemExit):
                self.helper.log_info("Connector stopped")
                sys.exit(0)
            except Exception as ex:
                self.helper.log_error(str(ex))
                raise ex

            if self.helper.connect_run_and_terminate:
                self.helper.log_info("Connector stopped")
                self.helper.force_ping()
                sys.exit(0)

            time.sleep(60)

    def _process_leaks(self):
        state = read_state(self._state_dir)
        downloader = LeaksLoader(self._downloader_config)
        downloader.init_connection()
        leaks_by_domain = downloader.download_leaks_data(state)

        if not leaks_by_domain:
            self.helper.log_info("No new events to process")
            return

        stix_bundles = self._create_stix_bundles(leaks_by_domain)
        for bundle in stix_bundles:
            self._batch_send(bundle)

        # Сохраняем новые offset'ы для каждого домена
        for domain, data in leaks_by_domain.items():
            state[domain] = {"offset": data["new_offset"]}
        write_state(self._state_dir, state)

    def _create_stix_bundles(self, leaks_by_domain: dict) -> list:
        self.helper.log_info(f"Processing leaks for domains: {list(leaks_by_domain.keys())}")

        res_bundles = []

        for domain, data in leaks_by_domain.items():
            leaks = data["items"]
            stix_bundle = []

            organization = stix2.v21.Identity(
                id=Identity.generate_id("PassLeak", "organization"),
                name="Passleak",
                identity_class="organization",
                description="Passleak Company https://passleak.com",
            )
            stix_bundle.append(organization)

            domain_identity = stix2.v21.Identity(
                id=Identity.generate_id(domain, "organization"),
                name=domain,
                identity_class="organization",
            )
            stix_bundle.append(domain_identity)

            self.helper.log_info(f"Converting {len(leaks)} events for domain {domain} to STIX")

            # Группируем инциденты по source (заменяет leak_id)
            incident_by_source = {}
            # Дедупликатор Malware объектов — per-bundle (per-domain)
            malware_by_type = {}
            # Множество уже добавленных связей incident→malware
            incident_malware_rels = set()

            for rec in leaks:
                source = rec.get("source") or "unknown"
                event_time = rec.get("event_time") or None
                stealer_type = rec.get("stealer_type") or None

                # --- Incident (по source) ---
                incident = incident_by_source.get(source)
                if incident is None:
                    try:
                        created_dt = datetime.fromisoformat(event_time) if event_time else datetime.now()
                    except (ValueError, TypeError):
                        created_dt = datetime.now()
                    incident_name = (
                        f"Credential leak [{source}] for {domain}"
                        if source != "unknown"
                        else f"Credential leak for {domain}"
                    )
                    incident = stix2.v21.Incident(
                        created_by_ref=organization.id,
                        created=created_dt,
                        name=incident_name,
                        description=f"Source: {source}",
                    )
                    incident_by_source[source] = incident
                    stix_bundle.append(incident)
                    stix_bundle.append(
                        stix2.v21.Relationship(
                            source_ref=incident.id,
                            target_ref=domain_identity.id,
                            relationship_type="related-to",
                        )
                    )

                # --- Malware (stealer_type) ---
                if stealer_type:
                    malware = malware_by_type.get(stealer_type)
                    if malware is None:
                        malware = stix2.v21.Malware(
                            id="malware--" + uuid_from_string(f"stealer:{stealer_type}"),
                            created_by_ref=organization.id,
                            name=stealer_type,
                            is_family=True,
                            malware_types=["stealer"],
                        )
                        malware_by_type[stealer_type] = malware
                        stix_bundle.append(malware)

                    rel_key = (incident.id, malware.id)
                    if rel_key not in incident_malware_rels:
                        incident_malware_rels.add(rel_key)
                        stix_bundle.append(
                            stix2.v21.Relationship(
                                source_ref=incident.id,
                                target_ref=malware.id,
                                relationship_type="related-to",
                            )
                        )

                # --- UserAccount ---
                email = rec.get("email") or ""
                login = rec.get("login") or ""
                password = rec.get("password") or ""

                identity = email or login
                if not identity:
                    continue

                account_id = "user-account--" + uuid_from_string(identity + password)
                user_account = stix2.v21.UserAccount(
                    id=account_id,
                    credential=password,
                    user_id=identity,
                    custom_properties=dict(
                        x_opencti_description=domain,
                        x_opencti_author="Passleak",
                    ),
                )
                stix_bundle.append(user_account)
                stix_bundle.append(
                    stix2.v21.Relationship(
                        source_ref=user_account.id,
                        target_ref=incident.id,
                        relationship_type="related-to",
                    )
                )
                stix_bundle.append(
                    stix2.v21.Relationship(
                        source_ref=user_account.id,
                        target_ref=domain_identity.id,
                        relationship_type="related-to",
                    )
                )

            res_bundles.append(stix_bundle)

        return res_bundles

    def _batch_send(self, stix_bundle: List):
        timestamp = int(time.time())
        now = datetime.utcfromtimestamp(timestamp)
        friendly_name = "Sending bundle @ {}".format(now.strftime("%Y-%m-%d %H:%M:%S"))

        self.helper.log_debug(f"Start uploading {len(stix_bundle)} objects")
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        bundle = stix2.v21.Bundle(objects=stix_bundle, allow_custom=True)
        self.helper.send_stix2_bundle(
            bundle=bundle.serialize(),
            update=True,
            work_id=work_id,
        )
        self.helper.log_info(
            f"Connector ran successfully, saving last_run as {timestamp}"
        )
        message = f"Last_run stored, next run in: {self.get_interval()} seconds"
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_debug("End of batch upload")


if __name__ == "__main__":
    try:
        connector = PasslekLeaks()
        connector.run()
    except Exception as ex:
        print(str(ex))
        traceback.print_tb(ex.__traceback__)
        time.sleep(10)
        sys.exit(0)
