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


def uuid_from_string(val: str):
    val = uuid.uuid5(SCO_DET_ID_NAMESPACE, val)
    return val


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
            "baseurl": self.get_config(
                "baseurl", config, "https://api.passleak.com/"
            ),
            "apikey": self.get_config("api_key", config, None),
            "contimeout": int(self.get_config("contimeout", config, 30)),
            "readtimeout": int(self.get_config("readtimeout", config, 60)),
            "retry": int(self.get_config("retry", config, 5)),
        }

    @staticmethod
    def get_config(name: str, config, default=None):
        env_name = "PASSLEAK_{}".format(name.upper())
        result = get_config_variable(env_name, ["passleak-leaks", name], config)
        if result is not None:
            return result
        else:
            return default

    def get_interval(self) -> int:
        return int(self.interval)

    def run(self):
        self.helper.log_info("Starting Passleak connector")

        while True:
            try:
                timestamp = int(time.time())
                current_state = self.helper.get_state()
                if current_state is not None and "last_run" in current_state:
                    last_run = current_state["last_run"]
                    last_run_str = datetime.utcfromtimestamp(last_run).strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )
                    self.helper.log_info(
                        "Connector's last run: {}".format(last_run_str)
                    )
                else:
                    last_run = None
                    self.helper.log_info("Connector's first run")

                if last_run is None or ((timestamp - last_run) > self.get_interval()):
                    self._process_leaks()
                    self.helper.set_state({"last_run": timestamp})
                else:
                    new_interval = self.get_interval() - (timestamp - last_run)
                    self.helper.log_info(
                        "Connector will not run. Next run in: {} seconds.".format(
                            round(new_interval, 2)
                        )
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

        if downloader.already_processed:
            return

        stix_bundles = self._create_stix_bundles(leaks_by_domain)
        for bundle in stix_bundles:
            self._batch_send(bundle)

        for domain, leaks in leaks_by_domain.items():
            state[domain] = leaks[0]['record_id']
        write_state(self._state_dir, state)

    def _create_stix_bundles(self, leaks_by_domain: dict) -> list:
        self.helper.log_info("Parsing leaks search results: {}".format(leaks_by_domain))

        res_bundles = list()
        for domain, leaks in leaks_by_domain.items():
            stix_bundle = list()
            organization = stix2.v21.Identity(
                id=Identity.generate_id("Passleak", "organization"),
                name="Passleak",
                identity_class="organization",
                description="Passleak Company https://passleak.com",
            )
            stix_bundle.append(organization)
            domain_identity = stix2.v21.Identity(
                id=Identity.generate_id(domain, "organization"),
                name=domain,
                identity_class="domain",
            )
            stix_bundle.append(domain_identity)

            self.helper.log_info(f"Converting domains {domain} leaks to STIX objects")
            incident_by_leak = {}
            for l_rec in leaks:
                leak_incident = incident_by_leak.get(l_rec['leak_id'])
                if leak_incident is None:
                    leak_incident = stix2.v21.Incident(
                        created_by_ref=organization.id,
                        created=l_rec['added'],
                        name=f'Account credentials leak for {domain}'
                    )
                    incident_by_leak[l_rec['leak_id']] = leak_incident
                    stix_bundle.append(leak_incident)
                    incident_domain_relation = stix2.v21.Relationship(
                        source_ref=leak_incident,
                        target_ref=domain_identity,
                        relationship_type="related-to"
                    )
                    stix_bundle.append(incident_domain_relation)

                identity = ""
                if len(l_rec['email']) > 0:
                    identity = l_rec['email']
                elif len(l_rec['username']) > 0:
                    identity = l_rec['username']
                elif len(l_rec['phone']) > 0:
                    identity = l_rec['phone']

                if len(identity) == 0:
                    continue

                id_uuid = uuid_from_string(identity+l_rec['password'])
                account_id = "user-account--" + str(id_uuid)
                user_account = stix2.v21.UserAccount(
                    id=account_id,
                    credential=l_rec['password'],
                    user_id=identity,
                    created_by_ref=organization.id,
                    created=l_rec['added'],
                )
                stix_bundle.append(user_account)
                relation = stix2.v21.Relationship(
                    target_ref=leak_incident,
                    source_ref=user_account,
                    relationship_type="related-to"
                )
                stix_bundle.append(relation)
            res_bundles.append(stix_bundle)

        return res_bundles

    def _batch_send(self, stix_bundle: List):
        timestamp = int(time.time())
        now = datetime.utcfromtimestamp(timestamp)
        friendly_name = "Sending bundle @ {}".format(now.strftime("%Y-%m-%d %H:%M:%S"))

        self.helper.log_debug(
            "Start uploading of the objects: {}".format(len(stix_bundle))
        )
        work_id = self.helper.api.work.initiate_work(
            self.helper.connect_id, friendly_name
        )

        bundle = stix2.v21.Bundle(objects=stix_bundle, allow_custom=True)
        self.helper.send_stix2_bundle(
            bundle=bundle.serialize(),
            update=True,
            work_id=work_id,
        )
        # Finish the work
        self.helper.log_info(
            f"Connector ran successfully, saving last_run as {str(timestamp)}"
        )
        message = f"Last_run stored, next run in: {str(self.get_interval())} seconds"
        self.helper.api.work.to_processed(work_id, message)
        self.helper.log_debug("End of the batch upload")


if __name__ == "__main__":
    try:
        connector = PasslekLeaks()
        connector.run()
    except Exception as ex:
        print(str(ex))
        traceback.print_tb(ex.__traceback__)
        time.sleep(10)
        sys.exit(0)
