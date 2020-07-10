# -*- coding: utf-8 -*-
import json
import os

from winsecs.utils import log


class Robomongo:

    def read_file_content(self, file_path):
        """
        Read the content of a file

        :param file_path: Path of the file to read.

        :return: File content as string.
        """
        content = ""
        if os.path.isfile(file_path):
            with open(file_path, 'r') as file_handle:
                content = file_handle.read()

        return content

    def parse_json(self, connection_file_path):
        repos_creds = []
        if not os.path.exists(connection_file_path):
            return repos_creds
        with open(connection_file_path) as connection_file:
            try:
                connections_infos = json.load(connection_file)
            except Exception:
                return repos_creds
            for connection in connections_infos.get("connections", []):
                try:
                    creds = {
                        "Name": connection["connectionName"],
                        "Host": connection["serverHost"],
                        "Port": connection["serverPort"]
                    }
                    crd = connection["credentials"][0]
                    if crd.get("enabled"):
                        creds.update({
                            "AuthMode": "CREDENTIALS",
                            "DatabaseName": crd["databaseName"],
                            "AuthMechanism": crd["mechanism"],
                            "Login": crd["userName"],
                            "Password": crd["userPassword"]
                        })
                    else:
                        creds.update({
                            "Host": connection["ssh"]["host"],
                            "Port": connection["ssh"]["port"],
                            "Login": connection["ssh"]["userName"]
                        })
                        if connection["ssh"]["enabled"] and connection["ssh"]["method"] == "password":
                            creds.update({
                                "AuthMode": "SSH_CREDENTIALS",
                                "Password": connection["ssh"]["userPassword"]
                            })
                        else:
                            creds.update({
                                "AuthMode": "SSH_PRIVATE_KEY",
                                "Passphrase": connection["ssh"]["passphrase"],
                                "PrivateKey": self.read_file_content(connection["ssh"]["privateKeyFile"]),
                                "PublicKey": self.read_file_content(connection["ssh"]["publicKeyFile"])
                            })
                    repos_creds.append(creds)
                except Exception as e:
                    log.error(f"Cannot retrieve connections credentials '{e}'")

        return repos_creds

    def run(self, profile):
        """
        Extract all connection's credentials.

        :return: List of dict in which one dict contains all information for a connection.
        """
        pwd_found = []
        for path in ['.config\\robomongo\\robomongo.json', '.3T\\robo-3t\\1.1.1\\robo3t.json']:
            connection_file_path = os.path.join(profile['USERPROFILE'], path)
            pwd_found += self.parse_json(connection_file_path)

        return pwd_found


modules = {"Robomongo": Robomongo()}
