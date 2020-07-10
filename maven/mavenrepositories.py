# -*- coding: utf-8 -*-
import os
from xml.etree import ElementTree
from winsecs.utils import log


class MavenRepositories:
    def run(self, profile):
        """
        Main function:

        - For encrypted password, provides the encrypted version of the password with the master password in order
        to allow "LaZagne run initiator" the use the encryption parameter associated with the version of Maven because
        encryption parameters can change between version of Maven.

        - "LaZagne run initiator" can also use the encrypted password and the master password "AS IS"
        in a Maven distribution to access repositories.
        See:
        github.com/jelmerk/maven-settings-decoder
        github.com/sonatype/plexus-cipher/blob/master/src/main/java/org/sonatype/plexus/components/cipher/PBECipher.java
        """

        # Extract the master password
        master_password = None
        master_password_file_location = profile["USERPROFILE"] + u'\\.m2\\settings-security.xml'
        if os.path.isfile(master_password_file_location):
            try:
                config = ElementTree.parse(master_password_file_location).getroot()
                master_password_node = config.find(".//master")
                if master_password_node is not None:
                    master_password = master_password_node.text
            except Exception as e:
                log.error("Cannot retrieve master password '%s'" % e)
                master_password = None

        # Extract all available repositories credentials
        repos_creds = []
        maven_settings_file_location = profile["USERPROFILE"] + '\\.m2\\settings.xml'
        if os.path.isfile(maven_settings_file_location):
            try:
                settings = ElementTree.parse(maven_settings_file_location).getroot()
                server_nodes = settings.findall(".//%sserver" % "{http://maven.apache.org/SETTINGS/1.0.0}")
                for server_node in server_nodes:
                    creds = {}
                    for child_node in server_node:
                        tag_name = child_node.tag.replace("{http://maven.apache.org/SETTINGS/1.0.0}", "")
                        if tag_name in ["id", "username", "password", "privateKey", "passphrase"]:
                            creds[tag_name] = child_node.text.strip()
                    if len(creds) > 0:
                        repos_creds.append(creds)
            except Exception as e:
                log.error("Cannot retrieve repositories credentials '%s'" % e)

        # Parse and process the list of repositories's credentials
        # 3 cases are handled:
        # => Authentication using password protected with the master password (encrypted)
        # => Authentication using password not protected with the master password (plain text)
        # => Authentication using private key
        pwd_found = []
        for creds in repos_creds:
            values = {"Id": creds["id"], "Login": creds["username"]}
            if "privateKey" in creds:
                pk_file_location = creds["privateKey"]
                pk_file_location = pk_file_location.replace("${user.home}", profile["USERPROFILE"])
                if not os.path.isfile(pk_file_location):
                    pwd = creds["password"].strip()
                    # Case for authentication using password protected with the master password
                    if pwd.startswith("{") and pwd.endswith("}"):
                        values["SymetricEncryptionKey"] = master_password
                        values["PasswordEncrypted"] = pwd
                    else:
                        values["Password"] = pwd
                else:
                    # Case for authentication using private key
                    pk_file_location = creds["privateKey"]
                    pk_file_location = pk_file_location.replace("${user.home}", profile["USERPROFILE"])
                    with open(pk_file_location, "r") as pk_file:
                        values["PrivateKey"] = pk_file.read()
                    if "passphrase" in creds:
                        values["Passphrase"] = creds["passphrase"]
            pwd_found.append(values)

        return pwd_found


modules = {"MavenRepositories": MavenRepositories()}
