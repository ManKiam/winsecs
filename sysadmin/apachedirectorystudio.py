# -*- coding: utf-8 -*-
from xml.etree.ElementTree import parse
from winsecs.utils import log
import os


class ApacheDirectoryStudio:
    def run(self, profile):
        """
        Extract all connection's credentials.

        :return: List of dict in which one dict contains all information for a connection.
        """
        repos_creds = []
        connection_file_location = os.path.join(
            profile["USERPROFILE"],
            '.ApacheDirectoryStudio\\.metadata\\.plugins\\org.apache.directory.studio.connection.core\\connections.xml'
        )
        if os.path.isfile(connection_file_location):
            try:
                connections = parse(connection_file_location).getroot()
                connection_nodes = connections.findall(".//connection")
                for connection_node in connection_nodes:
                    creds = {}
                    for connection_attr_name in connection_node.attrib:
                        # Interesting XML attributes in ADS connection configuration
                        if connection_attr_name in ["host", "port", "bindPrincipal", "bindPassword", "authMethod"]:
                            creds[connection_attr_name] = connection_node.attrib[connection_attr_name].strip()
                    if creds:
                        repos_creds.append(creds)
            except Exception as e:
                log.error("Cannot retrieve connections credentials '%s'" % e)

        # Parse and process the list of connections credentials
        pwd_found = []
        for creds in repos_creds:
            pwd_found.append({
                "Host"                  : creds["host"],
                "Port"                  : creds["port"],
                "Login"                 : creds["bindPrincipal"],
                "Password"              : creds["bindPassword"],
                "AuthenticationMethod"  : creds["authMethod"]
            })

        return pwd_found


modules = {"ApacheDirectoryStudio": ApacheDirectoryStudio()}
