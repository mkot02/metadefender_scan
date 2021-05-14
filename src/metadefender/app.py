import hashlib
import json

import yaml

from metadefender.api import MetadefenderApi, MetadefenderApiException


class MetadefenderScanner:
    def __init__(self, server, api_key=None, force=False):
        """This class is created as

        Arguments:
            server {str} -- URL ( <protocol>://<address> ) of a MetaDefender server

        Keyword Arguments:
            api_key {str} -- API Key for MetaDefender (default: {None})
            force {bool} -- Upload files for scanning even if they were scaned already (default: {False})
        """
        self.force = bool(force)
        self.result_list = []
        self.server_api = MetadefenderApi(server, api_key)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return

    def _calculate_file_hash(self, filename, hash_type="MD5"):
        """Calculates hash of specified file using one of three algorithms

        Arguments:
            filename {str} -- path to the file on local system

        Keyword Arguments:
            hash_type {str} -- Hashing algorithm to use. Possible values: MD5, SHA1, SHA256 (default: {'MD5'})

        Returns:
            str -- hash of the file converted to HEX
        """
        HASH_FUNCTIONS = {
            "MD5": hashlib.md5,
            "SHA1": hashlib.sha1,
            "SHA256": hashlib.sha256,
        }
        hash_o = HASH_FUNCTIONS.get(hash_type.upper(), hashlib.md5)()

        with open(filename, "rb") as fd:
            while True:
                chunk = fd.read(1000000)
                if len(chunk):
                    hash_o.update(chunk)
                else:
                    return hash_o.hexdigest()

    def scan_file(self, filename):
        """Checks whether file was already scanned and depending on 'force' parameter from class constructor
        upload file for scanning and return JSON object

        Arguments:
            filename {str} -- name of the file specified for scanning

        Returns:
            str -- API JSON response
        """
        file_hash = self._calculate_file_hash(filename)

        try:
            result = self.server_api.get_hash_details(file_hash)
        except MetadefenderApiException as e:
            result = e.message

        # Check if result result is proper and doesnt contain Not Found
        # of if force mode is set
        if not ("Not Found" in result or self.force):
            return (filename, result)

        try:
            data_id = self.server_api.upload_file(filename)
            self.server_api.wait_for_scan(json.loads(data_id)["data_id"])
        except MetadefenderApiException as e:
            result = e.message
        else:
            result = self.server_api.get_hash_details(file_hash)

        return (filename, result)

    def map(self, file_iter):
        """Returns generator over results of scanned files

        Arguments:
            file_iter {iterable} -- iterable with names of files to scan

        Returns:
            generator -- generator which iterates over results of scanning
        """
        return (self.scan_file(file_to_process) for file_to_process in file_iter)


class MetadefenderResultParser:
    def __init__(self, server):
        """This class is intended to parse and return results of MetaDefender API scanning in desired format"""
        self.result_map = dict()
        self.result_map["results"] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return

    def update(self, json_string):
        """Update the result-object with new result from MetaDefender API.

        Keyword Arguments:
            json_string {str} -- string with JSON response from MetaDefender API

        Raises:
            ValueError: if json_string and json_dict are specified in the same time, or none of them is specified
        """
        self.result_map["results"].append(json.loads(json_string))

    def dump_json(self):
        """Dump results to JSON format

        Returns:
            str -- string with dumped results
        """
        return json.dumps(self.result_map, indent=4)

    def dump_yaml(self):
        """Dump results to YAML format

        Returns:
            str -- string with dumped results
        """
        return yaml.safe_dump(self.result_map)


class MetadefenderReporter:
    pass
