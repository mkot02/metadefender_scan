#!/usr/bin/env python3

import hashlib
import json
import os
import platform
import time

import requests
import yaml


__version = 0.1


class MetadefenderApiInterface:
    def __init__(self, srv_address, api_key=None, json_decode=False):
        """Interface for requests to MetaDefender API.
        This class was created to allow autometed file scans without using MetaDefender web interface.

        NOTE: Admin interface for MetaDefender v4 is not implemented here!

        Arguments:
            srv_address {str} -- URL ( <protocol>://<address> ) of a MetaDefender server

        Keyword Arguments:
            api_key {str} -- API Key for MetaDefender (default: {None})
            json_decode {bool} -- spefifies if API JSON response should be converted to dict or left as a string

        Raises:
            RuntimeError: [description]
        """
        self.srv_address = srv_address.strip() if isinstance(srv_address, str) else None
        self.api_key = api_key.strip() if isinstance(api_key, str) else None
        self.json_decode = bool(json_decode)

        self.user_agent = "MetadefenderApiInterface/1.0 ({0} {1}; {2}; {3})".format(
            platform.system(), platform.release(), platform.version(), platform.node()
        )

        if self.srv_address is None:
            raise RuntimeError("Wrong server address.")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return

    def _request_api(self, request_url, headers=None, body=None, method="GET"):
        """Function which performs actual HTTP request to MetaDefender API.

        Arguments:
            request_url {str} -- full URL for API

        Keyword Arguments:
            headers {dict} -- dictionary with options that will be added to HTTP header (default: {None})
            body {byte-object} -- body for the HTTP request (default: {None})
            method {str} -- HTTP method. Possible values: GET, POST, PUT, DELETE (default: {'GET'})

        Raises:
            ValueError: [description]
            MetadefenderException: [description]

        Returns:
            [type] -- [description]
        """

        if method == "GET":
            response = requests.get(request_url)
        elif method == "POST":
            response = requests.post(request_url, headers=headers, data=body)
        else:
            raise ValueError("Invalid HTTP method: {0}".format(method))

        try:
            response.raise_for_status()
        except requests.HTTPError:
            raise MetadefenderException(
                "HTTP{0}: {1}".format(response.status_code, response.reason),
                response.status_code,
                response.reason,
                response.text,
            )
        else:
            return response.content

    def _decode_api_response(self, api_response):
        """Docodes response from API to string or to dictionary

        Arguments:
            api_response {byte object} -- byte response from MetaDefender API

        Returns:
            str -- API JSON response if class was created with parameter json_decode = True
            dict -- converted API JSON response if class was created with parameter json_decode = False
        """
        string = api_response.decode("utf-8")
        return json.loads(string) if self.json_decode else string

    def login(self, user, password):
        """Initiate a new session for using protected REST APIs of MetaDefender

        Arguments:
            user {str} -- username
            password {str} -- password

        Returns:
            str -- API JSON response if class was created with parameter json_decode = True
            dict -- converted API JSON response if class was created with parameter json_decode = False
        """
        request_url = "/".join([self.srv_address, "login"])

        headers = dict()
        headers["user"] = user
        headers["password"] = password

        api_reponse = self._request_api(request_url, headers, method="POST")
        return self._decode_api_response(api_reponse)

    def logout(self, session_id):
        """Destroy session for not using protected REST APIs  of MetaDefender

        Arguments:
            session_id {str} -- Session id, can be acquired by Login / Create a Session

        Returns:
            str -- API JSON response if class was created with parameter json_decode = True
            dict -- converted API JSON response if class was created with parameter json_decode = False
        """
        request_url = "/".join([self.srv_address, "logout"])

        headers = dict()
        headers["apikey"] = session_id

        api_reponse = self._request_api(request_url, headers, method="POST")
        return self._decode_api_response(api_reponse)

    def get_api_version(self):
        """Get version of MetaDefender API

        Returns:
            str -- API JSON response if class was created with parameter json_decode = True
            dict -- converted API JSON response if class was created with parameter json_decode = False
        """
        request_url = "/".join([self.srv_address, "apiversion"])
        api_reponse = self._request_api(request_url, method="GET")
        return self._decode_api_response(api_reponse)

    def get_workflow_profiles(self):
        """Get a list of all workflow profile names [i.e. "rule"] and associated IDs.

        Returns:
            str -- API JSON response if class was created with parameter json_decode = True
            dict -- converted API JSON response if class was created with parameter json_decode = False
        """
        request_url = "/".join([self.srv_address, "file", "rules"])
        api_reponse = self._request_api(request_url, method="GET")
        return self._decode_api_response(api_reponse)

    def get_engines_stats(self):
        """Get engine information for all usable anti-malware engines.

        Returns:
            str -- API JSON response if class was created with parameter json_decode = True
            dict -- converted API JSON response if class was created with parameter json_decode = False
        """
        request_url = "/".join([self.srv_address, "stat", "engines"])
        api_reponse = self._request_api(request_url, method="GET")
        return self._decode_api_response(api_reponse)

    def get_hash_details(self, hash_value):
        """Get details of previously scanned file using file hash

        Arguments:
            hash_value {str} -- hash value of file (MD5, SHA1, SHA256)

        Returns:
            str -- API JSON response if class was created with parameter json_decode = True
            dict -- converted API JSON response if class was created with parameter json_decode = False
        """
        request_url = "/".join([self.srv_address, "hash", str(hash_value)])
        api_reponse = self._request_api(request_url, method="GET")
        return self._decode_api_response(api_reponse)

    def upload_file(self, filename, archivepwd=None, rule=None):
        """Upload new file to MetaDefender

        Arguments:
            filename {str} -- Local path for file to be scanned.

        Keyword Arguments:
            archivepwd {str} -- Password of encrypted file if file is password protected. (default: {None})
            rule {str} -- A string to define which workflow to use (i.e. workflow name).
            This will supersede user_agent and both should not be used at the same time. (default: {None})

        Returns:
            str -- API JSON response if class was created with parameter json_decode = True
            dict -- converted API JSON response if class was created with parameter json_decode = False
        """
        request_url = "/".join([self.srv_address, "file"])

        headers = dict()
        headers["filename"] = os.path.basename(filename)
        headers["user_agent"] = self.user_agent

        if rule is not None:
            headers["rule"] = rule
        if archivepwd is not None:
            headers["archivepwd"] = archivepwd

        with open(filename, "rb") as fd:
            api_reponse = self._request_api(request_url, headers, fd, method="POST")

        return self._decode_api_response(api_reponse)

    def get_scan_result(self, data_id):
        """Query a previously submitted file's scanning result.

        Arguments:
            data_id {str} -- process identifier returned in JSON from upload_file function

        Returns:
            str -- API JSON response if class was created with parameter json_decode = True
            dict -- converted API JSON response if class was created with parameter json_decode = False
        """
        request_url = "/".join([self.srv_address, "file", str(data_id)])
        api_reponse = self._request_api(request_url, method="GET")
        return self._decode_api_response(api_reponse)

    def cancel_scan(self, data_id):
        """Cancel scan job previously send to server

        Arguments:
            data_id {str} -- process identifier returned in JSON from upload_file function

        Returns:
            str -- API JSON response if class was created with parameter json_decode = True
            dict -- converted API JSON response if class was created with parameter json_decode = False
        """
        request_url = "/".join([self.srv_address, "file", str(data_id), "cancel"])
        api_reponse = self._request_api(request_url, method="GET")
        return self._decode_api_response(api_reponse)

    def download_sanitized_file(self, data_id, filename):
        """Download file scanned from database.

        Arguments:
            data_id {str} -- process identifier returned in JSON from upload_file function
            filename {str} -- path to save sanitized file on local system (default: {'.'})
        """
        request_url = "/".join([self.srv_address, "file", "converted", str(data_id)])
        api_reponse = self._request_api(request_url, method="GET")

        with open(filename, "wb") as fd:
            fd.write(api_reponse)


class MetadefenderException(Exception):
    def __init__(self, message, status_code, reason, text):
        super(MetadefenderException, self).__init__(message)

        self.status_code = status_code
        self.reason = reason
        self.text = text


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
        self.server_api = MetadefenderApiInterface(server, api_key)

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

    def _wait_for_scan(self, data_id, interval=1):
        """Wait for job with specified data_id to be finished by server.
        Check status every X seconds specified in interval

        Arguments:
            server {str} -- URL of MetaDefender server
            data_id {str} -- data_id string returned

        Keyword Arguments:
            interval {int} -- number of seconds between checks (default: {1})
        """

        while (
            json.loads(self.server_api.get_scan_result(data_id))["process_info"][
                "progress_percentage"
            ]
            != 100
        ):
            time.sleep(interval)

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
        except MetadefenderException as e:
            result = e.message

        # Check if result result is proper and doesnt contain Not Found
        # of if force mode is set
        if not ("Not Found" in result or self.force):
            return (filename, result)

        try:
            data_id = self.server_api.upload_file(filename)
            self._wait_for_scan(json.loads(data_id)["data_id"])
        except MetadefenderException as e:
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
        self.server = str(server)
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


def buildFileList(files, includes=None, excludes=None, recursive=None):
    files = files if isinstance(files, list) else [files]

    result_list = []
    for fil in files:
        # Discard files which don't exists
        if not os.path.exists(fil):
            continue

        if os.path.isdir(fil):
            # Extend result list with file lists (2nd element of tuple)
            # of this this directory and all subdirectories
            for walk_step in os.walk(fil):
                dir_file_list = [os.path.join(walk_step[0], f) for f in walk_step[2]]
                result_list.extend(dir_file_list)

                # Break after first iteration if recursive flag is not set to
                # list only files in directory not subdirectories
                if fil == walk_step[0] and not recursive:
                    break
        else:
            result_list.append(fil)

    # Apply filters and return
    if includes is not None and excludes is not None:
        raise ValueError("Includes and excludes cannot be specified at the same time")
    elif includes is not None:
        ext_list = tuple(["." + ext for ext in includes.split(",")])
        return [os.path.abspath(f) for f in result_list if f.endswith(ext_list)]
    elif excludes is not None:
        ext_list = tuple(["." + ext for ext in excludes.split(",")])
        return [os.path.abspath(f) for f in result_list if not f.endswith(ext_list)]
    else:
        return result_list


if __name__ == "__main__":
    import argparse
    import multiprocessing.dummy as multiprocessing

    parser = argparse.ArgumentParser(prog="metadefender_scan", add_help=False)
    group_file = parser.add_argument_group(title="File(s) settgins")
    group_file.add_argument("files", nargs="+")
    group_file.add_argument(
        "-r",
        "--recursive",
        help="Scan files from subdirectories if specified file is a directory itself",
        action="store_true",
    )
    group_filter = group_file.add_mutually_exclusive_group()
    group_filter.add_argument(
        "-i",
        "--extension-include",
        dest="includes",
        help="Specify comma-separated list of file extensions. Only files with specified extensions will be scanned",
    )
    group_filter.add_argument(
        "-e",
        "--extension-exclude",
        dest="excludes",
        help="Specify comma-separated list of file extensions. Files with specified extensions will not be scanned",
    )
    group_file.add_argument(
        "-o",
        "--output",
        help="Specify file which scanning results will be saved to",
    )
    group_server = parser.add_argument_group(title="Server settgins")
    group_server.add_argument(
        "-s",
        "--server",
        help="Specify URL of MetaDefender server",
    )
    group_auth = group_file.add_mutually_exclusive_group()
    # group_auth.add_argument(
    #     "-k", "--api-key", dest="apikey", help="Specify API Key for MetaDefender server"
    # )
    # group_auth.add_argument("-u", "--username", help="Specify username for login")
    # group_server.add_argument("-p", "--password", help="Specify password for login")
    group_server.add_argument(
        "--force",
        type=bool,
        default=False,
        help="Send file to server even if there is cached result for this file",
    )
    group_other = parser.add_argument_group(title="Other settgins")
    group_other.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=5,
        help="Specify how many concurrent jobs should be started. Works only if scanning directory",
    )
    group_other.add_argument(
        "-h", "--help", help="Print this help message", action="help"
    )
    group_other.add_argument(
        "-v",
        "--verbose",
        help="Print what is currently being done to STDOUT",
        action="store_true",
    )
    cli_args = parser.parse_args()

    # Perform scanning
    if cli_args.verbose:
        print("Building list of files to process")
    file_list = buildFileList(
        cli_args.files, cli_args.includes, cli_args.excludes, cli_args.recursive
    )
    if cli_args.verbose:
        print("Discovered {0} files to process".format(len(file_list)))

    if len(file_list) == 0:
        raise SystemExit("No files to process")

    # Create objects
    scanner = MetadefenderScanner(cli_args.server, cli_args.apikey, cli_args.force)
    result_parser = MetadefenderResultParser(cli_args.server)
    process_pool = multiprocessing.Pool(processes=cli_args.jobs)

    result_map = process_pool.map(scanner.scan_file, file_list)

    # Update result_parser with results
    for filename, result in result_map:
        result_parser.update(result)
    else:
        results = result_parser.dump_yaml()

    # Deal with the results
    if cli_args.output:
        with open(cli_args.output, "w") as fd:
            fd.write(results)
    else:
        print(results)

    if cli_args.verbose:
        print("Finished")
