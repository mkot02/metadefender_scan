import json
import os
import platform
import time

import requests


class MetadefenderApi:
    def __init__(self, srv_address, api_key=None, json_decode=False):
        """Interface for requests to MetaDefender Core v4 API.
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
            MetadefenderApiException: [description]

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
            raise MetadefenderApiException(
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

    def wait_for_scan(self, data_id, interval=1):
        """Wait for job with specified data_id to be finished by server.
        Check status every X seconds specified in interval

        Arguments:
            server {str} -- URL of MetaDefender server
            data_id {str} -- data_id string returned

        Keyword Arguments:
            interval {int} -- number of seconds between checks (default: {1})
        """

        while (
            json.loads(self.get_scan_result(data_id))["process_info"][
                "progress_percentage"
            ]
            != 100
        ):
            time.sleep(interval)

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


class MetadefenderApiException(Exception):
    def __init__(self, message, status_code, reason, text):
        super(MetadefenderApiException, self).__init__(message)

        self.status_code = status_code
        self.reason = reason
        self.text = text
