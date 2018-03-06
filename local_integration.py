#!/usr/bin/env python2

from Atomic import run as atomic_run

from requests.compat import urljoin
from datetime import datetime

import docker
import json
import logging
import os
import requests
import subprocess
import sys


#OUTDIR = "/scannot"
#INDIR = "/scanin"

OUTDIR = "/tmp"
INDIR = "/tmp"


class EmptyLabelException(Exception):

    def __init__(self, message):
        super(EmptyLabelException, self).__init__(message)


def configure_logging(name="integration-scanner"):
    """
    Configures logging and returns logger object
    """
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s p%(process)s %(name)s %(lineno)d "
        "%(levelname)s - %(message)s"
    )
    ch.setFormatter(formatter)
    logger.addHandler(ch)
    return logger


def get_server_url(env_name="SERVER"):
    """
    Gets the SERVER env variable value
    """
    return "https://localhost/"
    """
    if not os.environ.get("SERVER", False):
        raise ValueError(
            "No value for SERVER env variable. Please re-run with: "
            "SERVER=<url> IMAGE_NAME=<image> atomic scan [..]")
    return os.environ.get("SERVER")
    """


def get_image_name(env_name="IMAGE_NAME"):
    """
    Gets the IMAGE env variable value
    """
    return "centos/centos:latest"
    if not os.environ.get("IMAGE_NAME", False):
        raise ValueError(
            "No value for IMAGE_NAME env variable. Please re-run with: "
            "SERVER=<url> IMAGE_NAME=<image> atomic scan [..]"
        )
    return os.environ.get("IMAGE_NAME")


def connect_local_docker_socket(base_url="unix:///var/run/docker.sock"):
    """
    Initiates local docker client connection
    """
    client = docker.Client(base_url=base_url)
    return client


def get_image_uuid(client, image_name):
    """
    Using passed docker client object, returns image uuid for image_name.
    """
    return client.inspect_image(image_name)["Id"].split(":")[-1]


def find_label(run_object, image, label):
    """
    For given image, return the value for label
    """
    return "value"
    """
    label_value = run_object.get_label(label)
    if not label_value:
        raise EmptyLabelException(
            "Image %s does not have % label configured." % (image, label)
        )
    return label_value
    """


def run_command(cmd, shell=True):
    """
    Runs a shell command.

    :param cmd: Command to run
    :param shell: Whether to run raw shell commands with '|' and redirections
    :type cmd: str
    :type shell: boolean

    :return: Command output
    :rtype: str
    :raises: subprocess.CalledProcessError
    """
    if shell:
        return subprocess.check_output(cmd, shell=True)
    else:
        return subprocess.check_output(cmd.split(), shell=False)


def post_request(endpoint, api, data):
    """
    Make a post call to analytics server with given data

    :param endpoint: API server end point
    :param api: API to make POST call against
    :param data: JSON data needed for POST call to api endpoint

    :return: Tuple (status, error_if_any)
             where status = True/False
                   error_if_any = string message on error, "" on success
    """
    return True, ""
    url = urljoin(endpoint, api)
    # return True, ""
    # TODO: check if we need API key in data
    try:
        requests.post(url, data)
    except requests.exceptions.RequestException as e:
        print e
        return False, str(e)
    else:
        # TODO check for response code
        return True, ""


def get_request(endpoint, api):
    """
    Make a get call to analytics server

    :param endpoint: API server end point
    :param api: API to make GET call against

    :return: The data received from get call
    """
    pass


class AnalyticsIntegration(object):
    """
    Analytics integrtion related tasks wrapped in this calls
    """

    def __init__(self, container, scan_type):
        """
        Initialize object variables specific to per container scanning
        """
        self.scanner = "scanner-analytics-integration"
        self.container = container
        # scan_type = [register, scan, get_report]
        self.scan_type = scan_type
        self.run_object = atomic_run.Run()
        # following are the labels must be present in image
        self.needed_labels_names = ["git-url", "git-sha", "email-ids"]
        # following three variables need to be processed later
        self.label_data = None
        self.image_name = None
        self.server_url = None
        # This will contain the result/error data
        self.respone = None
        self.errors = []
        self.failure = True
        # the labels needed for calling server APIs
        self.recorded_labels = {}
        # the needed data to be logged in scanner output
        self.data = {}
        # the templated data this scanner will export
        print container[1:]
        self.json_out = self.template_json_data(self.scanner,
                                                self.scan_type,
                                                container[1:])

    def template_json_data(self, scanner, scan_type, uuid):
        """
        Populate and return a template standard json data out for scanner.
        """
        current_time = datetime.now().strftime("%Y-%m-%d-H-%M-%S")
        json_out = {
            "Start Time": current_time,
            "Successful": False,
            "Scan Type": scan_type,
            "UUID": uuid,
            "CVE Feed Last Updated": "NA",
            "Scanner": scanner,
            "Scan Results": {},
            "Summary": ""
        }
        return json_out

    def record_fatal_error(self, error):
        self.errors.append(str(error))

    def record_label(self, name, value):
        self.recorded_labels[name] = value.strip()

    def return_on_failure(self):
        if self.failure:
            current_time = datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")
            self.json_out["Finished Time"] = current_time
            self.json_out["Successful"] = False
            self.json_out["Scan Results"] = self.data
            " ".join
            self.json_out["Summary"] = "Error: %s" % str(self.errors)
            return False, self.json_out

    def verify_recorded_labels(self):
        pass

    def _run(self):
        """
        Run the needed tasks for scanning container under test
        """
        try:
            self.image_name = get_image_name()
            self.server_url = get_server_url()
        except ValueError as e:
            self.record_fatal_error(e)
            self.failure = True
            return self.return_on_failure()
        else:
            self.failure = False
            # set the data right away for ensuring its exported
            self.data["image_name"] = self.image_name
            self.data["server_url"] = self.server_url

        """
        try:
            self.docker_client = connect_local_docker_socket()
        except Exception as e:
            self.record_fatal_error(e)
            self.failure = True
            return self.return_on_failure()
        else:
            self.failure = False
        """

        self.run_object.image = self.image_name
        for label in self.needed_labels_names:
            try:
                value = find_label(self.run_object, self.image_name, label)
            except EmptyLabelException as e:
                self.record_fatal_error(e)
                self.failure = True
            else:
                self.failure = False
                self.record_label(label, value)
        # this operation is clubbed with above for loop
        # intended to run after the loop is complete
        if self.failure:
            return self.return_on_failure()

        # if label retrieval is complete, verify the recorded labels
        self.verify_recorded_labels()

        # record the labels in data as well
        self.data.update(self.recorded_labels)

        if self.scan_type == "register":
            api = "/register"
        elif self.scan_type == "scan":
            api = "/scan"
        # TODO: add more cases for scan and report command
        else:
            api = "/register"

        status, out = post_request(endpoint=self.server_url,
                                   api=api,
                                   data=self.recorded_labels)
        if not status:
            self.failure = True
            self.record_fatal_error(out)
            return self.return_on_failure()

        # if there are no return on data failures, return True
        return self.return_on_success()

    def return_on_success(self):
        current_time = datetime.now().strftime("%Y-%m-%d-%H-%M-%S-%f")
        self.json_out["Finished Time"] = current_time
        self.json_out["Successful"] = True
        self.json_out["Scan Results"] = self.data
        self.json_out["Summary"] = (
            "Completed scan with data mentioned in Scan Results.")
        return True, self.json_out


class Scanner(object):
    """
    Wrapper class for running the scan over images and/or containers
    """

    def __init__(self, scan_type):
        self.scan_type = scan_type
        self.scanner = "scanner-analytics-integration"

    def target_containers(self):
        """
        Returns the containers / images to be processed
        """
        # atomic scan will mount container's image onto
        # a rootfs and expose rootfs to scanner under the /scanin directory
        # return [_dir for _dir in os.listdir(INDIR) if
        #        os.path.isdir(os.path.join(INDIR, _dir))
        #        ]

        return ["/tmp/foo"]

    def run(self):
        for container in self.target_containers():
            per_scan_object = AnalyticsIntegration(container, self.scan_type)
            _, output = per_scan_object._run()

            # Write scan results to json file
            out_path = os.path.join(OUTDIR, container)
            self.export_results(out_path, output, container)

    def export_results(self, out_path, output, container):
        """
        Export the JSON data in output_file
        """
        out_path = os.path.join(OUTDIR, container)
        print "Creating dir: %s" % out_path
        # os.makedirs(out_path)

        # result file name = "scanner-analytics-integration.json"
        result_filename = os.path.join(out_path,
                                       self.scanner + ".json")

        print "Exporting result in %s" % result_filename

        with open(result_filename, "w") as f:
            json.dump(output, f, indent=4, separators=(",", ": "))


if __name__ == "__main__":
    configure_logging()
    command = sys.argv[1]
    scanner = Scanner(scan_type=command)
    scanner.run()
