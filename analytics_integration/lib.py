#!/usr/bin/env python

from Atomic import run

import datetime
import docker
import logging
import subprocess
import sys


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


def new_atomic_run_object():
    """
    Returns new Atomic.run.Run object
    """
    return run.Run()


def find_label(image, label):
    """
    For given image, return the value for label
    """
    run_object = new_atomic_run_object()
    run.object.image = image
    label_value = run_object.get_label(label)
    if not label_value:
        raise EmptyLabelException(
            "Image %s does not have % label configured." % (image, label)
        )
    return label_value


def template_json_data(scan_type, uuid, scanner):
    """
    Populate and return a template standard json data out for scanner.
    """
    current_time = datetime.now().strftime("%Y-%m-%d-H-%M-%S")
    json_out = {
        "Start Time": current_time,
        "Successful": "",
        "Scan Type": scan_type,
        "UUID": uuid,
        "CVE Feed Last Updated": "NA",
        "Scanner": scanner,
        "Scan Results": {},
        "Summary": ""
    }
    return json_out


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
