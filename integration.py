#!/usr/bin/env python2

from Atomic import run

import datetime
import docker
import json
import logging
import os
import subprocess
import sys

OUTDIR = "/scannot"
INDIR = "/scanin"

command = sys.argv[1]
image_name = sys.argv[2]

json_output = template_json_data(
    "test_image_name", "ABCDEFG", "integration")

json_output["Scan Results"] = {
    "command": command,
    "image_name": image_name,
}


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


class Scanner(object):
    """
    Wrapper class for running the scan over images and/or containers
    """

    def target_containers(self):
        """
        Returns the containers / images to be processed
        """
        # atomic scan will mount container's image onto
        # a rootfs and expose rootfs to scanner under the /scanin directory
        return [_dir for _dir in os.listdir(INDIR) if
                os.path.isdir(os.path.join(INDIR, _dir))
                ]

    def run(self):
        for container in self.target_containers():
            data = json_output
            # Write scan results to json file
            out_path = os.path.join(OUTDIR, container)
            self.export_results(data, out_path)

    def export_results(self, data, out_path):
        """
        Export the JSON data in output_file
        """
        os.makedirs(out_path)
        current_time = datetime.now().strftime('%Y-%m-%d-%H-%M-%S-%f')
        data["Finished Time"] = current_time
        with open("integration_scanner.json", "w") as f:
            f.write(json.dumps(data, indent=4))


if __name__ == "__main__":
    configure_logging()
    scanner = Scanner()
    scanner.run()
