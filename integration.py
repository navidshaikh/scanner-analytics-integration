#!/usr/bin/env python2

from analytics_integration import lib

import datetime
import json
import os


OUTDIR = "/scannot"
SCANIN = "/scanin"

lib.configure_logging()

command = sys.argv[1]
image_name = sys.argv[2]


json_output = lib.template_json_data(
        "test_image_name", "ABCDEFG", "integration")

json_output["Scan Results"] = {
        "command": command,
        "image_name": image_name,
        }


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

    def export_results(self, data):
        """
        Export the JSON data in output_file
        """
        os.makedirs(out_path)
        current_time = datetime.now().strftime('%Y-%m-%d-%H-%M-%S-%f')
        data["Finished Time"] = current_time
        with open(self.result_filename, "w") as f:
            f.write(json.dumps(data, indent=4))


if __name__ == "__main__":
    scanner = Scanner()
    scanner.run()
