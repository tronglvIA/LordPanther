#!/usr/bin/python
#
# PE-Sieve Integration by @hasherezade

import os
import sys
import json
import traceback

from lib.util.helper import runProcess, printMess

class PESieve(object):
    """
    PESieve class makes use of hasherezade's PE-Sieve tool to scans a given process,
    searching for the modules containing in-memory code modifications
    """

    def __init__(self, workingDir, is64bit):

        # PE-Sieve tools
        self.peSieve = os.path.join(workingDir, 'tools/pe-sieve32.exe'.replace("/", os.sep))
        if is64bit:
            self.peSieve = os.path.join(workingDir, 'tools/pe-sieve64.exe'.replace("/", os.sep))

        if self.isAvailable():
            self.active = True
            printMess(messtype="NOTICE", message = "PE-Sieve successfully initialized BINARY: {0} "
                                      "SOURCE: https://github.com/hasherezade/pe-sieve".format(self.peSieve))
        else:
            printMess(messtype="NOTICE", message = "Cannot find PE-Sieve in expected location {0} "
                                      "SOURCE: https://github.com/hasherezade/pe-sieve".format(self.peSieve))

    def isAvailable(self):
        """
        Checks if the PE-Sieve tools are available in a "./tools" sub folder
        :return:
        """
        if not os.path.exists(self.peSieve):
            printMess(messtype="DEBUG", message = "PE-Sieve not found in location '{0}' - "
                                     "feature will not be active".format(self.peSieve))
            return False
        return True

    def scan(self, pid, pesieveshellc = False):
        """
        Performs a scan on a given process ID
        :param pid: process id of the process to check
        :return hooked, replaces, suspicious: number of findings per type
        """
        # Presets
        results = {"patched": 0, "replaced": 0, "unreachable_file": 0, "implanted_pe": 0, "implanted_shc": 0}
        # Compose command
        command = [self.peSieve, '/pid', str(pid), '/ofilter', '2', '/quiet', '/json'] + (['/shellc'] if pesieveshellc else [])
        # Run PE-Sieve on given process
        (output, returnCode) = runProcess(command)
        # Debug output
        # if self.logger.debug:
        print("\nPE-Sieve JSON output: %s" % output)
        if output == '' or not output:
            return results
        try:
            results_raw = json.loads(output)
            results = results_raw["scanned"]["modified"]
        except ValueError as v:
            traceback.print_exc()
            printMess(messtype = "DEBUG", message = "Couldn't parse the JSON output.")
        except Exception as e:
            traceback.print_exc()
            printMess(messtype = "ERROR", message = "Something went wrong during PE-Sieve scan.")
        return results