from typing import Dict, List
from sklearn.model_selection import StratifiedShuffleSplit
import wmi
import psutil
import re
import os
import sys
import platform
# Alter relate path's package to import `..lib.util.helper` 
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from lib.util.helper import *
from lib.pesieve import PESieve

class Process:

    # Attributes----------------------------------------
    """
    :Default = 0 which means variable is integer_type:
    :Another default which means variable is string_type: 
    """
    pid = 0
    name = "N/A"
    cmd = "N/A"
    path = "none"
    parent_pid = 0 
    priority = 0
    ws_size = "unknown" 
    owner = "unknow"
    # WinInit PID
    wininit_pid = 0
    # LSASS Counter
    lsass_count = 0
    t_systemroot = os.environ['SYSTEMROOT']


    # Constructor
    def __init__(self):
        # Get Parent Working Directory
        cwd_path =  os.path.dirname(os.path.realpath(__file__))
        project_path = os.path.dirname(cwd_path)

        # Is 64-bit or 32-bit system ?
        is64bit = False
        if platform.machine().endswith("64"):
            is64bit = True
        
        # Init PEsieve Class If only WinDows
        if sys.platform == 	"win32":
            self.peSieve = PESieve(project_path, is64bit)
        


    # Checking if a given process is running ------------
    def processExists(self, ProID):
        return psutil.pid_exists(ProID)

    # Gather Process Infor -------------------------------
    """
    :Iterating and returning a ListDict's processInformation which are running:
    """
    def get_proInfor(self):

        # Create a empty list with name result
        result = []

        # Iterate process which are running
        for process in wmi.WMI().Win32_Process():
            # Create a empty dict with name proInfor
            proInfor = {}

            proInfor["PID"] = process.ProcessId

            if not process.Name:
                proInfor["NAME"] = "N/A"
            else: proInfor["NAME"] = process.Name

            if not process.CommandLine:
                proInfor["CMD"] = "N/A"
            else: proInfor["CMD"] = process.CommandLine

            if not process.ExecutablePath:
                proInfor["PATH"] = "none"
            else: proInfor["PATH"] = process.ExecutablePath

            # Special Checks -----------------------------
            """
            :Better executable path:
            """
            if not "\\" in proInfor["CMD"] and proInfor["PATH"] != "none":
                proInfor["CMD"] = proInfor["PATH"]

            proInfor["PARENT_PID"] = process.ParentProcessId  
            proInfor["PRIORITY"] = process.Priority
            proInfor["WS_SIZE"] = process.VirtualSize

            try:
                owner_raw = process.GetOwner()
                if not owner_raw[2]:
                    proInfor["OWNER"] = "unknown"
                else: proInfor["OWNER"] = owner_raw[2]
            except Exception as e:
                proInfor["OWNER"] = "unknown"

            # Add proInfor to list
            result.append(proInfor)
        
        # Return result
        return result

    # Yara Process Memory---------------------------------
    def yara_processes(self, process, yara_rules: List, maxworkingset = int(200)):
        if self.processExists(process["PID"]):
            if int(process["WS_SIZE"]) < (maxworkingset * 1048576 ):
                try:
                    alerts = []
                    for rules in yara_rules:
                        # continue - fast switch
                        matches = rules.match(pid=process["PID"])
                        if matches:
                            for match in matches:

                                # Preset memory_rule
                                memory_rule = 1

                                # Built-in rules have meta fields (cannot be expected from custom rules)
                                if hasattr(match, 'meta'):

                                    # If a score is given
                                    if 'memory' in match.meta:
                                        memory_rule = int(match.meta['memory'])

                                # If rule is meant to be applied to process memory as well
                                if memory_rule == 1:

                                    # print match.rule
                                    alerts.append("Yara Rule MATCH: %s %s" % (match.rule, process))

                    if len(alerts) > 5:
                        printMess(messtype="WARNING", message="ProcessScan Too many matches on process memory - most likely a false positive %s" % process)
                    elif len(alerts) > 0:
                        for alert in alerts:
                            printMess(messtype="ALERT", message=f"ProcessScan : {alert}")
                except Exception as e:
                    traceback.print_exc()
                    if process["PATH"] != "none":
                        printMess(messtype="ERROR", message="ProcessScan Error during process memory Yara check (maybe the process doesn't exist anymore or access denied) %s" % process)
            else:
                printMess(messtype="DEBUG", message="ProcessScan Skipped Yara memory check due to the process' big working set size (stability issues) PID: %s NAME: %s SIZE: %s" % ( process["PID"], process["NAME"], process["WS_SIZE"]))

    # File Name Checks ------------------------------------
    def check_fileName(self, process,filename_iocs: List):
        for fioc in filename_iocs:
                match = fioc['regex'].search(process["CMD"])
                if match:
                    if int(fioc['score']) > 70:
                        printMess(messtype="ALERT", message="ProcessScan-File Name IOC matched PATTERN: %s DESC: %s MATCH: %s" % (fioc['regex'].pattern, fioc['description'], process["CMD"]))
                    elif int(fioc['score']) > 40:
                        printMess(messtype="WARNING", message="ProcessScan-File Name Suspicious IOC matched PATTERN: %s DESC: %s MATCH: %s" % (fioc['regex'].pattern, fioc['description'], process["CMD"]))

    # THOR Process Anomaly Checks--------------------------
    """ 
    :Base on `https://www.nextron-systems.com/thor/` idea:
    """
    def thor_proAnomaly(self, process):

        # Skeleton Key Malware Process
        if re.search(r"psexec .* [a-fA-F0-9]{32}", process["CMD"], re.IGNORECASE):
            printMess(messtype="WARNING", message=f"Process that looks liks SKELETON KEY psexec execution detected {process}")

        # Suspicious waitfor - possible backdoor
        if process["NAME"] == "waitfor.exe":
            printMess(messtype="WARNING", message=f"Suspicious waitfor.exe {process}")

        # Process: System
        if process["NAME"] == "System" and not process["PID"] == 4 :
            printMess(messtype="WARNING", message=f"System process without PID=4 {process}")

        # Process: smss.exe
        if process["NAME"] == "smss.exe" and not process["PARENT_PID"] == 4:
            printMess(messtype="WARNING",message=f"smss.exe parent PID is != 4 {process}")
        if process["PATH"] != "none":
            if process["NAME"] == "smss.exe" and not ( "system32" in process["PATH"].lower() or "system32" in process["CMD"].lower() ):
                printMess(messtype="WARNING",message=f"smss.exe path is not System32 {process}")
        if process["NAME"] == "smss.exe" and process["PRIORITY"] != 11:
            printMess(messtype="WARNING", message=f"smss.exe priority is not 11 {process}")

        # Process: csrss.exe
        if process["PATH"] != "none":
            if process["NAME"] == "csrss.exe" and not ( "system32" in process["PATH"].lower() or "system32" in process["CMD"].lower() ):
                printMess(messtype="WARNING", message=f"csrss.exe path is not System32 {process}")
        if process["NAME"] == "csrss.exe" and process["PRIORITY"] != 13:
            printMess(messtype="WARNING", message=f"csrss.exe priority is not 13 {process}")

        # Process: wininit.exe
        if process["PATH"] != "none":
            if process["NAME"] == "wininit.exe" and not ( "system32" in process["PATH"].lower() or "system32" in process["CMD"].lower() ):
                printMess(messtype="WARNING", message=f"wininit.exe path is not System32 {process}")
        if process["NAME"] == "wininit.exe" and process["PRIORITY"] != 13:
            printMess("NOTICE", message=f"wininit.exe priority is not 13 {process}")

        # Is parent to other processes - save PID
        if process["NAME"] == "wininit.exe":
            self.wininit_pid = process["PID"]

        # Process: services.exe
        if process["PATH"] != "none":
            if process["NAME"] == "services.exe" and not ( "system32" in process["PATH"].lower() or "system32" in process["CMD"].lower() ):
                printMess(messtype="WARNING", message=f"services.exe path is not System32{process}")
        if process["NAME"] == "services.exe" and process["PRIORITY"] != 9:
            printMess(messtype="WARNING", message=f"services.exe priority is not 9{process}")
        if self.wininit_pid > 0:
            if process["NAME"] == "services.exe" and not process["PARENT_PID"] == self.wininit_pid:
                printMess(messtype="WARNING", message=f"services.exe parent PID is not the one of wininit.exe{process}")

        # Process: lsass.exe
        if process["PATH"] != "none":
            if process["NAME"] == "lsass.exe" and not ( "system32" in process["PATH"].lower() or "system32" in process["CMD"].lower() ):
                printMess(messtype="WARNING", message=f"lsass.exe path is not System32{process}")
        if process["NAME"] == "lsass.exe" and process["PRIORITY"] != 9:
            printMess(messtype="WARNING", message=f"lsass.exe priority is not 9{process}")
        if self.wininit_pid > 0:
            if process["NAME"] == "lsass.exe" and not process["PARENT_PID"] == self.wininit_pid:
                printMess(messtype="WARNING", message=f"lsass.exe parent PID is not the one of wininit.exe{process}")

        # Only a single lsass process is valid - count occurrences
        if process["NAME"] == "lsass.exe":
            self.lsass_count += 1
            if self.lsass_count > 1:
                printMess(messtype="WARNING", message=f"lsass.exe count is higher than 1 {process}")

        # Process: svchost.exe
        if process["PATH"] != "none":
            if process["NAME"] == "svchost.exe" and not ( "system32" in process["PATH"].lower() or "system32" in process["CMD"].lower() ):
                printMess(messtype="WARNING", message=f"svchost.exe path is not System32{process}")
        if process["NAME"] == "svchost.exe" and process["PRIORITY"] != 8:
            printMess("NOTICE", message=f"svchost.exe priority is not 8 {process}")

        # Windows 10 FP
        #if process["NAME"] == "svchost.exe" and not ( self.check_svchost_owner(owner) or "unistacksvcgroup" in process["CMD"].lower()):
        #    printMess(messtype="WARNING", message=f"svchost.exe process owner is suspicious {process}")

        if process["NAME"] == "svchost.exe" and not " -k " in process["CMD"] and process["CMD"] != "N/A":
            printMess(messtype="WARNING", message=f"svchost.exe process does not contain a -k in its command line{process}")

        # Process: lsm.exe
        if process["PATH"] != "none":
            if process["NAME"] == "lsm.exe" and not ( "system32" in process["PATH"].lower() or "system32" in process["CMD"].lower() ):
                printMess(messtype="WARNING", message=f"lsm.exe path is not System32{process}")
        if process["NAME"] == "lsm.exe" and process["PRIORITY"] != 8:
            printMess("NOTICE", message=f"lsm.exe priority is not 8{process}")
        if process["NAME"] == "lsm.exe" and not ( process["OWNER"].startswith("NT ") or process["OWNER"].startswith("LO") or process["OWNER"].startswith("SYSTEM")  or process["OWNER"].startswith(u"система")):
            printMess(messtype="WARNING", message=f"lsm.exe process owner is suspicious{process}")
        if self.wininit_pid > 0:
            if process["NAME"] == "lsm.exe" and not process["PARENT_PID"] == self.wininit_pid:
                printMess(messtype="WARNING", message=f"lsm.exe parent PID is not the one of wininit.exe{process}")

        # Process: winlogon.exe
        if process["NAME"] == "winlogon.exe" and process["PRIORITY"] != 13:
            printMess(messtype="WARNING", message=f"winlogon.exe priority is not 13{process}")
        if re.search("(Windows 7|Windows Vista)", getPlatformFull()):
            if process["NAME"] == "winlogon.exe" and process["PARENT_PID"] > 0:
                for proc in wmi.WMI().Win32_Process():
                    if process["PARENT_PID"] == proc.ProcessId:
                        printMess(messtype="WARNING", message="winlogon.exe has a parent ID but should have none %s PARENTID: %s"
                                    % (process, str(process["PARENT_PID"])))

        # Process: explorer.exe
        if process["PATH"] != "none":
            if process["NAME"] == "explorer.exe" and not self.t_systemroot.lower() in process["PATH"].lower():
                printMess(messtype="WARNING", message=f"explorer.exe path is not %%SYSTEMROOT%% {process}")
        if process["NAME"] == "explorer.exe" and process["PARENT_PID"] > 0:
            for proc in wmi.WMI().Win32_Process():
                if process["PARENT_PID"] == proc.ProcessId:
                    printMess("NOTICE", message=f"explorer.exe has a parent ID but should have none {process}")

    # THOR Process Connection Checks----------------------- 
    """ 
    :Base on `https://www.nextron-systems.com/thor/` idea:
    """
    def check_c2(self, remote_system: str, c2_server: Dict):
        # IP - exact match
        if is_ip(remote_system):
            for c2 in c2_server:
                # if C2 definition is CIDR network
                if is_cidr(c2):
                    if ip_in_net(remote_system, c2):
                        return True, c2_server[c2]
                # if C2 is ip or else
                if c2 == remote_system:
                    return True, c2_server[c2]
        # Domain - remote system contains c2
        # e.g. evildomain.com and dga1.evildomain.com
        else:
            for c2 in c2_server:
                if c2 in remote_system:
                    return True, c2_server[c2]

        return False,""

    def thor_proConnections(self, process, c2_server: Dict):
        try:

            # Limits
            MAXIMUM_CONNECTIONS = 20

            # Counter
            connection_count = 0

            # Get psutil info about the process
            try:
                p = psutil.Process(process["PID"])
            except Exception as e:
                traceback.print_exc()
                return

            # print "Checking connections of %s" % process.Name
            for x in p.connections():

                # Evaluate a usable command line to check
                try:
                    command = process["CMD"]
                except Exception:
                    command = p.cmdline()

                if x.status == 'LISTEN':
                    connection_count += 1
                    printMess(messtype="NOTICE", message="Listening process PID: %s NAME: %s COMMAND: %s IP: %s PORT: %s" % (
                        str(process["PID"]), process["NAME"], command, str(x.laddr[0]), str(x.laddr[1]) ))
                    if str(x.laddr[1]) == "0":
                        printMess(messtype="WARNING", message="Listening on Port 0 PID: %s NAME: %s COMMAND: %s  IP: %s PORT: %s" % (
                                str(process["PID"]), process["NAME"], command, str(x.laddr[0]), str(x.laddr[1]) ))

                if x.status == 'ESTABLISHED':

                    # Lookup Remote IP
                    # Geo IP Lookup removed

                    # Check keyword in remote address
                    is_match, description = self.check_c2(str(x.raddr[0]), c2_server)
                    if is_match:
                        printMess(messtype="ALERT", message="Malware Domain/IP match in remote address PID: %s NAME: %s COMMAND: %s IP: %s PORT: %s DESC: %s" % (
                                str(process["PID"]), process["NAME"], command, str(x.raddr[0]), str(x.raddr[1]), description))

                    # Full list
                    connection_count += 1
                    printMess(messtype="NOTICE",
                               message="ProcessScan Established connection PID: %s NAME: %s COMMAND: %s LIP: %s LPORT: %s RIP: %s RPORT: %s" % (
                        str(process["PID"]), process["NAME"], command, str(x.laddr[0]), str(x.laddr[1]), str(x.raddr[0]), str(x.raddr[1]) ))

                # Maximum connection output
                if connection_count > MAXIMUM_CONNECTIONS:
                    printMess(messtype="NOTICE", message="Connection output threshold reached. Output truncated.")
                    return

        except Exception as e:
            printMess(messtype="INFO", message="Process %s does not exist anymore or cannot be accessed" % str(process["PID"]))
            traceback.print_exc()
            sys.exit(1)
            
    # PE-Sieve Checks--------------------------------------
    def pe_sieve(self, process, shellc = False):

        # Start
        try:
            if self.processExists(process["PID"]):
                result = self.peSieve.scan(process["PID"], shellc)

            if result["replaced"]:
                printMess(messtype="WARNING", message="PE-Sieve reported replaced process %s REPLACED: %s" %
                            (process, str(result["replaced"])))
            elif result["implanted_pe"] or result["implanted_shc"]:
                printMess(messtype="WARNING", message="PE-Sieve reported implanted process %s "
                            "IMPLANTED PE: %s IMPLANTED SHC: %s" % (process, str(result["implanted_pe"]),
                                                                    str(result["implanted_shc"])) )
            elif result["patched"]:
                printMess(messtype="NOTICE", message="PE-Sieve reported patched process %s PATCHED: %s" %
                            (process, str(result["patched"])))
            elif result["unreachable_file"]:
                printMess(messtype="NOTICE",message="PE-Sieve reported a process with unreachable exe %s UNREACHABLE: %s" %
                            (process, str(result["unreachable_file"])))
            else:
                printMess(messtype="INFO", message="PE-Sieve reported no anomalies %s" % process)
                
        except WindowsError as e:
            traceback.print_exc()
            printMess(messtype="ERROR", message ="Error while accessing process handle using PE-Sieve.")

    # # Scan Process ----------------------------------------
    # def scan_processes(self):
    #     for process in self.get_proInfor():
    #         # Skip some PIDs and Current own process
    #         if process["PID"] == 0 or process["PID"] == 4:
    #             printMess(messtype="INFOR", message=f"Skipping Process: {process}")
    #             continue
    #         if process["PID"] == os.getpid() or process["PID"] == psutil.Process(os.getpid()).ppid():
    #             printMess(messtype="INFOR", message=f"Skipping Current Own Process: {process}")
    #             continue
    #         # Else
    #         if process["NAME"] == "wininit.exe":
    #             self.wininit_pid = process["PID"]
    #         ## Next 
    #         print("------------------------------------------------------------")
    #         printMess(messtype="INFOR", message=f"Scanning Process: {process}")
    #         ### Skeleton Key Malware Process
    #         if re.search(r"psexec .* [a-fA-F0-9]{32}", process["CMD"], re.IGNORECASE):
    #             printMess(messtype="WARNING", message=f"Process that looks liks SKELETON KEY psexec execution detected {process}")
    #         ###############################################################
    #         # Yara Process Memory Checks
    #         # self.yara_processes(process)
    #         ###############################################################
    #         # PE-Sieve Checks
    #         self.pe_sieve(process)
    #         print("------------------------------------------------------------")
    #         ############################################################### 
    #         # Thor Process Connections Checks
    #         # self.thor_proConnections(process)
    #         # print("------------------------------------------------------------")
    #         ###############################################################
    #         # Thor Process Anomaly Checks
    #         # self.thor_proAnomaly(process)
            



