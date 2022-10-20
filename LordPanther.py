import argparse
from models.Process import Process
from models.Manager import Manager
from lib.util.helper import printMess
import os
import psutil


def init_args():
    parser = argparse.ArgumentParser(description="LordPanther - Process Scanner | This's Cover Project base on https://github.com/Neo23x0/Loki"
                                    "I also want to use this opportunity to express my gratitude and respect to Neo23x0 && @hasherezade")
    
    parser.add_argument("--nofilenameioc", help="Do not perform IOCs_FileName scans", default=False, action="store_true")
    parser.add_argument("--noyara", help="Do not perform yara process memory scans", default=False, action="store_true")
    parser.add_argument("--nothorcnc", help="Do not perform Command And Control (Process Connection) scans", default=False, action="store_true")
    parser.add_argument("--nothoranomaly", help="Do not perform Thor Process Anomaly scans", default=False, action="store_true")
    parser.add_argument("--nopesieve", help="Do not perform PE-SIEVE scans", default=False, action="store_true")
    
    return parser.parse_args()

def scan_processes(manager: Manager, taskmgr: Process, args):
    for process in taskmgr.get_proInfor():
        # Skip some PIDs and Current own process
        if process["PID"] == 0 or process["PID"] == 4:
            printMess(messtype="INFOR", message=f"Skipping Process: {process} {chr(10)}")
            continue
        if process["PID"] == os.getpid() or process["PID"] == psutil.Process(os.getpid()).ppid():
            printMess(messtype="INFOR", message=f"Skipping Current Own Process: {process}")
            continue
        # Else
        if process["NAME"] == "wininit.exe":
            taskmgr.wininit_pid = process["PID"]
        ## Next 
        print(f'{chr(10)}{chr(9)*4}||====<> {process["NAME"]} | ID: {process["PID"]} <>====||')
        printMess(messtype="INFOR", message=f"Scanning Process: {process} {chr(10)}")
        ###############################################################
        # File Name Check
        if not args.nofilenameioc:
            taskmgr.check_fileName(process, manager.filename_iocs)
        ###############################################################
        # Yara Process Memory Checks
        if not args.noyara:
            taskmgr.yara_processes(process, manager.yara_rules)
        ###############################################################
        # PE-Sieve Checks
        if not args.nopesieve:
            taskmgr.pe_sieve(process)
        ############################################################### 
        # Thor Process Connections Checks
        if not args.nothorcnc:
            taskmgr.thor_proConnections(process, manager.c2_server)
        ###############################################################
        # Thor Process Anomaly Checks
        if not args.nothoranomaly:
            taskmgr.thor_proAnomaly(process)


if __name__ == "__main__":

    # Initialization arguments ---------------------------------------------------------------
    args = init_args()

    # Creating Objects ------------------------------------------------------------------------
    manager = Manager()
    taskmgr = Process()

    # Manager'll check existence of signatures-base. If NOT will update from signature-base Neo23x0()github repo
    if not manager.exist_sigs_base():
        manager.update_signatures()

    
    print("\n=======================|>| STARTING LOAD SIGNATURES |<|========================\n")
    # Read IOCs -------------------------------------------------------------------------------
    # File Name IOCs (all files in iocs that contain 'filename') | Return filename_iocs = [] attribute
    if not args.nofilenameioc:
        manager.load_filename_iocs(manager.ioc_path)
        printMess(messtype="INFO", message="File Name Characteristics initialized with %s regex patterns" % len(manager.filename_iocs))
    else:
        printMess(messtype="INFO", message="File Name Characteristics Initialization was DEACTIVATED with --nofilenameioc.")

    # C2 based IOCs (all files in iocs that contain 'c2') | Return c2_server = {} attribute
    if not args.nothorcnc:
        manager.load_c2_iocs(manager.ioc_path)
        printMess(messtype="INFO",message= "C2 server indicators initialized with %s elements" % len(manager.c2_server.keys()))
    else:
        printMess(messtype="INFO", message="C2 server indicators Initialization was DEACTIVATED with --nothorcnc.")

    # Compile Yara Rules | Return yara_rules = [] attribute
    if not args.noyara:
        manager.load_yara_rules()
    else:
        printMess(messtype="INFO", message="Processing YARA rules folder Initialization was DEACTIVATED with --noyara.")


    print("\n=======================|>| STARTING PROCESSES SCANNER |<|=======================\n")
    # Call scan_processes function--------------------------------------------------------------
    scan_processes(manager=manager, taskmgr=taskmgr, args=args)

    




