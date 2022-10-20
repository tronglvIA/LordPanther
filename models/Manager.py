from email import message
from email.message import Message
import logging
from urllib.request import urlopen
import traceback
import os, sys
import zipfile
import io
import shutil
import yara
import codecs
# Alter relate path's package to import `..lib.util.helper` 
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from lib.util.helper import *


class Manager:

    # Signatures Attribute
    yara_rules = []
    filename_iocs = []
    c2_server = {}
    # Yara rule directories
    yara_rule_directories = []

    UPDATE_URL_SIGS = [
        "https://github.com/Neo23x0/signature-base/archive/master.zip",
        "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/develop.zip"
    ]

    # Constructor -----------------------------------------
    def __init__(self):
        cwd_path =  os.path.dirname(os.path.realpath(__file__))
        self.project_path = os.path.dirname(cwd_path)
        # Set IOC path
        self.ioc_path = os.path.join(self.project_path, "signature-base/iocs/".replace("/", os.sep))
        # Yara rule directories
        self.yara_rule_directories.append(os.path.join(self.project_path, "signature-base/yara".replace("/", os.sep)))
        self.yara_rule_directories.append(os.path.join(self.project_path, "signature-base/iocs/yara".replace("/", os.sep)))
        self.yara_rule_directories.append(os.path.join(self.project_path, "signature-base/3rdparty".replace("/", os.sep)))

    # Download Signatures ---------------------------------
    def update_signatures(self):
        try:
            # Download Signatures-Base from the URL list (self.UPDATE_URL_SIGS).
            for url_sig in self.UPDATE_URL_SIGS:
                ## Request to URL
                try:
                    printMess(messtype="INFOR", message=f"Manager Downloading {url_sig} ...")
                    response = urlopen(url_sig)
                except Exception as e:
                    printMess(messtype="ERROR", message="Error downloading the signature database - "
                                                        "check your Internet connection")
                    traceback.print_exc()
                    sys.exit(1)

                ## Creating Signature Base Directory
                try:
                    # Create path for signature-base folder.
                    sigDir = os.path.join(self.project_path, os.path.abspath("signature-base/"))
                    # Separate Yara Rules into SubFolders
                    for subFolder in ["", "iocs", "yara", "misc"]:
                        path2_subFolder_rules = os.path.join(sigDir, subFolder)
                        if not os.path.exists(path2_subFolder_rules):
                            os.makedirs(path2_subFolder_rules)
                except Exception as e:
                    printMess(messtype="ERROR", message="Error while creating the signature-base directories.")
                    traceback.print_exc()
                    sys.exit(1)

                ## Extract the Archive File
                try:
                    # Read ZipFile data
                    zipData = zipfile.ZipFile(io.BytesIO(response.read()))
                    for zipFilePath in zipData.namelist():
                        sigName = os.path.basename(zipFilePath)
                        # Extract the rules
                        printMess(messtype="INFOR", message=f"Extracting {zipFilePath} ...")
                        if "/iocs/" in zipFilePath and zipFilePath.endswith(".txt"):
                            targetFile = os.path.join(sigDir, "iocs", sigName)
                        elif "/yara/" in zipFilePath and zipFilePath.endswith(".yar"):
                            targetFile = os.path.join(sigDir, "yara", sigName)
                        elif "/misc/" in zipFilePath and zipFilePath.endswith(".txt"):
                            targetFile = os.path.join(sigDir, "misc", sigName)
                        elif zipFilePath.endswith(".yara"):
                            targetFile = os.path.join(sigDir, "yara", sigName)
                        else:
                            continue
                        # New file
                        if not os.path.exists(targetFile):
                            printMess(messtype="INFO", message=f"New signature file: {sigName}")
                        # Extract file
                        source = zipData.open(zipFilePath)
                        target = open(targetFile, "wb")
                        with source, target:
                            shutil.copyfileobj(source, target)
                        target.close()
                        source.close()
                except Exception as e:
                    printMess(messtype="ERROR", message="Error while extracting the signature files from the download "
                                                         "package")
                    traceback.print_exc()  
                    sys.exit(1)   
                                                    
        except Exception as e:
            traceback.print_exc()
            return False

        return True

    # Loading Signatures Base -----------------------------
    #:filename_iocs:
    def load_filename_iocs(self, ioc_directory):
        os_platform = sys.platform
    
        try:
            for ioc_filename in os.listdir(ioc_directory):
                if 'filename' in ioc_filename:
                    with codecs.open(os.path.join(ioc_directory, ioc_filename), 'r', encoding='utf-8') as file:
                        lines = file.readlines()

                        # Last Comment Line
                        last_comment = ""
                        # Initialize score variable
                        score = 0
                        # Initialize empty description
                        desc = ""

                        for line in lines:
                            try:
                                # Empty
                                if re.search(r'^[\s]*$', line):
                                    continue

                                # Comments
                                if re.search(r'^#', line):
                                    last_comment = line.lstrip("#").lstrip(" ").rstrip("\n")
                                    continue

                                # Elements with description
                                if ";" in line:
                                    line = line.rstrip(" ").rstrip("\n\r")
                                    row = line.split(';')
                                    regex = row[0]
                                    score = row[1]
                                    if len(row) > 2:
                                        regex_fp = row[2]
                                    desc = last_comment

                                # Elements without description
                                else:
                                    regex = line

                                # Replace environment variables
                                regex = replaceEnvVars(regex)
                                # OS specific transforms
                                regex = transformOS(regex, os_platform)

                                # If false positive definition exists
                                regex_fp_comp = None
                                if 'regex_fp' in locals():
                                    # Replacements
                                    regex_fp = replaceEnvVars(regex_fp)
                                    regex_fp = transformOS(regex_fp, os_platform)
                                    # String regex as key - value is compiled regex of false positive values
                                    regex_fp_comp = re.compile(regex_fp)

                                # Create dictionary with IOC data
                                fioc = {'regex': re.compile(regex), 'score': score, 'description': desc, 'regex_fp': regex_fp_comp}
                                self.filename_iocs.append(fioc)

                            except Exception as e:
                                printMess(messtype="ERROR", message= "Error reading line: %s" % line)
                                traceback.print_exc()
                                sys.exit(1)

        except Exception as e:
            if 'ioc_filename' in locals():
                printMess(messtype="ERROR",  message= "Init-Error reading IOC file: %s" % ioc_filename)
            else:
                printMess(messtype="ERROR",  message= "Init-Error reading files from IOC folder: %s" % ioc_directory)  
            sys.exit(1)

    #:Command and control iocs:
    def load_c2_iocs(self, ioc_directory):
        try:
            for ioc_filename in os.listdir(ioc_directory):
                try:
                    if 'c2' in ioc_filename:
                        with codecs.open(os.path.join(ioc_directory, ioc_filename), 'r', encoding='utf-8') as file:
                            lines = file.readlines()

                            # Last Comment Line
                            last_comment = ""

                            for line in lines:
                                try:
                                    # Comments and empty lines
                                    if re.search(r'^#', line) or re.search(r'^[\s]*$', line):
                                        last_comment = line.lstrip("#").lstrip(" ").rstrip("\n")
                                        continue

                                    # Split the IOC line
                                    if ";" in line:
                                        line = line.rstrip(" ").rstrip("\n\r")
                                        row = line.split(';')
                                        c2 = row[0]
                                        # LoadPanther doesn't use the C2 score (only THOR Lite)
                                        # score = row[1]

                                        # Elements without description
                                    else:
                                        c2 = line

                                    # Check length
                                    if len(c2) < 4:
                                        printMess(messtype="NOTICE", message=
                                                   "Init-C2 server definition is suspiciously short - will not add %s" %c2)
                                        continue

                                    # Add to the LoadPanther iocs
                                    self.c2_server[c2.lower()] = last_comment

                                except Exception as e:
                                    printMess(messtype="ERROR", message= "Init-Cannot read line: %s" % line)
                                    sys.exit(1)
                except OSError as e:
                    printMess(messtype="ERROR", message="Init-No such file or directory")
        except Exception as e:
            traceback.print_exc()
            printMess(messtype="ERROR", message="Init-Error reading Hash file: %s" % ioc_filename)

    #:Load yara_rules:
    def walk_error(self,err):
        if "Error 3" in str(err):
            logging.error(str(err))
            print("Directory walk error")

    def load_yara_rules(self):
    
        yaraRules = ""
        dummy = ""
        rule_count = 0

        try:
            for yara_rule_directory in self.yara_rule_directories:
                if not os.path.exists(yara_rule_directory):
                    continue
                printMess(messtype="INFO", message= "Init-Processing YARA rules folder {0}".format(yara_rule_directory))
                for root, directories, files in os.walk(yara_rule_directory, onerror=self.walk_error, followlinks=False):
                    for file in files:
                        try:
                            # Full Path
                            yaraRuleFile = os.path.join(root, file)

                            # Skip hidden, backup or system related files
                            if file.startswith(".") or file.startswith("~") or file.startswith("_"):
                                continue

                            # Extension
                            extension = os.path.splitext(file)[1].lower()

                            # Skip all files that don't have *.yar or *.yara extensions
                            if extension != ".yar" and extension != ".yara":
                                continue

                            with open(yaraRuleFile, 'r') as yfile:
                                yara_rule_data = yfile.read()

                            # Test Compile
                            try:
                                compiledRules = yara.compile(source=yara_rule_data, externals={
                                    'filename': dummy,
                                    'filepath': dummy,
                                    'extension': dummy,
                                    'filetype': dummy,
                                    'md5': dummy,
                                    'owner': dummy,
                                })
                                printMess(messtype="DEBUG", message="Init-Initializing Yara rule %s" % file)
                                rule_count += 1
                            except Exception as e:
                                printMess(messtype="ERROR", message="Init-Error while initializing Yara rule %s ERROR: %s" % (file, sys.exc_info()[1]))
                                traceback.print_exc()
                                # if logger.debug:
                                #     sys.exit(1)
                                continue

                            # Add the rule
                            yaraRules += yara_rule_data

                        except Exception as e:
                            printMess(messtype="ERROR", message="Init-Error reading signature file %s ERROR: %s" % (yaraRuleFile, sys.exc_info()[1]))
                            traceback.print_exc()
                                # sys.exit(1)

            # Compile
            try:
                printMess("INFO", "Initializing all YARA rules at once (composed string of all rule files)")
                compiledRules = yara.compile(source=yaraRules, externals={
                    'filename': dummy,
                    'filepath': dummy,
                    'extension': dummy,
                    'filetype': dummy,
                    'md5': dummy,
                    'owner': dummy,
                })
                printMess(messtype="INFO", message="Initialized %d Yara rules" % rule_count)
            except Exception as e:
                traceback.print_exc()
                printMess(messtype="ERROR", message="Init-Error during YARA rule compilation ERROR: %s - please fix the issue in the rule set" % sys.exc_info()[1])
                sys.exit(1)

            # Add as LoadPanther YARA rules
            self.yara_rules.append(compiledRules)

        except Exception as e:
            printMess(messtype="ERROR", message="Init-Error reading signature folder /signatures/")
            traceback.print_exc()
            sys.exit(1)

    # Checking Exists Signature-Base ----------------------
    def exist_sigs_base(self):
        cwd_path =  os.path.dirname(os.path.realpath(__file__))
        project_path = os.path.dirname(cwd_path)
        sigDir = os.path.join(project_path, "signature-base")
        if not os.path.exists(sigDir) or os.listdir(sigDir) == []:
            printMess(messtype="NOTICE", message="The 'signature-base' subdirectory doesn't exist or is empty. "
                                         "Trying to retrieve the signature database automatically.")
            return False
        return True

    
