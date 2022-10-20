import platform
import threading
import subprocess
import os
import signal
import traceback
import re
from datetime import datetime
import netaddr

# Print Notification
def printMess(messtype, message):
    timenow = (datetime.now()).strftime("%d-%m-%Y %H:%M:%S")
    print("[{}] {}: {}".format(timenow, messtype, message))

def getPlatformFull():
    type_info = ""
    try:
        type_info = "%s PROC: %s ARCH: %s" % ( " ".join(platform.win32_ver()), platform.processor(), " ".join(platform.architecture()))
    except Exception as e:
        type_info = " ".join(platform.win32_ver())
    return type_info

def runProcess(command, timeout=10):
    """
    Run a process and check it's output
    :param command:
    :return output:
    """
    output = ""
    returnCode = 0

    # Kill check
    try:
        kill_check = threading.Event()
        def _kill_process_after_a_timeout(pid):
            # https://stackoverflow.com/questions/6688815/windowserror-error-5-access-is-denied
            # https://github.com/jupyter/nbmanager/issues/8
            os.kill(pid, signal.SIGTERM)
            kill_check.set() # tell the main routine that we had to kill
            print("timeout hit - killing pid {0}".format(pid))
            # use SIGKILL if hard to kill...
            return "", 1
        try:
            p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError as e:
            returnCode = e.returncode
            traceback.print_exc()
        #print p.communicate()[0]
        pid = p.pid
        watchdog = threading.Timer(timeout, _kill_process_after_a_timeout, args=(pid, ))
        watchdog.start()
        (stdout, stderr) = p.communicate()
        output = "{0}{1}".format(stdout.decode('utf-8'), stderr.decode('utf-8'))
        watchdog.cancel() # if it's still waiting to run
        success = not kill_check.isSet()
        kill_check.clear()
    except Exception as e:
        traceback.print_exc()

    return output, returnCode

def check_svchost_owner(self, owner):
    ## Locale setting
    import ctypes
    import locale
    windll = ctypes.windll.kernel32
    locale = locale.windows_locale[ windll.GetUserDefaultUILanguage() ]
    if locale == 'fr_FR':
        return (owner.upper().startswith("SERVICE LOCAL") or
            owner.upper().startswith(u"SERVICE RÉSEAU") or
            re.match(r"SERVICE R.SEAU", owner) or
            owner == u"Système"  or
            owner.upper().startswith(u"AUTORITE NT\Système") or
            re.match(r"AUTORITE NT\\Syst.me", owner))
    elif locale == 'ru_RU':
        return (owner.upper().startswith("NET") or
            owner == u"система" or
            owner.upper().startswith("LO"))
    else:
        return ( owner.upper().startswith("NT ") or owner.upper().startswith("NET") or
            owner.upper().startswith("LO") or
            owner.upper().startswith("SYSTEM"))

def transformOS(regex, platform):
    # Replace '\' with '/' on Linux/Unix/OSX
    if platform != "win32":
        regex = regex.replace(r'\\', r'/')
        regex = regex.replace(r'C:', '')
    return regex

def replaceEnvVars(path):

    # Setting new path to old path for default
    new_path = path

    # ENV VARS ----------------------------------------------------------------
    # Now check if an environment env is included in the path string
    res = re.search(r"([@]?%[A-Za-z_]+%)", path)
    if res:
        env_var_full = res.group(1)
        env_var = env_var_full.replace("%", "").replace("@", "")

        # Check environment variables if there is a matching var
        if env_var in os.environ:
            if os.environ[env_var]:
                new_path = path.replace(env_var_full, re.escape(os.environ[env_var]))

    # TYPICAL REPLACEMENTS ----------------------------------------------------
    if path[:11].lower() == "\\systemroot":
        new_path = path.replace("\\SystemRoot", os.environ["SystemRoot"])

    if path[:8].lower() == "system32":
        new_path = path.replace("system32", "%s\\System32" % os.environ["SystemRoot"])

    #if path != new_path:
    #    print "OLD: %s NEW: %s" % (path, new_path)
    return new_path

def is_ip(string):
    try:
        if netaddr.valid_ipv4(string):
            return True
        if netaddr.valid_ipv6(string):
            return True
        return False
    except:
        traceback.print_exc()
        return False


def is_cidr(string):
    try:
        if netaddr.IPNetwork(string) and "/" in string:
            return True
        return False
    except:
        return False


def ip_in_net(ip, network):
    try:
        # print "Checking if ip %s is in network %s" % (ip, network)
        if netaddr.IPAddress(ip) in netaddr.IPNetwork(network):
            return True
        return False
    except:
        return False