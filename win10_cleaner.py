import os
import sys
import stat
import argparse
import logging
import log_helper
import subprocess
import psutil

logger = log_helper.setup_logger(name="win10_cleaner", level=logging.DEBUG, log_to_file=True)

"""We assume hosts located there. 
In future versions of application we will be locating Windows directory to cover all cases.
"""
HOSTS_FILE = "C:\\Windows\\System32\\drivers\\etc\\hosts"


"""List of telemetry-relates websites to add to hosts file and disable all traffic on it.
"""
TELEMETRY_SERVERS = """
0.0.0.0 vortex.data.microsoft.com
0.0.0.0 vortex-win.data.microsoft.com
0.0.0.0 telecommand.telemetry.microsoft.com
0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net
0.0.0.0 oca.telemetry.microsoft.com
0.0.0.0 oca.telemetry.microsoft.com.nsatc.net
0.0.0.0 sqm.telemetry.microsoft.com
0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net
0.0.0.0 watson.telemetry.microsoft.com
0.0.0.0 watson.telemetry.microsoft.com.nsatc.net
0.0.0.0 redir.metaservices.microsoft.com
0.0.0.0 choice.microsoft.com
0.0.0.0 choice.microsoft.com.nsatc.net
0.0.0.0 df.telemetry.microsoft.com
0.0.0.0 reports.wes.df.telemetry.microsoft.com
0.0.0.0 wes.df.telemetry.microsoft.com
0.0.0.0 services.wes.df.telemetry.microsoft.com
0.0.0.0 sqm.df.telemetry.microsoft.com
0.0.0.0 telemetry.microsoft.com
0.0.0.0 watson.ppe.telemetry.microsoft.com
0.0.0.0 telemetry.appex.bing.net
0.0.0.0 telemetry.urs.microsoft.com
0.0.0.0 telemetry.appex.bing.net:443
0.0.0.0 settings-sandbox.data.microsoft.com
0.0.0.0 vortex-sandbox.data.microsoft.com
0.0.0.0 survey.watson.microsoft.com
0.0.0.0 watson.live.com
0.0.0.0 watson.microsoft.com
0.0.0.0 statsfe2.ws.microsoft.com
0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com
0.0.0.0 compatexchange.cloudapp.net
0.0.0.0 cs1.wpc.v0cdn.net
0.0.0.0 a-0001.a-msedge.net
0.0.0.0 statsfe2.update.microsoft.com.akadns.net
0.0.0.0 sls.update.microsoft.com.akadns.net
0.0.0.0 fe2.update.microsoft.com.akadns.net
0.0.0.0 65.55.108.23 
0.0.0.0 65.39.117.230
0.0.0.0 23.218.212.69 
0.0.0.0 134.170.30.202
0.0.0.0 137.116.81.24
0.0.0.0 diagnostics.support.microsoft.com
0.0.0.0 corp.sts.microsoft.com
0.0.0.0 statsfe1.ws.microsoft.com
0.0.0.0 pre.footprintpredict.com
0.0.0.0 204.79.197.200
0.0.0.0 23.218.212.69
0.0.0.0 i1.services.social.microsoft.com
0.0.0.0 i1.services.social.microsoft.com.nsatc.net
0.0.0.0 feedback.windows.com
0.0.0.0 feedback.microsoft-hohm.com
0.0.0.0 feedback.search.microsoft.com
"""


"""Map human-readable service names to system name.
For example "Diagnostic Policy Service" should be addressed "DPS".
Like "net stop DPS"
"""
SERVICES = {
    # Related to Telemetry
    "Connected User Experiences and Telemetry": "DiagTrack",
    "Diagnostic Policy Service": "DPS",
    "dmwappushsvc": "dmwappushsvc",

    # If you don't use Maps
    "Downloaded Maps Manager": "MapsBroker",

    # If you don't use IPv6
    "IP Helper": "iphlpsvc",

    # If you don't want remote registry
    "Remote Registry": "RemoteRegistry",

    # Safe to turn off
    "Secondary Logon": "seclogon",

    # Use anti-malware instead
    "Security Center": "wscsvc",

    # If you don't want to use touch keyboard
    "Touch Keyboard and Handwriting Panel Service": "TabletInputService",

    # Use anti-malware instead
    "Windows Defender Service": "mpssvc",

    # Safe to turn off
    "Windows Error Reporting Service": "WerSvc",

    # If you don't have scanner
    "Windows Image Acquisition": "stisvc"
}


TASKS = ["\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
         "\\Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
         "\\Microsoft\\Windows\\Application Experience\\StartupAppTask",
         "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
         "\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip"]


POWERSHELL_COMMAND = r'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe'


def on_rm_error(*args):
    """
    In case the file or directory is read-only and we need to delete it
    this function will help to remove 'read-only' attribute
    :param args: (func, path, exc_info) yuple
    """
    # path contains the path of the file that couldn't be removed
    # let's just assume that it's read-only and unlink it.
    _, path, _ = args
    os.chmod(path, stat.S_IWRITE)
    logger.warning("Unable to delete %s" % path)
    os.unlink(path)


def read_from_file(services_file):
    """
    :param services_file: File with newline-separated services list
    :return: list of services with stripped newlines and skipped empty strings
    """
    with open(services_file) as f:
        content = f.readlines()
    # remove whitespace characters like `\n` at the end of each line
    return [x.strip() for x in content if x]


def disable_service(service):
    """
    :param service: Human-readable service name to disable, for example "Security Center"
    """
    logger.info('Trying to disable service "{0}"'.format(service))
    system_srv_name = SERVICES[service]
    logger.info('System service name "{0}"'.format(system_srv_name))

    ret = os.system('sc config "{0}" start= disabled'.format(system_srv_name))
    if ret != 0:
        logger.warning("sc config returned error code {0}, in some cases it's okay".format(ret))

    ret = os.system('sc stop "{0}"'.format(system_srv_name))
    if ret != 0:
        logger.warning("sc stop returned error code {0}, in some cases it's okay".format(ret))


def disable_task(task_name):
    """

    :param task_name:
    :return:
    """
    subprocess.Popen([POWERSHELL_COMMAND,
                      '-ExecutionPolicy', 'Unrestricted',
                      'Disable-ScheduledTask', '-TaskName', '"{0}"'.format(task_name)],
                     stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE)
    logger.info('Task "{0}" disabled'.format(task_name))


def disable_services(services_list):
    """
    :param services_list: List of Human-readable service names to disable
    """
    for srv in services_list:
        disable_service(srv)


def disable_tasks(tasks_list):
    """
    :param tasks_list: List of tasks in standard Scheduler format
    \\Microsoft\\Windows\\Application Experience\\StartupAppTask
    ""
    :return:
    """
    for task in tasks_list:
        disable_task(task)


def take_file_ownership():
    """
    Take ownership over 'hosts' file, which is necessary to edit it even under Administrator rights
    """
    ret = os.system("takeown.exe /f {0}".format(HOSTS_FILE))
    if ret == 0:
        logger.info("Ownership of '{0}' file has been taken successfully".format(HOSTS_FILE))
    else:
        logger.warning("takeown.exe returned error code {0}, unable to take ownership {1}".format(ret, HOSTS_FILE))


def disable_telemetry_traffic():
    """
    Disable all traffic to known MS Telemetry servers
    """
    with open(HOSTS_FILE, "a") as hosts_file:
        hosts_file.write(TELEMETRY_SERVERS)
    logger.info("All traffic to MS Telemetry servers disabled")


def find_cortana_directory(name, path):
    """
    :param name: Name of Cortana executable
    :param path: Path to Windows Store applications directory
    :return: Path to the directory contains Cortana
    """
    for root, dirs, files in os.walk(path):
        if name in files:
            return root


def disable_cortana_service():
    cortana_directory = find_cortana_directory("SearchUI.exe", "C:\\Windows\\SystemApps")
    logger.info("Cortana found at path %s" % cortana_directory)

    for p in psutil.process_iter():
        # Kill auxiliary processes
        if p.name() in ["ActionUriServer.exe",
                        "PlacesServer.exe",
                        "backgroundTaskHost.exe",
                        "RemindersServer.exe",
                        "RemindersShareTargetApp.exe"]:
            cortana_path = p.exe()
            logger.info("Auxiliary process found at path {0}, PID={1}".format(cortana_path, p.pid))
            p.kill()

        if p.name() == "SearchUI.exe":
            # Kill Cortana processes
            cortana_path = p.exe()
            logger.info("Cortana process run at path {0}, PID={1}".format(cortana_path, p.pid))

            cortana_directory, _ = os.path.split(cortana_path)
            logger.debug("Cortana directory %s" % cortana_directory)
            p.kill()
            p.wait()

    # make it never rub again
    new_cortana_directory = cortana_directory + "_cortana_backup"            
    os.rename(cortana_directory, new_cortana_directory)
    logger.debug("New Cortana directory %s" % new_cortana_directory)


def main():
    """
    Uninstall applications based on list, or simply retrreive the list of installed applications
    :return: System return code
    """
    default_services = ["Connected User Experiences and Telemetry",
                        "Diagnostic Policy Service",
                        "dmwappushsvc",
                        "Downloaded Maps Manager",
                        "IP Helper",
                        "Remote Registry",
                        "Secondary Logon",
                        "Security Center",
                        "Touch Keyboard and Handwriting Panel Service",
                        "Windows Defender Service",
                        "Windows Error Reporting Service",
                        "Windows Image Acquisition"]

    parser = argparse.ArgumentParser(description='Command-line params')
    parser.add_argument('--stop-services',
                        help='Stop services and tasks, providing private data transfer to Microsoft',
                        action='store_true',
                        default="",
                        required=False)
    parser.add_argument('--block-telemetry-traffic',
                        help='Block traffic to all known Microsoft servers, related to telemetry collection',
                        action='store_true',
                        default=False,
                        required=False)
    parser.add_argument('--disable-cortana',
                        help='Disable Cortana from constant consuming system resources',
                        action='store_true',
                        default=False,
                        required=False)

    args = parser.parse_args()

    stop_services = args.stop_services
    block_telemetry_traffic = args.block_telemetry_traffic
    disable_cortana = args.disable_cortana

    if stop_services:
        services_list = default_services
        disable_services(services_list)
        disable_tasks(TASKS)

    if block_telemetry_traffic:
        take_file_ownership()
        disable_telemetry_traffic()

    if disable_cortana:
        disable_cortana_service()

    return 0


###########################################################################
if __name__ == '__main__':
    sys.exit(main())
