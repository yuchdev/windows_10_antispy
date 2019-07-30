import os
import sys
import stat
import argparse
import logging
import log_helper
import subprocess

logger = log_helper.setup_logger(name="win10_cleaner", level=logging.DEBUG, log_to_file=True)


"""Map human-readable service names to system name
For example "Diagnostic Policy Service" should be addressed "DPS"
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
    return [x.strip() for x in content if x.strip() != ""]


def disable_service(service):
    """
    :param service: Human-readable service name to disable, for example "Security Center"
    """
    logger.info('Trying to disable service "{0}"'.format(service))
    system_srv_name = SERVICES[service]
    logger.info('System service name "{0}"'.format(system_srv_name))

    ret = os.system('sc config "{0}" start= disabled'.format(system_srv_name))
    if ret != 0:
        logger.warning("sc config returned error code {0}".format(ret))

    ret = os.system('sc stop "{0}"'.format(system_srv_name))
    if ret != 0:
        logger.warning("sc stop returned error code {0}".format(ret))


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


def disable_services(services_list):
    """
    :param services_list: List of Human-readable service names to disable
    :return:
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
    parser.add_argument('--services-file',
                        help='Pass text file with newline-separated names',
                        dest='services_file',
                        default="",
                        required=False)

    args = parser.parse_args()
    services_file = args.services_file

    if services_file != "":
        logger.info("Service list loaded from file {0}".format(services_file))
        services_list = read_from_file(services_file)
    else:
        logger.info("Default service list selected")
        services_list = default_services

    disable_services(services_list)
    disable_tasks(TASKS)

    return 0


###########################################################################
if __name__ == '__main__':
    sys.exit(main())
