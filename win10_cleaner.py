import os
import sys
import stat
import argparse
import logging
import log_helper

logger = log_helper.setup_logger(name="win10_cleaner", level=logging.DEBUG, log_to_file=True)

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
    with open(services_file) as f:
        content = f.readlines()
    # remove whitespace characters like `\n` at the end of each line
    return [x.strip() for x in content]


# Delete bloatware with PS script

# Disable
def disable_service(service):
    os.system('sc config "{0}" start= disabled'.format(service))
    os.system('sc stop "{0}"'.format(service))


def disable_services(services_list):
    for srv in services_list:
        disable_service(srv)


# Disable GP (API or registry)

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
        services_list = read_from_file(services_file)
    else:
        services_list = default_services

    disable_services(services_list)

    return 0


###########################################################################
if __name__ == '__main__':
    sys.exit(main())
