import os
import sys
import argparse
import logging
import log_helper
import subprocess
import psutil
import getpass

logger = log_helper.setup_logger(name="win10_cleaner", level=logging.DEBUG, log_to_file=True)

"""
We use PowerShell for most of operations. Python provides convenient wrapper for its output
"""
POWERSHELL_COMMAND = r'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe'

"""
Disable Cortana by killing the process and renaming Cortana directory in SystemApps
so that RintimeBroker did not start it again
"""


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


class DisableTelemetry:
    """
    Disable Telemetry services, scheduled tasks and traffic to MS Telemetry servers
    """

    def __init__(self):
        """
        Stub init for static analyzer
        """
        pass

    """
    Map human-readable service names to system name.
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

    """
    Scheduler Tasks related to Telemetry
    """
    TASKS = ["\\Microsoft\\Windows\\Application Experience\\Microsoft Compatibility Appraiser",
             "\\Microsoft\\Windows\\Application Experience\\ProgramDataUpdater",
             "\\Microsoft\\Windows\\Application Experience\\StartupAppTask",
             "\\Microsoft\\Windows\\Customer Experience Improvement Program\\Consolidator",
             "\\Microsoft\\Windows\\Customer Experience Improvement Program\\UsbCeip"]

    """
    List of telemetry-relates websites to add to 'hosts' file and disable all traffic on it
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

    """
    We assume hosts located there.
    In future versions of application we will be locating Windows directory to cover all cases.
    """
    HOSTS_FILE = "C:\\Windows\\System32\\drivers\\etc\\hosts"

    @staticmethod
    def read_from_file(services_file):
        """
        :param services_file: File with newline-separated services list
        :return: list of services with stripped newlines and skipped empty strings
        """
        with open(services_file) as f:
            content = f.readlines()
        # remove whitespace characters like `\n` at the end of each line
        return [x.strip() for x in content if x]

    @staticmethod
    def disable_service(service):
        """
        :param service: Human-readable service name to disable, for example "Security Center"
        """
        logger.info('Trying to disable service "{0}"'.format(service))
        system_srv_name = DisableTelemetry.SERVICES[service]
        logger.info('System service name "{0}"'.format(system_srv_name))

        ret = os.system('sc config "{0}" start= disabled'.format(system_srv_name))
        if ret != 0:
            logger.warning("sc config returned error code {0}, in some cases it's okay".format(ret))

        ret = os.system('sc stop "{0}"'.format(system_srv_name))
        if ret != 0:
            logger.warning("sc stop returned error code {0}, in some cases it's okay".format(ret))

    @staticmethod
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

    @staticmethod
    def disable_services(services_list):
        """
        :param services_list: List of Human-readable service names to disable
        """
        for srv in services_list:
            DisableTelemetry.disable_service(srv)

    @staticmethod
    def disable_tasks(tasks_list):
        """
        :param tasks_list: List of tasks in standard Scheduler format
        \\Microsoft\\Windows\\Application Experience\\StartupAppTask
        ""
        :return:
        """
        for task in tasks_list:
            DisableTelemetry.disable_task(task)

    @staticmethod
    def take_file_ownership():
        """
        Take ownership over 'hosts' file, which is necessary to edit it even under Administrator rights
        """
        ret = os.system("takeown.exe /f {0}".format(DisableTelemetry.HOSTS_FILE))
        if ret == 0:
            logger.info("Ownership of '{0}' file has been taken successfully".format(DisableTelemetry.HOSTS_FILE))
        else:
            logger.warning("takeown.exe returned error code {0}, unable to take ownership {1}".format(
                ret, DisableTelemetry.HOSTS_FILE))

    @staticmethod
    def disable_telemetry_traffic():
        """
        Disable all traffic to known MS Telemetry servers
        """
        with open(DisableTelemetry.HOSTS_FILE, "a") as hosts_file:
            hosts_file.write(DisableTelemetry.TELEMETRY_SERVERS)
        logger.info("All traffic to MS Telemetry servers disabled")


class ApplicationsListParser:
    """
    List, parse and uninstall Metro applications
    """

    """List of Windows Metro applications to uninstall (edit it to adjust your preferences)"""
    DEFAULT_REMOVE_UWP = [
        'Microsoft.MicrosoftEdge',
        'Microsoft.Windows.ContentDeliveryManager',
        'Microsoft.Windows.CloudExperienceHost',
        'Microsoft.Win32WebViewHost',
        'Microsoft.XboxGameCallableUI',
        'Microsoft.Windows.SecureAssessmentBrowser',
        'Microsoft.Windows.SecHealthUI',
        'Microsoft.Windows.PeopleExperienceHost',
        'Microsoft.Windows.XGpuEjectDialog',
        'Microsoft.Windows.ParentalControls',
        'Microsoft.Windows.NarratorQuickStart',
        'Microsoft.BioEnrollment',
        'Microsoft.Wallet',
        'Microsoft.WebpImageExtension',
        'Microsoft.XboxSpeechToTextOverlay',
        'Microsoft.Advertising.Xaml',
        'Microsoft.MicrosoftEdgeDevToolsClient',
        'Microsoft.GetHelp',
        'Microsoft.ZuneMusic',
        'Microsoft.ScreenSketch',
        'Microsoft.Appconnector',
        'Microsoft.People',
        'Microsoft.HEIFImageExtension',
        'Microsoft.WebMediaExtensions',
        'Microsoft.Messaging',
        'Microsoft.VP9VideoExtensions',
        'Microsoft.Windows.Photos',
        'Microsoft.XboxIdentityProvider',
        'Microsoft.Windows.Cortana',
        'Microsoft.XboxGameOverlay',
        'Microsoft.MicrosoftStickyNotes',
        'Microsoft.XboxApp',
        'Microsoft.MSPaint',
        'Microsoft.XboxGamingOverlay',
        'Microsoft.WindowsMaps',
        'Microsoft.WindowsSoundRecorder',
        'Microsoft.3DBuilder',
        'Microsoft.WindowsAlarms',
        'microsoft.windowscommunicationsapps',
        'Microsoft.WindowsCalculator',
        'Microsoft.Microsoft3DViewer']

    """
    Position of key and value in PowerShell output
    """
    KEY = 0
    VALUE = 1

    def __init__(self, current_user):
        """
        On creating the object we read and parse all Metro applications
        self.output_cache is used for saving PowerShell output stream
        self.applications_list is a dictionary of {Name:PackageFullName}
        "Name" let you recognize the app and decide whether you want to delete it or leave
        "PackageFullName" is used to uninstalling itself
        """
        self.output_cache = []
        self.applications_list = {}
        self.__read_bloatware_apps(current_user)

    def __push_application(self):
        """
        Auxiliary method to push a pair {ApplicationReadableName:ApplicationFullName}
        to a dictionary
        """
        if len(self.output_cache) == 0:
            return
        self.applications_list[self.output_cache[0]] = self.output_cache[1]
        self.output_cache.clear()

    def __parse_string(self, output):
        """
        Parse a single string from PowerShell output
        Normally it has simple format Key:Value
        We don't need them all only "Name" and "PackageFullName"
        :param output: String in "Key:Value" format
        Empty string means end of a single application properties list
        """
        if output == "":
            self.__push_application()
        string_pair = output.split(':', 2)
        if string_pair[ApplicationsListParser.KEY] == "Name":
            self.output_cache.append(string_pair[ApplicationsListParser.VALUE])
        if string_pair[ApplicationsListParser.KEY] == "PackageFullName":
            self.output_cache.append(string_pair[ApplicationsListParser.VALUE])

    def __read_bloatware_apps(self, current_user):
        """
        Run the PowerShell command
        Get-AppXPackage -User %current_user%
        Input has a format like that:
        Name : Microsoft.Advertising.Xaml
        Publisher : CN=Microsoft Corporation
        Architecture : X86
        Version : 10.1811.1.0
        ...
        We strip /r/n symbols, skip all whitespaces and decode output to UTF-8
        before passing the string to parser
        """
        process = subprocess.Popen([POWERSHELL_COMMAND, '-ExecutionPolicy', 'Unrestricted',
                                    'Get-AppXPackage -User {0}'.format(current_user)],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)

        for line in iter(process.stdout.readline, b''):
            self.__parse_string(line.decode('utf-8').rstrip().replace(" ", ""))
        process.communicate()

    def list_bloatware_apps(self):
        """
        List all Windows Metro applications to choose what to uninstall
        Redirect the output to file so that choose is like a source of
        uninstalling list
        """
        for application_name in self.applications_list.keys():
            print(application_name)

    @staticmethod
    def __uninstall_metro_app(app_readable_name, app_full_name):
        """
        Uninstall single Metro application
        We use a PowerShell command Remove-AppxPackage %app_full_name%
        :param app_readable_name: Human-readable name of the application
        :param app_full_name: Full name of the aplication for PowerShell uninstall command
        """
        subprocess.Popen([POWERSHELL_COMMAND,
                          '-ExecutionPolicy', 'Unrestricted',
                          'Remove-AppxPackage', '"{0}"'.format(app_full_name)],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
        logger.info('Application "{0}" uninstalled'.format(app_readable_name))

    def uninstall_bloatware_apps(self, uninstall_list):
        """
        Uninstall either default or user-defined set of applications
        :param uninstall_list:
        """
        if len(uninstall_list) == 0:
            uninstall_list = ApplicationsListParser.DEFAULT_REMOVE_UWP

        for app_readable_name, app_full_name in self.applications_list.items():
            if app_readable_name in uninstall_list:
                self.__uninstall_metro_app(app_readable_name, app_full_name)

    @staticmethod
    def read_from_file(applications_file):
        """
        :param applications_file: File with newline-separated applications list
        :return: list of services with stripped newlines and skipped empty strings
        """
        with open(applications_file) as f:
            content = f.readlines()
        # remove whitespace characters like `\n` at the end of each line
        return [x.strip() for x in content if x]


def main():
    """
    Uninstall applications based on list, or simply retrieve the list of installed applications
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
    parser.add_argument('--disable-telemetry',
                        help='Stop services and scheduled tasks, providing private data transfer to Microsoft',
                        action='store_true',
                        default="",
                        required=False)
    parser.add_argument('--block-telemetry-traffic',
                        help='Block traffic to all known Microsoft servers, related to telemetry collection',
                        action='store_true',
                        default=False,
                        required=False)
    parser.add_argument('--disable-cortana',
                        help='Disable Cortana from constant consuming system resources. '
                             'Warning! Disabling Cortana may not be reliable function, '
                             'it does not work during updates or other housekeeping. '
                             'In case of access failure try after update finished/reboot/etc',
                        action='store_true',
                        default=False,
                        required=False)
    parser.add_argument('--uninstall-bloatware',
                        help='Uninstall unnecessary UWP Windows Metro applications, coming with the Windows 10.',
                        action='store_true',
                        default=False,
                        required=False)
    parser.add_argument('--list-bloatware',
                        help='List all installed UWP Windows Metro applications, so that you can choose '
                             'what to uninstall and what to leave. If you are not sure, leave the application',
                        action='store_true',
                        default=False,
                        required=False)
    parser.add_argument('--uninstall-from-file',
                        help='Redirecting output from the script with the --list-bloatware key you can create a file'
                             'with the list of applications to uninstall',
                        dest='applications_file',
                        default=False,
                        required=False)

    args = parser.parse_args()
    current_user = getpass.getuser()
    logger.info("Current user %s" % current_user)

    if args.disable_telemetry:
        services_list = default_services
        DisableTelemetry.disable_services(services_list)
        DisableTelemetry.disable_tasks(DisableTelemetry.TASKS)

    if args.block_telemetry_traffic:
        DisableTelemetry.take_file_ownership()
        DisableTelemetry.disable_telemetry_traffic()

    if args.disable_cortana:
        disable_cortana_service()

    if args.uninstall_bloatware:
        parser = ApplicationsListParser(current_user)
        parser.uninstall_bloatware_apps([])

    if args.list_bloatware:
        parser = ApplicationsListParser(current_user)
        parser.list_bloatware_apps()

    if args.applications_file:
        uninstall_from_file = args.applications_file
        logger.info("Reading applications list from file %s" % uninstall_from_file)
        if not os.path.isfile(uninstall_from_file):
            logger.warning("File %s does not exist" % uninstall_from_file)
        parser = ApplicationsListParser(current_user)
        parser.uninstall_bloatware_apps(uninstall_from_file)

    return 0


###########################################################################
if __name__ == '__main__':
    sys.exit(main())
