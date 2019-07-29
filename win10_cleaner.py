import os
import re
import sys
import stat
import shutil
import argparse
import logging
import log_helper


logger = log_helper.setup_logger(name="win10_cleaner", level=logging.DEBUG, log_to_file=True)


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

# Delete bloatware with PS script

# Disable services

# Disable GP (API or registry)

def main():
    """
    Uninstall applications based on list, or simply retrreive the list of installed applications
    :return: System return code
    """
    parser = argparse.ArgumentParser(description='Command-line params')
    parser.add_argument('--home',
                        help='TODO',
                        dest='home',
                        default="",
                        required=False)

    args = parser.parse_args()
    home = args.home

    return 0


###########################################################################
if __name__ == '__main__':
    sys.exit(main())
