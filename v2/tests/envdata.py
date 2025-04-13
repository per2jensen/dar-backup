
import logging
import os

from dataclasses import dataclass
from datetime import datetime
from dar_backup.util import setup_logging

@dataclass
class EnvData():
    test_case_name: str
    test_dir: str
    backup_dir: str
    backup_d_dir: str
    data_dir: str
    restore_dir: str
    template_config_file: str
    config_file: str
    template_dar_rc: str
    dar_rc: str
    log_file: str
    datestamp: str
    logger: logging.Logger
    command_logger: logging.Logger

    def __init__(self, test_case_name: str, logger: logging.Logger, command_logger: logging.Logger):
        self.test_case_name = test_case_name
        self.test_dir = f"/tmp/unit-test/{test_case_name.lower()}"
        self.backup_dir = os.path.join(self.test_dir, "backups")
        self.backup_d_dir = os.path.join(self.test_dir, "backup.d")
        self.restore_dir = os.path.join(self.test_dir, "restore")
        self.data_dir = os.path.join(self.test_dir, "data")
        self.template_config_file = os.path.abspath(os.path.join(os.path.dirname(__file__),"../template/dar-backup.conf.template"))
        self.config_file = os.path.join(self.test_dir, "dar-backup.conf")
        self.template_dar_rc = os.path.abspath(os.path.join(os.path.dirname(__file__), "../template/.darrc"))
        self.dar_rc = os.path.join(self.test_dir, ".darrc")
        self.log_file = "/tmp/unit-test/test.log"
        self.datestamp = datetime.now().strftime('%Y-%m-%d')
        self.logger = logger
        self.command_logger = command_logger
