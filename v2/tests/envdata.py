
import logging
import os

from dataclasses import dataclass
from typing import Optional
from datetime import datetime

@dataclass
class EnvData():
    test_case_name: str
    test_root: str
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

    def __init__(self, test_case_name: str, logger: logging.Logger, command_logger: logging.Logger, base_dir: Optional[str] = None):
        self.test_case_name = test_case_name
        self.test_root = os.path.abspath(os.fspath(base_dir)) if base_dir else "/tmp/unit-test"
        self.test_dir = os.path.join(self.test_root, test_case_name.lower())
        self.backup_dir = os.path.join(self.test_dir, "backups")
        self.backup_d_dir = os.path.join(self.test_dir, "backup.d")
        self.restore_dir = os.path.join(self.test_dir, "restore")
        self.data_dir = os.path.join(self.test_dir, "data")
        self.template_config_file = os.path.abspath(os.path.join(os.path.dirname(__file__),"../template/dar-backup.conf.template"))
        self.config_file = os.path.join(self.test_dir, "dar-backup.conf")
        self.template_dar_rc = os.path.abspath(os.path.join(os.path.dirname(__file__), "../template/.darrc"))
        self.dar_rc = os.path.join(self.test_dir, ".darrc")
        self.log_file = os.path.join(self.test_root, "test.log")
        self.datestamp = datetime.now().strftime('%Y-%m-%d')
        self.logger = logger
        self.command_logger = command_logger
