import json
import os
import logging
import sys
import logging.handlers
from logging import Logger


class LoggingBase(Logger):
    def __init__(self, name='Lil Pwny'):
        super().__init__(name)
        self.notify_format = logging.Formatter(
            '{"localtime": "%(asctime)s", "level": "NOTIFY", "source": "%(name)s", "match_type": "%(type)s", '
            '"detection_data": %(message)s}')
        self.info_format = logging.Formatter(
            '{"localtime": "%(asctime)s", "level": "%(levelname)s", "source": "%(name)s", "message":'
            ' "%(message)s"}')
        self.log_path = ''
        self.logger = logging.getLogger(self.name)
        self.logger.setLevel(logging.DEBUG)


class FileLogger(LoggingBase):
    def __init__(self, log_path):
        LoggingBase.__init__(self)
        self.handler = logging.handlers.WatchedFileHandler(os.path.join(log_path, 'lil-pwny.log'))
        self.logger.addHandler(self.handler)

    def log_notification(self, log_data, match_type):
        self.handler.setFormatter(self.notify_format)
        self.logger.warning(json.dumps(log_data), extra={
            'type': match_type
        })

    def log_info(self, log_data):
        self.handler.setFormatter(self.info_format)
        self.logger.info(log_data)

    def log_critical(self, log_data):
        self.handler.setFormatter(self.info_format)
        self.logger.critical(log_data)


class StdoutLogger(LoggingBase):
    def __init__(self):
        LoggingBase.__init__(self)
        self.handler = logging.StreamHandler(sys.stdout)
        self.logger.addHandler(self.handler)

    def log_notification(self, log_data, match_type):
        self.handler.setFormatter(self.notify_format)
        self.logger.warning(json.dumps(log_data), extra={
            'type': match_type
        })

    def log_info(self, log_data):
        self.handler.setFormatter(self.info_format)
        self.logger.info(log_data)

    def log_critical(self, log_data):
        self.handler.setFormatter(self.info_format)
        self.logger.critical(log_data)

