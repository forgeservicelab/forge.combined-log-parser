"""
Utilities to transform an Apache log string into a dictionary holding the same information.

At the time only apache combined format is supported.
"""

import re
from ipaddr import IPAddress
from datetime import datetime, timedelta


class NoSuchParserError(Exception):

    """Exception to be thrown when the requested parser is not available."""

    def __init__(self, request=None):
        """Set the error message."""
        self.msg = "The requested parser" + ("[%s]" % request if request else "") + " is not available."

    def __str__(self):
        """Exception string representation."""
        return repr(self.msg)


class Parser(object):

    """Wrapper class over the specific format parsers."""

    COMBINED = 1

    _instance = None

    def __new__(cls, *args, **kwargs):
        """Parser objects should be singletons."""
        if cls is Parser:
            raise TypeError("Parser class may not be instantiated directly")

        if not cls._instance:
            cls._instance = super(Parser, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    @staticmethod
    def create(format):
        """Initialize the requested concrete parser."""
        try:
            return {
                Parser.COMBINED: CombinedParser(),
            }[format]
        except KeyError:
            raise NoSuchParserError(format)

    def _parseTimestamp(self, timestamp):
        naive, offset = timestamp.split()
        naive_ts = datetime.strptime(naive, '%d/%b/%Y:%H:%M:%S')
        offset_ts = int(offset[:-2])*60 + int(offset[-2:])
        hours, minutes = divmod(offset_ts, 60)
        return naive_ts - timedelta(hours=hours, minutes=minutes)

    def parse(self, log):
        """
        Parse a log line and returns a dictionary of strings with its fields.

        Arguments:
            log(str): The log line, in Apache combined format
        Returns:
            dict: A dictionary with the named fields of the log line.
        """
        matches = self.regex.search(log)
        return dict(zip(self.fields, matches.groups()))


class CombinedParser(Parser):

    """Parser for Apache Combined logs."""

    def __init__(self):
        """Initialize the log splitting regular expression."""
        self.regex = re.compile(r'(\S+) (\S+) (\S+) \[(\S+ \S+)\] "(.+)" (\d+) (\d+) "(\S+)" "(.+)"')
        self.fields = [
            'remote_ip',
            'remote_logname',
            'remote_user',
            'timestamp',
            'http_request',
            'response_status',
            'response_size',
            'referer',
            'user_agent'
        ]

    def parse(self, log):
        """
        Parse an apache combined log line and returns a dictionary with its fields.

        Arguments:
            log(str): The log line, in Apache combined format
        Returns:
            dict: A dictionary with the named fields of the log line.
        """
        try:
            logDict = super(CombinedParser, self).parse(log)
        except Exception, e:
            print log
            raise e

        logDict['remote_ip'] = IPAddress(logDict['remote_ip'])
        logDict['timestamp'] = self._parseTimestamp(logDict['timestamp'])
        logDict['response_status'] = int(logDict['response_status'])
        logDict['response_size'] = int(logDict['response_size'])
        return logDict
