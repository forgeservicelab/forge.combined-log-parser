"""
Utilities to transform an Apache log string into a dictionary holding the same information.

At the time only apache combined format is supported.
"""

import re
from ipaddr import IPAddress
from datetime import datetime, timedelta, tzinfo


class NoSuchParserError(Exception):

    """Exception to be thrown when the requested parser is not available."""

    def __init__(self, request=None):
        """Set the error message."""
        self.msg = "The requested parser" + ("[%s]" % request if request else "") + " is not available."

    def __str__(self):
        """Exception string representation."""
        return repr(self.msg)


class FixedOffset(tzinfo):

    """Fixed offset in minutes: `time = utc_time + utc_offset`."""

    def __init__(self, offset):
        """Initialize fixed offset."""
        self.__offset = timedelta(minutes=offset)
        hours, minutes = divmod(offset, 60)
        # NOTE: the last part is to remind about deprecated POSIX GMT+h timezones
        #  that have the opposite sign in the name;
        #  the corresponding numeric value is not used e.g., no minutes
        self.__name = '<%+03d%02d>%+d' % (hours, minutes, -hours)

    def utcoffset(self, dt=None):
        """UTC offset getter."""
        return self.__offset

    def tzname(self, dt=None):
        """TimeZone name getter."""
        return self.__name

    def dst(self, dt=None):
        """No info."""
        return timedelta(0)

    def __repr__(self):
        """Offset representation."""
        return 'FixedOffset(%d)' % (self.utcoffset().total_seconds() / 60)


class Parser(object):

    """Wrapper class over the specific format parsers."""

    COMBINED = 1
    BOGUS = 2

    _instance = None

    def __new__(cls, *args, **kwargs):
        """Parser objects should be singletons."""
        if not cls._instance:
            cls._instance = super(Parser, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    @staticmethod
    def create(format):
        """Initialize the requested concrete parser."""
        try:
            return {
                Parser.COMBINED: CombinedParser(),
                Parser.BOGUS: BogusParser()
            }[format]
        except KeyError:
            raise NoSuchParserError(format)

    def _parseTimestamp(self, timestamp):
        naive, offset = timestamp.split()
        naive_ts = datetime.strptime(naive, '%d/%b/%Y:%H:%M:%S')
        offset_ts = int(offset[-4:-2])*60 + int(offset[-2:])
        return naive_ts.replace(tzinfo=FixedOffset(offset_ts))

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
        self.regex = re.compile(r'(\S+) (\S+) (\S+) \[(\S+ \S+)\] "([A-Z]+) (\S+) (\S+)" (\d+) (\d+) "(\S+)" "(.+)"')
        self.fields = [
            'remote_ip',
            'remote_logname',
            'remote_user',
            'timestamp',
            'http_method',
            'request_uri',
            'request_protocol',
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
        logDict = super(CombinedParser, self).parse(log)
        logDict['remote_ip'] = IPAddress(logDict['remote_ip'])
        logDict['timestamp'] = self._parseTimestamp(logDict['timestamp'])
        logDict['response_status'] = int(logDict['response_status'])
        logDict['response_size'] = int(logDict['response_size'])
        return logDict
