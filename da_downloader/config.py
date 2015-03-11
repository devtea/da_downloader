'''
config.py
Module to handle YAML config loading and validation.
'''
from __future__ import division, absolute_import, print_function, unicode_literals

import errno
import os

import yaml

import logger

log = logger.getLogger()


def getConfig(file):
    '''Parses given file and returns a config dictionary'''
    log.debug('Config File: %s' % file)
    try:
        with open(file) as c:
            config = yaml.safe_load(c)
    except IOError as e:
        if e.errno == errno.ENOENT:  # Doesn't Exist
            log.error('Config file not found')
            return None
        elif e.errno == errno.EACCES:  # Access Denied
            log.error('Cannot access config file')
            return None
        elif e.errno == errno.EISDIR:  # Is directory
            log.error('Config is a directory')
            return None
        else:
            raise
    except yaml.scanner.ScannerError:  # bad yaml
            log.error('Malformed YAML')
            return None
    log.debug('Config values: %s' % config)
    return validate(config)


def validate(config):
    #TODO run through RX for structural validation
    return config


if __name__ == '__main__':
    print(__doc__)
