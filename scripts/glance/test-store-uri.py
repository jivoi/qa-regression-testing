#!/usr/bin/python

import sys

if len(sys.argv) < 3:
    sys.exit(3)

version = sys.argv[1]
url = sys.argv[2]

if float(version) >= 12.04:
    import glance.common.exception
import glance.store
if float(version) >= 12.10:
    import glance.store.base
import glance.store.location
import glance.store.swift
if float(version) < 12.10:
    import logging
    logging.basicConfig(level=logging.DEBUG)
else:
    import logging
    glance.store.location.LOG.logger.addHandler(logging.StreamHandler(sys.stderr))
    glance.store.location.LOG.logger.setLevel("DEBUG")
    glance.store.swift.LOG.logger.addHandler(logging.StreamHandler(sys.stderr))
    glance.store.swift.LOG.logger.setLevel("DEBUG")

if float(version) >= 12.10:
    glance.store.create_stores()

try:
    obj = glance.store.location.get_location_from_uri(url)
except glance.common.exception.BadStoreUri:
    raise
except:
    raise
    sys.exit(2)

