#!/usr/bin/env python
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from collections import defaultdict
import hashlib
import random
import sys
import time
import os
from optparse import OptionParser

from swift.common.daemon import run_daemon
from swift.common.storage_policy import POLICIES
from swift.common.utils import parse_options, list_from_csv
from swift.obj.auditor import ObjectAuditor, dump_recon_cache, ratelimit_sleep
from swift import gettext_ as _
from swift.obj.diskfile import DiskFileNotExist, DiskFileDeviceUnavailable
from kinetic_swift.obj.server import DiskFileManager

from kinetic_swift.utils import get_device_host_and_port


class KineticAuditor(ObjectAuditor):

    def __init__(self, *args, **kwargs):
        super(KineticAuditor, self).__init__(*args, **kwargs)
        self.reset_stats()
        self.mgr = DiskFileManager(self.conf, self.logger)
        self.swift_dir = self.conf.get('swift_dir', '/etc/swift')
        self.max_files_per_second = float(
            self.conf.get('files_per_second', 20))
        self.max_bytes_per_second = float(
            self.conf.get('bytes_per_second', 10000000))
        self.interval = 30

    def reset_stats(self):
        self.stats = defaultdict(int)
        self.bytes_running_time = 0
        self.bytes_processed = 0
        self.total_bytes_processed = 0
        self.total_files_processed = 0
        self.passes = 0
        self.quarantines = 0
        self.errors = 0

    def run_forever(self, *args, **kwargs):
        """Run the auditor continuously."""
        time.sleep(random.random() * self.interval)
        while True:
            begin = time.time()
            self.logger.info(_('Begin object audit sweep'))
            self.run_once(*args, **kwargs)
            elapsed = time.time() - begin
            self.logger.info(_('Object audit sweep completed: %.02fs'),
                             elapsed)
            dump_recon_cache({'object_audit_sweep': elapsed},
                             self.rcache, self.logger)
            if elapsed < self.interval:
                time.sleep(self.interval - elapsed)
            self.reset_stats()

    def _get_devices(self):
        return set([
            d['device'] for policy in POLICIES for d in
            POLICIES.get_object_ring(int(policy), self.swift_dir).devs
            if d
        ])

    def _find_objects(self, device):
        conn = self.mgr.get_connection(*get_device_host_and_port(device))
        start_key = 'objects'
        end_key = 'objects/'
        for head_key in conn.iterKeyRange(start_key, end_key):
            yield head_key

    def _audit_object(self, device, head_key):
        df = self.mgr.get_diskfile_from_audit_location(
            device, head_key)
        try:
            f = df.open()
        except DiskFileNotExist:
            self.logger.debug(
                'object %r does not exist', head_key)
        else:
            etag = hashlib.md5()
            size = 0
            with f:
                metadata = df.get_metadata()
                for chunk in df:
                    chunk_len = len(chunk)
                    etag.update(chunk)
                    size += chunk_len
                    self.bytes_running_time = ratelimit_sleep(
                        self.bytes_running_time,
                        self.max_bytes_per_second,
                        incr_by=chunk_len)
                    self.bytes_processed += chunk_len
                    self.total_bytes_processed += chunk_len
                if size != int(metadata.get('Content-Length')):
                    self.logger.warning(
                        'found object %r with size %r instead of %r',
                        head_key, size, metadata.get('Content-Length'))
                    df.quarantine()
                    return False
                got_etag = etag.hexdigest()
                expected_etag = metadata.get('ETag')
                if got_etag != expected_etag:
                    self.logger.warning(
                        'found object %r with etag %r instead of %r',
                        head_key, got_etag, expected_etag)
                    df.quarantine()
                    return False
        return True

    def audit_object(self, device, location):
        success = False
        try:
            success = self._audit_object(device, location)
        except Exception:
            self.logger.exception('Unhandled exception in audit of %s/%s',
                                  device, location)
        return success

    def _audit_device(self, device):
        for location in self._find_objects(device):
            self.stats['found_objects'] += 1
            success = self.audit_object(device, location)
            if success:
                self.stats['success'] += 1
            else:
                self.stats['failures'] += 1

    def audit_device(self, device):
        success = False
        try:
            self._audit_device(device)
        except DiskFileDeviceUnavailable:
            self.logger.warning('Unable to connect to %s', device)
        except Exception:
            self.logger.exception('Unhandled exception while auditing %s',
                                  device)
        else:
            success = True
        if success:
            self.stats['device.success'] += 1
        else:
            self.stats['device.failures'] += 1

    def run_once(self, *args, **kwargs):
        self.reset_stats()
        override_devices = list_from_csv(kwargs.get('devices'))
        devices = override_devices or self._get_devices()
        self.logger.info('Starting sweep of %r', devices)
        start = time.time()
        for device in devices:
            self.audit_device(device)
        self.logger.info('Finished sweep of %r (%ds) => %r', devices,
                         time.time() - start, self.stats)


def main():
    try:
        if not os.path.exists(sys.argv[1]):
            sys.argv.insert(1, '/etc/swift/kinetic.conf')
    except IndexError:
        pass
    parser = OptionParser("%prog CONFIG [options]")
    parser.add_option('-d', '--devices',
                      help='Audit only given devices. '
                           'Comma-separated list')
    conf_file, options = parse_options(parser, once=True)
    run_daemon(KineticAuditor, conf_file,
               section_name='object-auditor', **options)


if __name__ == "__main__":
    sys.exit(main())
