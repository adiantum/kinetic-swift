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

import errno
from optparse import OptionParser
import os
import socket
import sys
import time
import struct

import msgpack

from swift.common.utils import parse_options, split_path, Timestamp
from swift.common.daemon import run_daemon
from swift.common.direct_client import direct_put_object
from swift.obj.replicator import ObjectReplicator
from swift import gettext_ as _
from swift.common.storage_policy import (
    POLICIES, EC_POLICY, get_policy_string, split_policy_string)

from kinetic_swift.client import KineticSwiftClient
from kinetic_swift.utils import get_internal_client, key_range_markers
from kinetic_swift.obj.server import (object_key, diskfile,
                                      install_kinetic_diskfile, temp_key)

from kinetic_swift.utils import get_device_host_and_port


CLENAUP_ABORT_UPLOAD_SECONDS = 28800


def _cleanup_old_chunks(conn, policy):
    """
    Look for old temp markers and remove orphaned chunks.
    """
    temp_range = key_range_markers(diskfile.get_tmp_dir(policy))
    for temp_marker in conn.iterKeyRange(*temp_range):
        # tmp.<hash>.<nonce>.<time>.<stamp>
        parts = temp_marker.split('.')
        timeout = float('.'.join(parts[3:5])) + CLENAUP_ABORT_UPLOAD_SECONDS
        if time.time() < timeout:
            continue
        # see if a head key exists for this nonce
        hash_range = key_range_markers('%s.%s' % (
            diskfile.get_data_dir(policy), parts[1]))
        for key in conn.iterKeyRange(*hash_range):
            if split_key(key)['nonce'] == parts[2]:
                break
        else:
            # did not find matching head key
            chunk_marker = 'chunks.{1}.{2}'.format(*parts)
            chunk_range = key_range_markers(chunk_marker)
            conn.delete_keys(conn.iterKeyRange(*chunk_range))
        conn.delete(temp_marker, force=True).wait()


def split_key(key):
    parts = key.split('.')
    base, policy = split_policy_string(parts[0])
    if base != 'objects':
        return False
    hashpath = parts[1]
    timestamp = '.'.join(parts[2:4])
    ext = parts[4]
    nonce_parts = parts[-1].split('-')
    nonce = '-'.join(nonce_parts[:5])
    if len(nonce_parts) > 5:
        frag_index = int(nonce_parts[5])
    else:
        frag_index = None
    return {
        'policy': policy,
        'hashpath': hashpath,
        'ext': ext,
        'nonce': nonce,
        'frag_index': frag_index,
        'timestamp': timestamp,
    }


class KineticReplicator(ObjectReplicator):

    def __init__(self, conf):
        install_kinetic_diskfile()
        super(KineticReplicator, self).__init__(conf)
        self.replication_mode = conf.get('kinetic_replication_mode', 'push')
        self.connect_timeout = int(conf.get('connect_timeout', 3))
        self.response_timeout = int(conf.get('response_timeout', 30))
        # device => [last_used, conn]
        self._conn_pool = {}
        self.max_connections = int(conf.get('max_connections', 10))
        self.swift = get_internal_client(conf, 'Kinetic Object Rebuilder',
                                         self.logger)

    def iter_all_objects(self, conn, policy):
        prefix = get_policy_string('objects', policy)
        key_range = [prefix + term for term in ('.', '/')]
        last_key, last_key_info = None, {}
        for key in conn.iterKeyRange(*key_range, reverse=True):
            key_info = split_key(key)
            if key_info['ext'] == 'ts' and Timestamp(
                    key_info['timestamp']) < (
                        time.time() - self.reclaim_age):
                self.logger.debug('reclaiming tombstone %r' % key)
                conn.delete(key, force=True).wait()
                continue
            if not last_key:
                last_key, last_key_info = key, key_info
                continue
            if last_key_info['hashpath'] == key_info['hashpath']:
                # this next key is better, we should clean up the old one!
                last_key_info['timestamp'] = '0'
                temp_marker = temp_key(**last_key_info)
                conn.put(temp_marker, '', force=True).wait()
                conn.delete(last_key, force=True).wait()
            else:
                yield last_key
                last_key, last_key_info = key, key_info
        yield last_key

    def find_target_devices(self, key, policy):
        key_info = split_key(key)
        # ring magic, find all of the nodes for the partion of the given hash
        raw_digest = key_info['hashpath'].decode('hex')
        part = struct.unpack_from('>I', raw_digest)[0] >> \
            policy.object_ring._part_shift
        return policy.object_ring.get_part_nodes(part)

    def build_job(self, device, key, policy):
        key_info = split_key(key)
        # ring magic, find all of the nodes for the partion of the given hash
        raw_digest = key_info['hashpath'].decode('hex')
        part = struct.unpack_from('>I', raw_digest)[0] >> \
            policy.object_ring._part_shift
        nodes = policy.object_ring.get_part_nodes(part)
        # filter current device from nodes if primary
        targets = [n for n in nodes if n['device'] != device]
        if policy.policy_type == EC_POLICY:
            if nodes[key_info['frag_index']]['device'] == device:
                # this is the primary device for this frag_index
                delete = False
            else:
                delete = True
                targets = [n for n in targets
                           if n['index'] == key_info['frag_index']]
        else:
            if nodes == targets:
                # the targets for this key do not include our device
                delete = True
            else:
                # this node is a primary for this part
                delete = False
        job = {
            'device': device,
            'key': key,
            'key_info': key_info,
            'part': part,
            'policy': policy,
            'frag_index': key_info['frag_index'],
            'targets': targets,
            'delete': delete,
        }
        return job

    def iter_object_keys(self, conn, key):
        yield key
        key_info = split_key(key)
        chunk_key = 'chunks.%(hashpath)s.%(nonce)s' % key_info
        for key in conn.iterKeyRange(chunk_key + '.', chunk_key + '/'):
            yield key

    def replicate_object_to_target(self, conn, keys, target):
        device = target['device']
        if self.replication_mode == 'push':
            conn.push_keys(device, keys)
        else:
            conn.copy_keys(device, keys)

    def is_object_on_target(self, target, key):
        # get key ready for getPrevious on target
        key_info = split_key(key)
        key = object_key(key_info['policy'], key_info['hashpath'])

        conn = self.get_conn(target['device'])
        entry = conn.getPrevious(key).wait()
        if not entry:
            return False
        target_key_info = split_key(entry.key)
        if not target_key_info:
            return False
        if target_key_info['hashpath'] != key_info['hashpath']:
            return False
        if target_key_info['timestamp'] < key_info['timestamp']:
            return False
        if (target_key_info['frag_index'] is not None and
                target_key_info['frag_index'] != target.get('index')):
            return False
        return True

    def get_conn(self, device):
        now = time.time()
        try:
            pool_entry = self._conn_pool[device]
        except KeyError:
            self.logger.debug('Creating new connection to %r', device)
            self._close_old_connections()
            conn = self._get_conn(device)
        else:
            conn = pool_entry[1]
        if conn.faulted or not conn.isConnected:
            conn.reconnect()
        self._conn_pool[device] = (now, conn)
        return conn

    def _close_old_connections(self):
        oldest_keys = sorted(self._conn_pool, key=lambda k:
                             self._conn_pool[k][0])
        while len(self._conn_pool) > self.max_connections:
            device = oldest_keys.pop(0)
            pool_entry = self._conn_pool.pop(device)
            last_used, conn = pool_entry
            self.logger.debug('Closing old connection to %r (%s)', device,
                              time.time() - last_used)
            conn.close()

    def _get_conn(self, device):
        host, port = get_device_host_and_port(device)
        conn = KineticSwiftClient(
            self.logger, host, int(port),
            connect_timeout=self.connect_timeout,
            response_timeout=self.response_timeout,
        )
        return conn

    def reconstruct_fa(self, conn, target, job):
        """
        Use internal client to rebuild the object data needed to reconstruct
        the fragment archive that is missing on the target node.

        :param conn: a KineticClient connection to the device which has the
                      object metadata for the fragment archive we're rebuilding
        :param target: the ring node which is missing the fragment archive
        :param job: the job dict
        """
        key_info = split_key(job['key'])
        # get object info from conn
        resp = conn.get(job['key'])
        entry = resp.wait()
        info = msgpack.unpackb(entry.value)
        # internal client GET
        account, container, obj = split_path(
            info['name'], 3, rest_with_last=True)
        status, headers, body_iter = self.swift.get_object(
            account, container, obj, {})
        if status // 100 != 2:
            return False
        if headers['x-timestamp'] != key_info['timestamp']:
            return False
        for header in ('etag', 'content-length'):
            headers.pop(header, None)
        headers.update({
            'X-Object-Sysmeta-Ec-Frag-Index': target['index'],
            'X-Backend-Storage-Policy-Index': int(job['policy']),
        })

        # make ec_frag body iter
        def make_segment_iter(segment_size):
            segment_buff = ''
            for chunk in body_iter:
                if not chunk:
                    break
                segment_buff += chunk
                if len(segment_buff) >= segment_size:
                    yield segment_buff[:segment_size]
                    segment_buff = segment_buff[segment_size:]
            if segment_buff:
                yield segment_buff

        def make_frag_iter(policy, frag_index):
            for segment in make_segment_iter(policy.ec_segment_size):
                yield policy.pyeclib_driver.encode(segment)[frag_index]
        # direct client PUT
        direct_put_object(target, job['part'], account, container, obj,
                          make_frag_iter(job['policy'], target['index']),
                          headers=headers)

    def replicate_object(self, conn, job):
        keys = None
        success = 0
        for target in job['targets']:
            try:
                if self.is_object_on_target(target, job['key']):
                    success += 1
                    continue
                if (job['policy'].policy_type == EC_POLICY
                        and not job['delete']):
                    if not self.reconstruct_fa(conn, target, job):
                        continue
                else:
                    keys = keys or list(self.iter_object_keys(
                        conn, job['key']))
                    self.replicate_object_to_target(conn, keys, target)
            except Exception:
                self.logger.exception('Unable to replicate %r to %r',
                                      job['key'], target['device'])
            else:
                self.logger.info('Successfully replicated %r to %r',
                                 job['key'], target['device'])
                success += 1
        if job['delete'] and success >= len(job['targets']):
            # might be nice to drop the whole partition at once
            keys = keys or list(self.iter_object_keys(conn, job['key']))
            conn.delete_keys(keys)
            self.logger.info(
                'successfully removed handoff %(key)r to %(device)r', job)

    def replicate_device(self, device, conn, policy):
        self.logger.info('begining replication pass for %r', device)
        for key in self.iter_all_objects(conn, policy):
            job = self.build_job(device, key, policy)
            # refresh conn
            conn = self.get_conn(device)
            self.replicate_object(conn, job)
        _cleanup_old_chunks(conn, policy)

    def _replicate(self, *devices, **kwargs):
        policy = kwargs.get('policy', POLICIES.legacy)
        for device in devices:
            try:
                # might be a good place to go multiprocess
                try:
                    conn = self.get_conn(device)
                except:
                    self.logger.exception(
                        'Unable to connect to device: %r', device)
                    continue
                try:
                    self.replicate_device(device, conn, policy)
                except socket.error as e:
                    if e.errno != errno.ECONNREFUSED:
                        raise
                    self.logger.error('Connection refused for %r', device)
            except Exception:
                self.logger.exception('Unhandled exception with '
                                      'replication for device %r', device)

    def replicate(self, override_devices=None, **kwargs):
        self.start = time.time()
        self.suffix_count = 0
        self.suffix_sync = 0
        self.suffix_hash = 0
        self.replication_count = 0
        self.last_replication_count = -1
        self.partition_times = []
        for policy in POLICIES:
            obj_ring = self.load_object_ring(policy)
            devices = override_devices or [d['device'] for d in
                                           obj_ring.devs if d]
            self.logger.debug(_("Begin replication for %r"), policy)
            try:
                self._replicate(*devices, policy=policy)
            except Exception:
                self.logger.exception(
                    _("Exception in top-level replication loop"))
            self.logger.info('replication cycle for %r complete', devices)


def main():
    try:
        if not os.path.exists(sys.argv[1]):
            sys.argv.insert(1, '/etc/swift/kinetic.conf')
    except IndexError:
        pass
    parser = OptionParser("%prog CONFIG [options]")
    parser.add_option('-d', '--devices',
                      help='Replicate only given devices. '
                           'Comma-separated list')
    conf_file, options = parse_options(parser, once=True)
    run_daemon(KineticReplicator, conf_file,
               section_name='object-replicator', **options)


if __name__ == "__main__":
    sys.exit(main())
