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

from random import shuffle

from swift import gettext_ as _
from swift.container.sync import ic_conf_body
from swift.common.wsgi import ConfigString
from swift.common.internal_client import InternalClient


def get_internal_client(conf, title, logger, default_retries=3):
    request_tries = int(conf.get('request_tries') or default_retries)
    internal_client_conf_path = conf.get('internal_client_conf_path')
    if not internal_client_conf_path:
        logger.warning(
            _('Configuration option internal_client_conf_path not '
              'defined. Using default configuration, See '
              'internal-client.conf-sample for options'))
        internal_client_conf = ConfigString(ic_conf_body)
    else:
        internal_client_conf = internal_client_conf_path
    try:
        client = InternalClient(
            internal_client_conf, title, request_tries)
    except IOError as err:
        if err.errno != errno.ENOENT:
            raise
        raise SystemExit(
            _('Unable to load internal client from config: %r (%s)') %
            (internal_client_conf_path, err))
    return client


def key_range_markers(marker):
    """
    So we only use '.' to separate "paths" in or key names, that means that
    any key under a "path" starting with "foo" would be after "foo." and
    before "foo/" because chr(ord('.') + 1) == '/'.

    :param marker: the first segment of the key space

    :returns: a tuple, (start_key, end_key)
    """
    return tuple(marker + m for m in ('.', '/'))

def get_device_host_and_port(device):
    """
    This function can take host and port from Swift ring if we'll
    add all kinetic disk intefaces (comma separated),
    as soon as kinatic disk have two 1Gbps intarfaces

    :param device: host:port[,host:port]
    :return:
    """
    interfaces = device.split(",")
    shuffle(interfaces)

    return interfaces[0].split(":")