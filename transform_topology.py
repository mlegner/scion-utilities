#!/usr/bin/python3
# Copyright 2014 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import os
import glob
import json
import functools

from lib.packet.scion_addr import ISD_AS
from lib.topology import Topology
from lib.defines import SERVICE_TYPES


ScionLabInfrastructureASOffsetAddr=0xFFAA00000000
ScionlabUserASOffsetAddr=0xFFAA00010000


def isUserAS(ASID):
    return ASID > 1000

def map_ISD(old_isd):
    if old_isd == 42:
        return 16
    elif old_isd >= 20 and old_isd <= 21:
        return old_isd - 20 + 60
    else:
        return old_isd + 16

def map_ASID(old_asid):
    if isUserAS(old_asid):
        # user ASes
        offset = ScionlabUserASOffsetAddr - 1000
    else:
        # infrastructure AS
        offset = ScionLabInfrastructureASOffsetAddr
    return old_asid + offset

@functools.lru_cache(maxsize=None)
def map_id(old_ia):
    """
    Returns the new IA
    :param old_ia ISD_AS is an IA prior to address standardization
    Examples: 
    1-1001  -> 17-ffaa:1:1
    1-11    -> 17-ffaa:0:1101
    2-22    -> 18-ffaa:0:1202
    42-1    -> 16-ffaa:0:1001
    """
    ia = ISD_AS(old_ia)
    I = ia[0]
    A = ia[1]
    userAS = isUserAS(A)
    if not userAS and I != 42:
        A -= I * 10
        if A > 15:
            A = 10 + A % 10
    I = map_ISD(I)
    A = map_ASID(A)
    if not userAS:
        A += I * 256
    return ISD_AS.from_values(I, A)


def rename_key_everywhere(topo_thing, old_keyname, new_keyname):
    if isinstance(topo_thing, dict):
        for k, v in topo_thing.items():
            if k == old_keyname:
                topo_thing[new_keyname] = topo_thing.pop(old_keyname)
            rename_key_everywhere(v, old_keyname, new_keyname)
    elif not isinstance(topo_thing, str):
        try:
            it = iter(topo_thing)
        except:
            return
        for thing in it:
            rename_key_everywhere(it, old_keyname, new_keyname)


class FullTopo:
    """
    Class manipulating one or more whole SCIONLab ISDs certs, topos, etc.
    """
    def __init__(self, gen_dir):
        self._isds = {}
        if not os.path.exists(gen_dir) or not os.path.isdir(gen_dir):
            raise Exception('%s doesn\'t look to be a directory' % gen_dir)
        contents = glob.glob(os.path.join(gen_dir, 'ISD*'))
        for isd_path in contents:
            isd = os.path.basename(isd_path)[3:]
            isd = int(isd)
            self._isds[isd] = self.get_isd_from_path(isd_path)
    
    @classmethod
    def get_isd_from_path(cls, isd_path):
        contents = glob.glob(os.path.join(isd_path, 'AS*'))
        isd = {}
        for as_path in contents:
            AS = os.path.basename(as_path)[2:]
            isd[AS] = cls.get_as_from_path(as_path)
        return isd

    @classmethod
    def get_as_from_path(cls, as_path):
        # print(as_path)
        contents = glob.glob(os.path.join(as_path, 'cs*'))
        if len(contents) != 1:
            raise Exception('Expected to find 1 entry cs* in %s but found %d' % (as_path, len(contents)))
        topo_file = os.path.join(contents[0], 'topology.json')
        contents = glob.glob(topo_file)
        if len(contents) != 1:
            raise Exception('Expected to find 1 topology.json file in %s but found %d' % (topo_file, len(contents)))
        with open(topo_file) as f:
            topo_dict = dict(json.load(f))
        # rename_key_everywhere(topo_dict, 'Core', 'NNNNNN')
        rename_key_everywhere(topo_dict, 'LinkType', 'LinkTo')
        try:
            t = Topology.from_dict(topo_dict)
        except Exception:
            print('Exception parsing topology for path %s' % topo_file)
            raise
        return t

    def remap_all(self):
        for k, v in self._isds.items():
            self._isds[map_ISD(k)] = self.remap_isd(self._isds.pop(k))

    @classmethod
    def remap_isd(cls, ases):
        # map topologies
        for AS, topo in ases.items():
            print('mapping ', AS)
            cls.remap_topology(topo)
        # regenerate core AS certs
        # regenerate TRC
        # regenerate non core AS certs
        return ases

    @classmethod
    def remap_topology(cls, topo):
        topo.isd_as = map_id(str(topo.isd_as))
        for serv in (*topo.beacon_servers, *topo.certificate_servers, *topo.path_servers, *topo.sibra_servers, *topo.border_routers):
            serv.name = cls.remap_service_name(serv.name)
        # BRs contain references to other IAs
        for br in topo.border_routers:
            for k, v in br.interfaces.items():
                v.isd_as = map_id(str(v.isd_as))

    @classmethod
    def remap_service_name(cls, serv_name):
        first, middle, last = serv_name.split('-')
        middle = first[2:] + '-' + middle
        first = first[:2]
        newid = map_id(middle)
        return '%s%s-%s' %(first, newid.file_fmt(), last)
    


def test_preconditions():
    def do_test(oldvalue, expected):
        actual = str(map_id(oldvalue))
        if actual != expected:
            raise Exception('Mapping IDs failure: %s != %s' % (actual, expected))
    do_test('1-11',   '17-ffaa:0:1101')
    do_test('1-102',  '17-ffaa:0:110c')
    do_test('42-1',   '16-ffaa:0:1001')
    do_test('20-201', '60-ffaa:0:3c01')
    

def main():
    test_preconditions()
    parser = argparse.ArgumentParser()
    parser.add_argument('gen', help='Gen folder to apply the transformation')
    parser.add_argument('-d', '--dry', help='Dry run. Don\'t make changes')
    args = parser.parse_args()
    
    ft = FullTopo(args.gen)
    ft.remap_all()

if __name__ == "__main__":
    main()

