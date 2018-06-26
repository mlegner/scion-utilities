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
import base64

from lib.util import (
    load_json_file,
    read_file
)
from lib.packet.scion_addr import ISD_AS
from lib.topology import Topology
from lib.defines import SERVICE_TYPES
from lib.crypto.certificate import (Certificate, 
    SUBJECT_STRING,
    ISSUER_STRING,
    TRC_VERSION_STRING,
    VERSION_STRING,
    COMMENT_STRING,
    CAN_ISSUE_STRING,
    ISSUING_TIME_STRING,
    EXPIRATION_TIME_STRING,
    ENC_ALGORITHM_STRING,
    SUBJECT_ENC_KEY_STRING,
    SIGN_ALGORITHM_STRING,
    SUBJECT_SIG_KEY_STRING,
    SIGNATURE_STRING,
)


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



def remap_topology(topo):
    topo.isd_as = map_id(str(topo.isd_as))
    for serv in (*topo.beacon_servers, *topo.certificate_servers, *topo.path_servers, *topo.sibra_servers, *topo.border_routers):
        serv.name = remap_service_name(serv.name)
    # BRs contain references to other IAs
    for br in topo.border_routers:
        for k, v in br.interfaces.items():
            v.isd_as = map_id(str(v.isd_as))

def remap_service_name(serv_name):
    first, middle, last = serv_name.split('-')
    middle = first[2:] + '-' + middle
    first = first[:2]
    newid = map_id(middle)
    return '%s%s-%s' %(first, newid.file_fmt(), last)

# -------------------------------- Topology classes

class ASTopology(Topology):
    @classmethod
    def from_directory(cls, as_path):
        contents = glob.glob(os.path.join(as_path, 'cs*'))
        if len(contents) != 1:
            raise Exception('Expected to find 1 entry cs* in %s but found %d' % (as_path, len(contents)))
        topo_file = os.path.join(contents[0], 'topology.json')
        contents = glob.glob(topo_file)
        if len(contents) != 1:
            raise Exception('Expected to find 1 topology.json file in %s but found %d' % (topo_file, len(contents)))
        return cls.from_file(topo_file)

    @classmethod
    def from_file(cls, topo_file):
        topo_dict = load_json_file(topo_file)
        rename_key_everywhere(topo_dict, 'LinkType', 'LinkTo')
        t = cls.from_dict(topo_dict)
        # now keys:
        t.keys = {}
        p = os.path.join(os.path.dirname(topo_file), 'keys')
        if t.is_core_as:
            t.keys['online'] = base64.b64decode(read_file(os.path.join(p, 'online-root.seed')))
            t.keys['offline'] = base64.b64decode(read_file(os.path.join(p, 'offline-root.seed')))
            t.keys['core'] = base64.b64decode(read_file(os.path.join(p, 'core-sig.seed')))
        t.keys['sign'] = base64.b64decode(read_file(os.path.join(p, 'as-sig.seed')))
        t.keys['decrypt'] = base64.b64decode(read_file(os.path.join(p, 'as-decrypt.key')))
        p = os.path.join(os.path.dirname(topo_file), 'certs')
        contents = glob.glob(os.path.join(p, '*.crt'))
        if len(contents) != 1:
            raise Exception('Wrong number of entries in %s for *crt: Expect 1 but got %d' % (p, len(contents)))
        contents = read_file(contents[0])
        certs = json.loads(contents)
        if len(certs) != 2:
            print(certs)
            raise Exception('Certificates must contain a chain of 2 elements; this one has %d elements' % len(certs) )
        t.certs = {'as': certs['0'], 'core': certs['1']}
        return t

    def get_keys(self):
        return self.keys

    def ia_str(self):
        return str(self.isd_as)

    def as_id(self):
        return self.isd_as[1]

    def remap_topology(self):
        remap_topology(self)

    def reissue_core_cert(self):
        if not self.is_core_as:
            return
        sign_priv = self.get_keys()['online']
        c = Certificate(self.certs['core'])
        setattr(c, Certificate.FIELDS_MAP[SUBJECT_STRING][0], self.ia_str())
        setattr(c, Certificate.FIELDS_MAP[ISSUER_STRING][0], self.ia_str())
        c.sign(sign_priv) # self signed
        self.certs['core'] = c
        
    def reissue_cert(self, core_ases):
        issuer = list(core_ases.values())[0]
        sign_priv = issuer.keys['core']
        print(sign_priv)
        c = Certificate(self.certs['as'])
        print('-------------------------------------')
        print(c)
        setattr(c, Certificate.FIELDS_MAP[SUBJECT_STRING][0], self.ia_str())
        setattr(c, Certificate.FIELDS_MAP[ISSUER_STRING][0], issuer.ia_str())
        c.sign(sign_priv)
        print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
        print(c)
        self.certs['as'] = c

class ISD(object):
    def __init__(self, isdId = None):
        self._internal = dict()
        self.isd_id = isdId
        self.core_ases = []
    def __getitem__(self, key):
        return self._internal[key]
    def __setitem__(self, key, value):
        self._internal[key] = value
    def items(self):
        return self._internal.items()

    @classmethod
    def load_from_path(cls, isd_path):
        isdId = os.path.basename(isd_path)[3:]
        isdId = int(isdId)
        isd = cls(isdId)
        contents = glob.glob(os.path.join(isd_path, 'AS*'))
        for as_path in contents:
            a = ASTopology.from_directory(as_path)
            if a.is_core_as:
                isd.core_ases.append(a.as_id())
            isd._internal[a.isd_as[1]] = a
        return isd

    def remap_isd(self):
        mappings = {}
        # map topologies
        for AS, topo in self._internal.items():
            # print('mapping ', AS)
            old_id = topo.as_id()
            # print('OLD:', old_id)
            topo.remap_topology()
            mappings[old_id] = topo.as_id()
            # print('NEW:', topo.as_id())
        print(mappings)
        for k, v in mappings.items():
            self._internal[v] = self._internal.pop(k)
        self.core_ases = [mappings[x] if x in mappings.keys() else x for x in self.core_ases]
        core_topos = {k:self._internal[k] for k in self.core_ases}
        
        # regenerate core AS certs
        for _, topo in core_topos.items():
            topo.reissue_core_cert()
        
        # regenerate TRC
        # TODO
        # regenerate non core AS certs
        for AS, topo in self._internal.items():
            topo.reissue_cert(core_topos)

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
            isd = ISD.load_from_path(isd_path)
            self._isds[isd.isd_id] = isd
    
    def remap_all(self):
        for k, v in self._isds.items():
            v.remap_isd()
            # self._isds[map_ISD(k)] = self.remap_isd(self._isds.pop(k))
            self._isds.pop(k)
            self._isds[v.isd_id] = v

    # @classmethod
    # def remap_isd(cls, ases):
    #     # map topologies
    #     for AS, topo in ases.items():
    #         cls.remap_topology(topo)
    #         print('mapping ', AS)
    #     # regenerate core AS certs
    #     for AS, topo in ases.items():
    #         cls.reissue_cert(topo)
    #     # regenerate TRC
    #     # regenerate non core AS certs
    #     return ases

    # @classmethod
    # def remap_topology(cls, topo):
    #     topo.isd_as = map_id(str(topo.isd_as))
    #     for serv in (*topo.beacon_servers, *topo.certificate_servers, *topo.path_servers, *topo.sibra_servers, *topo.border_routers):
    #         serv.name = cls.remap_service_name(serv.name)
    #     # BRs contain references to other IAs
    #     for br in topo.border_routers:
    #         for k, v in br.interfaces.items():
    #             v.isd_as = map_id(str(v.isd_as))

    # @classmethod
    # def remap_service_name(cls, serv_name):
    #     first, middle, last = serv_name.split('-')
    #     middle = first[2:] + '-' + middle
    #     first = first[:2]
    #     newid = map_id(middle)
    #     return '%s%s-%s' %(first, newid.file_fmt(), last)

    @classmethod
    def reissue_cert(cls, topo):
        # print(topo.certs['as'])
        if topo.is_core_as:
            sign_priv = topo.get_keys()['online']
            cert = topo.certs['as']
            # c = cert['1']
            # c = Certificate.from_values(
            #     topo.ia_str(), 
            #     topo.ia_str(), 
            #     c[TRC_VERSION_STRING],
            #     c[VERSION_STRING],
            #     c[COMMENT_STRING],
            #     c[CAN_ISSUE_STRING],
            #     c[EXPIRATION_TIME_STRING]
            # )
            c = Certificate(cert['1'])
            print('-------------------------------------')
            print(c)
            setattr(c, Certificate.FIELDS_MAP[SUBJECT_STRING][0], topo.ia_str())
            setattr(c, Certificate.FIELDS_MAP[ISSUER_STRING][0], topo.ia_str())
            c.sign(sign_priv)
            print('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')
            print(c)


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

