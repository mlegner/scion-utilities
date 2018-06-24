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

from lib.packet.scion_addr import ISD_AS


ScionLabInfrastructureASOffsetAddr=0xFFAA00000000
ScionlabUserASOffsetAddr=0xFFAA00010000


def map_ISD(old_isd):
    return old_isd + 16

def map_ASID(old_asid):
    if old_asid < 1000:
        # infrastructure AS
        offset = ScionLabInfrastructureASOffsetAddr
    else:
        # user ASes
        offset = ScionlabUserASOffsetAddr - 1000
    return old_asid + offset

def map_id(old_ia):
    """
    Returns the new IA
    :param old_ia ISD_AS is an IA prior to address standarization
    """
    pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('gen', help='Gen folder to apply the transformation')
    parser.add_argument('-d', '--dry', help='Dry run. Don\'t make changes')
    args = parser.parse_args()
    print(map_ASID(1001))

if __name__ == "__main__":
    main()

