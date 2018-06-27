#!/usr/bin/python3
# Copyright 2018 ETH Zurich
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


# Stdlib
import argparse
from peewee import MySQLDatabase, SqliteDatabase

# SCION
from lib.packet.scion_addr import ISD_AS
from transform_topology import map_id, map_ISD


DB = None
DRY = False


def dry_execute_query(query):
    print(query)
    if not DRY:
        DB.execute_sql(query)


def transform_coord(args):
    print("Updating datatypes:")
    dry_execute_query("ALTER TABLE scion_lab_as MODIFY isd SMALLINT UNSIGNED;")
    dry_execute_query("ALTER TABLE scion_lab_as MODIFY as_id BIGINT UNSIGNED;")
    dry_execute_query("ALTER TABLE isd_location MODIFY isd SMALLINT UNSIGNED;")

    print("\nUpdating infrastructure ASes in scion_lab_as:")
    as_rows = DB.execute_sql("SELECT id, isd, as_id FROM scion_lab_as WHERE type = 0;")
    for row in as_rows:
        old_isd_as = ISD_AS.from_values(row[1], row[2])
        new_isd_as = map_id(old_isd_as)
        print("Old ISD_AS:", old_isd_as, "\tNew ISD_AS:", new_isd_as)
        dry_execute_query(
            "UPDATE scion_lab_as SET isd = {}, as_id = {} WHERE id = {};".format(
                new_isd_as[0], new_isd_as[1], row[0]))

    print("\nUpdating table isd_location:")
    isd_rows = DB.execute_sql("SELECT id, isd FROM isd_location;")
    for row in isd_rows:
        dry_execute_query(
            "UPDATE isd_location SET isd = {} WHERE id = {};".format(
                map_ISD(row[1]), row[0]))
    return


def transform_web(args):
    print("Updating ASes in ad_manager_ad:")
    as_rows = DB.execute_sql("SELECT id, isd_id, as_id FROM ad_manager_ad;").fetchall()
    for row in as_rows:
        isd_as = map_id(ISD_AS.from_values(row[1], row[2]))
        dry_execute_query(
            "UPDATE ad_manager_ad SET isd_id = {}, as_id = {}, as_id_str = '{}' "
            "WHERE id = {};".format(isd_as[0], isd_as[1], isd_as.as_str(), row[0]))

    print("\nUpdating border routers:")
    br_rows = DB.execute_sql("SELECT id, `name` FROM ad_manager_borderrouter;").fetchall()
    for row in br_rows:
        ids = row[1][2:].split('-')
        if ids[0] == "0":
            dry_execute_query("DELETE FROM ad_manager_borderrouter WHERE id = {};".format(row[0]))
            dry_execute_query("DELETE FROM ad_manager_borderrouteraddress "
                              "WHERE router_id = {};".format(row[0]))
            dry_execute_query("DELETE FROM ad_manager_borderrouterinterface "
                              "WHERE id = {};".format(row[0]))
            continue
        isd_as = map_id(ISD_AS.from_values(int(ids[0]), int(ids[1])))
        new_name = "br{}-{}".format(isd_as.file_fmt(), ids[2])
        dry_execute_query(
            "UPDATE ad_manager_borderrouter SET `name` = '{}' WHERE id = {};".format(
                new_name, row[0]))

    br_rows = DB.execute_sql("SELECT id, neighbor_isd_id, neighbor_as_id "
                             "FROM ad_manager_borderrouterinterface;").fetchall()
    for row in br_rows:
        isd_as = map_id(ISD_AS.from_values(row[1], row[2]))
        dry_execute_query(
            "UPDATE ad_manager_borderrouterinterface SET neighbor_isd_id = {}, "
            "neighbor_as_id = {}, neighbor_as_id_str = '{}' WHERE id = {};".format(
                isd_as[0], isd_as[1], isd_as.as_str(), row[0]))

    print("\nUpdating services:")
    rows = DB.execute_sql("SELECT id, `name` FROM ad_manager_service;").fetchall()
    for row in rows:
        service = row[1][:2]
        ids = row[1][2:].split('-')
        if ids[0] == "0":
            dry_execute_query("DELETE FROM ad_manager_service WHERE id = {};".format(row[0]))
            continue
        isd_as = map_id(ISD_AS.from_values(int(ids[0]), int(ids[1])))
        new_name = "{}{}-{}".format(service, isd_as.file_fmt(), ids[2])
        dry_execute_query(
            "UPDATE ad_manager_service SET `name` = '{}' WHERE id = {};".format(
                new_name, row[0]))

    print("\nUpdating ISDs in ad_manager_isd:")
    isd_rows = DB.execute_sql("SELECT id FROM ad_manager_isd;").fetchall()
    for row in isd_rows:
        dry_execute_query("DELETE FROM ad_manager_isd WHERE id = {};".format(row[0]))
    for row in isd_rows:
        dry_execute_query("INSERT INTO ad_manager_isd VALUES({});".format(map_ISD(row[0])))

    return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--address', help="database address", default='localhost')
    parser.add_argument('--port', help="database port", type=int, default=3306)
    parser.add_argument('-d', '--database', help="database name", required=True)
    parser.add_argument('-u', '--user', help="database user", default="root")
    parser.add_argument('-p', '--password', help="database password", default=None)
    parser.add_argument('-w', '--web', help="apply to scion-web instead of scion-coord",
                        action='store_true')
    parser.add_argument('--dry', help='dry run: only print SQL queries', action='store_true')
    args = parser.parse_args()

    global DB
    if args.web:
        DB = SqliteDatabase(args.database)
    else:
        DB = MySQLDatabase(args.database, user=args.user, passwd=args.password,
                           host=args.address, port=args.port)
    global DRY
    DRY = args.dry

    DB.connect()
    transform_web(args) if args.web else transform_coord(args)
    DB.close()


if __name__ == "__main__":
    main()
