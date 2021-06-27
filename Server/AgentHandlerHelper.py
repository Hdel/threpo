import time
import pymysql

import Utilities


def registration(conn: pymysql.Connection, message):
    print("registration start...")
    cursor = conn.cursor()
    info_dict = message["info"]
    secret = message["info"]["secret"]
    machine_digest = Utilities.hash_wrapper(info_dict)
    info_dict.pop("secret")

    cursor.execute("insert into machines (secret, digest, state, update_time) values ('%s', '%s', %d, %f)"
                   % (secret, machine_digest, 0, time.time()))
    ret_id = conn.insert_id()
    cursor.execute("insert into change_log (operation, description, op_timestamp, witness) values (%d, '%s', %f, %d)"
                   % (0, "new_machine" + '@' + str(ret_id) + '@' + str(ret_id), time.time(), 0))
    conn.commit()

    hardware_insert_many(conn, info_dict, ret_id)
    return ret_id


def normal(message, key):
    check_result = Utilities.check_integrity(message, key)
    if check_result["status"] == "sound":
        return 0
    else:
        return check_result


def confirmation(conn: pymysql.Connection, message, key):
    integrity_check_result = Utilities.check_integrity(message, key)
    if integrity_check_result["status"] != "sound":
        return integrity_check_result

    # check digest
    sent_digest = integrity_check_result["info"]["digest"]
    info_dict = integrity_check_result["info"]
    info_dict.pop("digest")

    digest_check_result = Utilities.check_digest(conn, integrity_check_result["identity"], info_dict, sent_digest)
    if digest_check_result["status"] == "sound":
        info_from_db = collect_info(conn, integrity_check_result["identity"])
        if info_dict == info_from_db:
            return 0
        else:
            return {"status": "error", "description": "same digest but different hardware!"}
    else:
        return digest_check_result


def abnormal(conn: pymysql.Connection, message, key):
    abnormal_list = message["info"]["abnormal_list"]
    old_list = message["info"]["old_list"]
    identity = message["identity"]
    del_list = []
    insert_list = []

    if key == 0:
        key = Utilities.get_key_by_id(conn, identity)

    integrity_check_result = Utilities.check_integrity(message, key)
    if integrity_check_result["status"] != "sound":
        return integrity_check_result

    info_from_db = collect_info(conn, integrity_check_result["identity"])
    if old_list == info_from_db:
        for entry in abnormal_list:
            if entry["abnormal_type"] == 3:
                insert_list.append({"res_type": entry["res_type"], "content": entry["description"]})
                old_list[entry["res_type"]].append(entry["description"])
            elif entry["abnormal_type"] == 2:
                del_list.append({"res_type": entry["res_type"], "content": entry["description"]})
                old_list[entry["res_type"]].remove(entry["description"])
                # check if changes provided matches with new hash digest

        new_digest = integrity_check_result["info"]["new_digest"]
        for entry in old_list:
            old_list[entry].sort(key=str)

        cursor = conn.cursor()
        cursor.execute("select secret from machines where id=%d" % identity)
        result = cursor.fetchone()
        secret = result[0]

        dict_with_secret = old_list.update({"secret": secret})
        calculated_hash = Utilities.hash_wrapper(dict_with_secret)

        if calculated_hash != new_digest:
            return {"status": "error", "description": "wrong new digest."}

        abnormal_update(conn, identity, del_list, insert_list, new_digest)
        return 0

    else:
        return {"status": "error", "description": "wrong old hardware info."}


def collect_info(conn: pymysql.Connection, identity):
    cursor = conn.cursor()
    final_dict = dict()
    info_table = ["cpu_info", "ram_info", "disk_info", "nic_info", "gcard_info"]

    for table in info_table:
        cursor.execute("select * from %s where machine=%d" % (table, identity))

        desc = cursor.description
        info = cursor.fetchall()

        desc_table = {}
        for column in range(len(desc)):
            if desc[column][0] not in ["id", "machine"]:
                desc_table.update({desc[column][0]: column})

        if len(info) == 0:
            continue
        else:
            this_info = []
            for entry in info:
                cur_hardware = dict()
                for column in desc_table:
                    cur_hardware.update({column: entry[desc_table[column]]})
                this_info.append(cur_hardware)
            this_info.sort(key=str)
            final_dict.update({table: this_info})

    return final_dict


def hardware_insert_many(conn: pymysql.Connection, items, machine):
    cursor = conn.cursor()
    for item in items:
        table_name = item
        for entry in items[item]:
            fields_fragment = ""
            values_fragment = ""
            for field in entry:
                fields_fragment += str(field) + ", "
                cur_value = entry[field]
                if type(cur_value) == str:
                    cur_value = "'" + cur_value + "'"
                values_fragment += str(cur_value) + ", "

            fields_fragment += "machine"
            values_fragment += str(machine)

            # print(table_name)
            # print(fields_fragment)
            # print(values_fragment)

            cursor.execute("insert into %s (%s) values(%s)" % (table_name, fields_fragment, values_fragment))
            item_id = conn.insert_id()
            cursor.execute(
                "insert into change_log (operation, description, op_timestamp, witness, machine) values (%d, '%s', %f, %d, %d) "
                % (3, table_name + '@' + str(item_id) + '@' + str(machine), time.time(), 0, machine))

    conn.commit()


def abnormal_update(conn: pymysql.Connection, identity, del_list, insert_list, new_digest):
    cursor = conn.cursor()
    cpu_insert = "insert into cpu_info (machine, caption, core) values (%d, '%s', %d)"
    ram_insert = "insert into ram_info (machine, size, manufacturer, sn) values (%d, %d, '%s', '%s')"
    disk_insert = "insert into disk_info (machine, size, caption, sn) values (%d, %d, '%s', '%s')"
    nic_insert = "insert into nic_info (machine, mac) values (%d, '%s')"
    gcard_insert = "insert into gcard_info (machine,caption) values (%d, '%s')"
    log_insert = "insert into change_log (operation, description, op_timestamp, witness, machine) values (%d, '%s', %f, %d, %d)"

    for item in del_list:
        if item["res_type"] == "cpu_info":
            sql_select = "select id from cpu_info where machine=%d and caption='%s' and core=%d order by id limit 1"
            cursor.execute(sql_select % (identity, item["content"]["name"], item["content"]["core"]))
            target_id = cursor.fetchone()[0]
            sql_query = "update cpu_info set machine=-1 where machine=%d and caption='%s' and core=%d order by id limit 1"
            cursor.execute(sql_query % (identity, item["content"]["name"], item["content"]["core"]))

        elif item["res_type"] == "ram_info":
            sql_select = "select id from ram_info where machine=%d and size=%d and manufacturer='%s' and sn='%s' order by id limit 1"
            cursor.execute(sql_select % (identity, item["content"]["size"], item["content"]["manufacturer"], item["content"]["sn"]))
            target_id = cursor.fetchone()[0]
            sql_query = "update ram_info set machine=-1 where machine=%d and size=%d and manufacturer='%s' and sn='%s' order by id limit 1"
            cursor.execute(sql_query % (identity, item["content"]["size"], item["content"]["manufacturer"], item["content"]["sn"]))

        elif item["res_type"] == "disk_info":
            sql_select = "select id from disk_info where machine=%d and size=%d and caption='%s' and sn='%s' order by id limit 1"
            cursor.execute(sql_select % (identity, item["content"]["size"], item["content"]["name"], item["content"]["sn"]))
            target_id = cursor.fetchone()[0]
            sql_query = "update disk_info set machine=-1 where machine=%d and size=%d and caption='%s' and sn='%s' order by id limit 1"
            cursor.execute(sql_query % (identity, item["content"]["size"], item["content"]["name"], item["content"]["sn"]))

        elif item["res_type"]== "nic_info":
            sql_select = "select id from nic_info where machine=%d and mac='%s' order by id limit 1"
            cursor.execute(sql_select % (identity, item["content"]))
            target_id = cursor.fetchone()[0]
            sql_query = "update nic_info set machine=-1 where machine=%d and mac='%s' order by id limit 1"
            cursor.execute(sql_query % (identity, item["content"]))

        elif item["res_type"]== "gcard_info":
            sql_select = "select id from nic_info where machine=%d and caption='%s' order by id limit 1"
            cursor.execute(sql_select % (identity, item["content"]))
            target_id = cursor.fetchone()[0]
            sql_query = "update nic_info set machine=-1 where machine=%d and caption='%s' order by id limit 1"
            cursor.execute(sql_query % (identity, item["content"]))

        # insert into change_log (operation, description, op_timestamp, witness) values (%d, '%s', %f, %d)
        cursor.execute(log_insert % (2, item["res_type"]+'@'+str(target_id)+'@'+str(identity), time.time(), 0, identity))

    for item in insert_list:
        if item["res_type"] == "cpu_info":
            cursor.execute(cpu_insert % (identity, item["content"]["name"], item["content"]["core"]))
            target_id = conn.insert_id()

        elif item["res_type"] == "ram_info":
            cursor.execute(ram_insert % (identity, item["content"]["size"], item["content"]["manufacturer"], item["content"]["sn"]))
            target_id = conn.insert_id()

        elif item["res_type"] == "disk_info":
            cursor.execute(disk_insert % (identity, item["content"]["size"], item["content"]["name"], item["content"]["sn"]))
            target_id = conn.insert_id()

        elif item["res_type"] == "nic_info":
            cursor.execute(nic_insert % (identity, item["content"]))
            target_id = conn.insert_id()

        elif item["res_type"] == "gcard_info":
            cursor.execute(gcard_insert % (identity, item["content"]))
            target_id = conn.insert_id()

        cursor.execute(log_insert % (3, item["res_type"]+'@'+str(target_id)+'@'+str(identity), time.time(), 0, identity))

    cursor.execute("update machines set digest='%s' where id=%d" % (new_digest, identity))
    conn.commit()


# conn = DatabaseUtils.get_database_connection()
# conn.close()
