import socket
import ssl
import time
import random
from email.mime.multipart import MIMEMultipart

from django.views.decorators.csrf import csrf_exempt, csrf_protect
from django.shortcuts import render, redirect
from configparser import ConfigParser
import hashlib
import pymysql
import smtplib
from email.mime.text import MIMEText
from email.header import Header

buffer_dict = dict()


def get_user_dict(request):
    name = request.COOKIES.get("name")
    role = request.COOKIES.get("role")
    identity = int(request.COOKIES.get("id"))
    return {"name": name, "role": role, "id": identity}


def alert_hardware(request):
    global buffer_dict
    db_conn = get_db()
    cursor = db_conn.cursor()

    cursor.execute("update change_log set witness=0, lock_time=0 "
                   "where %f-lock_time>300 and witness=-1" % time.time())

    context = {}
    context.update(get_user_dict(request))
    context['title'] = '警告查看'

    risk_config = get_risk()
    risk_dict = {"r": "(operation = 0 or operation = 3)", "d": "operation = 2",
                 "t": "operation = 4", "i": "operation = 5", "s": "operation = 6",
                 "n": "(operation = 7 or operation = 10)", "g": "operation = 8",
                 "u": "operation=9", "l": "operation=11"}

    msg_list = list()
    buffer_list = list()

    for risk in risk_config:
        # fetch log: from highest risk to lowest
        op_class = risk[-1]
        sql_s = risk_dict[op_class]

        while True:
            cursor.execute("select * from change_log where %s and witness=0 order by id, op_timestamp limit 1" % sql_s)
            result = cursor.fetchone()
            if not result:
                break

            description = result[2].split("@")
            if description[0].startswith("switch"):
                result_machine = result[6]
                print(result_machine)
                cursor.execute("select * from change_log where machine=%d and operation > 6 and witness = 0 order by id, op_timestamp"
                               % result_machine)
                result_list = cursor.fetchall()
                processed_data = record_to_desc_switch(result_list, cursor)
                id_list = processed_data["id_list"]
                msg_desc_list = processed_data["msg_list"]
                status_list = processed_data["status_list"]

            else:
                result_machine = result[6]
                cursor.execute("select * from change_log where machine=%d and operation <=6 and witness = 0 order by id, op_timestamp"
                               % result_machine)
                result_list = cursor.fetchall()
                processed_data = record_to_description(result_list, cursor)
                # print("to here 1")
                id_list = processed_data["id_list"]
                msg_desc_list = processed_data["msg_list"]
                status_list = processed_data["status_list"]

            status_index = 0

            for msg in msg_desc_list:
                index = len(msg_list)
                receive = "check-box-" + str(index + 1)
                comment_place = "comment-place-" + str(index + 1)
                msg_list.append({"identity": str(index + 1), "description": msg,
                                 "status": status_list[status_index], "receive": receive,
                                 "comment_place": comment_place})
                status_index += 1

            for ids in id_list:
                buffer_list.append(ids)
                for log_id in ids:
                    cursor.execute("update change_log set witness=-1, lock_time=%f where id=%d" % (time.time(), log_id))
                db_conn.commit()

        # # in this code block: fill the message list
        # if op_class == "r":
        #     i = 0
        #     list_len = len(result_list)
        #     while i < list_len:
        #         entry = result_list[i]
        #         # construct description list
        #         # if it is an insert entry
        #         if entry[1] == 3:
        #             buffer_list.append([entry[0]])
        #
        #             description_list = entry[2].split("@")
        #             description_str = "agent [" + str(description_list[2]) + "]: hardware inserted.\n" \
        #                                                                      "hardware information:\n"
        #             cursor.execute("select * from %s where id=%d" % (description_list[0], int(description_list[1])))
        #             hardware_info = cursor.fetchone()
        #             hardware_str = description_list[0][:-5] + ": "
        #             for j in range(2, len(hardware_info)):
        #                 hardware_str += str(hardware_info[j]) + " "
        #             description_str += hardware_str
        #             i += 1
        #         # if it is an registration entry
        #         elif entry[1] == 0:
        #             temp_buffer = [entry[0]]
        #             description_list = entry[2].split("@")
        #             machine_id = description_list[1]
        #             machine_timestamp = entry[3]
        #             description_str = "agent [" + str(description_list[1]) + "]: registered\nhardware information:\n"
        #
        #             i += 1
        #             while i < list_len:
        #                 entry = result_list[i]
        #                 if entry[1] == 0:
        #                     break
        #                 else:
        #                     description_list = entry[2].split("@")
        #                     temp_buffer.append(entry[0])
        #                     if description_list[2] != machine_id or entry[3] > machine_timestamp + 3:
        #                         break
        #                     cursor.execute(
        #                         "select * from %s where id=%d" % (description_list[0], int(description_list[1])))
        #                     hardware_info = cursor.fetchone()
        #                     hardware_str = description_list[0][:-5] + ": "
        #                     for j in range(2, len(hardware_info)):
        #                         hardware_str += str(hardware_info[j]) + " "
        #
        #                     hardware_str += "\n"
        #                     description_str += hardware_str
        #                     i += 1
        #
        #             buffer_list.append(temp_buffer)
        #
        #         # build msg_list
        #         receive = "check-box-" + str(len(msg_list) + 1)
        #         comment_place = "comment-place-" + str(len(msg_list) + 1)
        #         identity = str(len(msg_list) + 1)
        #         status = risk[0]
        #
        #         msg_list.append({"identity": identity, "description": description_str.split("\n"), "status": status,
        #                          "receive": receive, "comment_place": comment_place})
        #         if len(msg_list) >= 10:
        #             break
        #
        # elif op_class == "d":
        #     for entry in result_list:
        #         buffer_list.append([entry[0]])
        #         identity = str(len(msg_list) + 1)
        #         description_list = entry[2].split("@")
        #         description_str = "agent [" + str(description_list[2]) + "]: hardware removed.\nhardware information:\n"
        #         cursor.execute("select * from %s where id=%d" % (description_list[0], int(description_list[1])))
        #         hardware_info = cursor.fetchone()
        #         hardware_str = description_list[0][:-5] + ": "
        #
        #         for j in range(2, len(hardware_info)):
        #             hardware_str += str(hardware_info[j]) + " "
        #
        #         description_str += hardware_str
        #         status = risk[0]
        #
        #         receive = "check-box-" + str(len(msg_list) + 1)
        #         comment_place = "comment-place-" + str(len(msg_list) + 1)
        #
        #         msg_list.append({"identity": identity, "description": description_str.split("\n"), "status": status,
        #                          "receive": receive, "comment_place": comment_place})
        #         if len(msg_list) >= 10:
        #             break
        #
        # elif op_class in ["u", "i", "t"]:
        #     op_dict = {"u": "unknown error.", "i": "integrity check failed.", "t": "timeout."}
        #
        #     for entry in result_list:
        #         buffer_list.append([entry[0]])
        #         identity = str(len(msg_list) + 1)
        #         description_list = entry[2].split("@")
        #         description_str = "agent [" + str(description_list[1]) + "]: " + op_dict[op_class]
        #         status = risk[0]
        #         receive = "check-box-" + str(len(msg_list) + 1)
        #         comment_place = "comment-place-" + str(len(msg_list) + 1)
        #         msg_list.append({"identity": identity, "description": description_str.split("\n"), "status": status,
        #                          "receive": receive, "comment_place": comment_place})
        #         if len(msg_list) >= 10:
        #             break
        #
        # # in this code block: check the break condition
        # if len(msg_list) >= 10:
        #     break

    context['msg_list'] = msg_list
    username = context['name']
    buffer_dict[username] = buffer_list
    print(buffer_dict)
    db_conn.close()
    return render(request, 'alert-hardware.html', context)


def hardware_to_description(table, hw_id, cursor):
    cursor.execute("select * from %s where id=%d" % (table, hw_id))
    hardware_info = cursor.fetchone()

    hardware_str = table[:-5] + ": "
    for j in range(2, len(hardware_info)):
        hardware_str += str(hardware_info[j]) + " "
    hardware_str += "\n"

    return hardware_str


# TODO
def record_to_desc_switch(db_record_list, cursor):
    desc_list = []
    id_list = list()
    status_list = list()
    i = 0
    op_risk_dict = get_op_risk_dict()
    print("in desc...")

    while i < len(db_record_list):
        print("num" + str(i) + "...")
        record = db_record_list[i]

        operation = record[1]
        description_list = record[2].split("@")
        status_list.append(op_risk_dict[operation])

        cursor.execute("select switch_name from switch_table where id = %d" % record[6])
        switch_name = cursor.fetchone()[0]

        if operation == 7:
            description_str = "Switch [" + switch_name + "]: registration.\n"
            i += 1
            reg_timestamp = record[3]
            temp_id = [record[0]]

            while i < len(db_record_list) and db_record_list[i][1] == 10 \
                    and db_record_list[i][3] - reg_timestamp < 10:
                record = db_record_list[i]
                i += 1
                temp_id.append(record[0])

            desc_list.append(description_str.split("\n"))
            id_list.append(temp_id)

        elif operation == 9 or operation == 10:
            op_dict = {9: "remove ", 10: "add "}
            hardware_str = record[2]
            hardware_str = op_dict[operation] + hardware_str
            description_str = hardware_str
            desc_list.append(description_str.split("\n"))
            id_list.append([record[0]])
            i += 1

        elif operation == 11:
            description_str = "Switch [" + switch_name + "]: timeout.\n"
            desc_list.append(description_str.split("\n"))
            id_list.append([record[0]])
            i += 1

    print(desc_list)
    print(id_list)
    print(status_list)
    return {"msg_list": desc_list, "id_list": id_list, "status_list": status_list}


def record_to_description(db_record_list, cursor):
    description_str = ""
    desc_list = []
    id_list = list()
    status_list = list()
    i = 0
    op_risk_dict = get_op_risk_dict()

    while i < len(db_record_list):
        record = db_record_list[i]

        operation = record[1]
        description_list = record[2].split("@")
        status_list.append(op_risk_dict[operation])

        if operation == 0:
            description_str = "Agent [" + description_list[1] + "]: registration.\nhardware info:\n"
            i += 1
            reg_timestamp = record[3]
            temp_id = [record[0]]

            while i < len(db_record_list) and db_record_list[i][1] == 3 \
                    and db_record_list[i][3] - reg_timestamp < 5:
                record = db_record_list[i]
                description_list = record[2].split("@")
                hardware_str = hardware_to_description(description_list[0], int(description_list[1]), cursor)
                description_str += hardware_str
                i += 1
                temp_id.append(record[0])
            desc_list.append(description_str.split("\n"))
            id_list.append(temp_id)

        elif operation == 2 or operation == 3:
            op_dict = {2: "remove ", 3: "add "}
            hardware_str = hardware_to_description(description_list[0], int(description_list[1]), cursor)
            hardware_str = op_dict[operation] + hardware_str
            description_str = hardware_str
            desc_list.append(description_str.split("\n"))
            id_list.append([record[0]])
            i += 1

        elif operation == 4:
            description_str = "Agent [" + description_list[1] + "]: timeout.\n"
            desc_list.append(description_str.split("\n"))
            id_list.append([record[0]])
            i += 1
        elif operation == 5:
            description_str = "Agent [" + description_list[1] + "]: integrity check failed.\n"
            desc_list.append(description_str.split("\n"))
            id_list.append([record[0]])
            i += 1
        elif operation == 6:
            description_str = "Agent [" + description_list[1] + "]: restored.\n"
            desc_list.append(description_str.split("\n"))
            id_list.append([record[0]])
            i += 1
    # print(desc_list)
    # print(id_list)
    # print(status_list)
    return {"msg_list": desc_list, "id_list": id_list, "status_list": status_list}


def alert_hardware_post(request):
    global buffer_dict
    conn = get_db()
    cursor = conn.cursor()

    trans_id_list = buffer_dict[get_user_dict(request)["name"]]
    for i in range(1, len(trans_id_list) + 1):
        check_box = "check-box-" + str(i)
        comment_place = "comment-place-" + str(i)
        data_position = trans_id_list[i - 1]
        is_abnormal = request.POST[check_box]
        comment = request.POST[comment_place]
        # print(type(get_user_dict(request)["id"]))
        # print(type(data_position[0]))
        rows_affected = cursor.execute("update change_log set witness=%d where id=%d and witness=-1" %
                                       (int(get_user_dict(request)["id"]), data_position[0]))
        if rows_affected == 0:
            print("rows affected..." + str(rows_affected))
            i += 1
            continue

        cursor.execute("select * from change_log where id=%d" % data_position[0])
        log_data = cursor.fetchone()
        operation = log_data[1]
        data_description = log_data[2].split("@")

        if operation not in [0, 7]:
            admin_description = str(data_position[0]) + "@" + str(0) + "@" + comment
            cursor.execute("insert into admin_log (admin_id, operation, description, op_timestamp, state)"
                           "values(%d, %d, '%s', %f, %d)" %
                           (int(get_user_dict(request)["id"]), 0, admin_description, time.time(), 0))
            if operation == 2 or operation == 3:
                pass
            elif operation == 4:
                if int(is_abnormal) == 1:
                    machine_state = 2
                else:
                    machine_state = 3
                    # machine removal during maintenance
                    hardware_table = {"ram_info", "cpu_info", "disk_info", "nic_info", "gcard_info"}
                    for table in hardware_table:
                        cursor.execute("update %s set machine=%d where machine=%d" %
                                       (table, -int(data_description[1]), int(data_description[1])))

                cursor.execute("update machines set state=%d, comment='%s' where id=%d" %
                               (machine_state, comment, int(data_description[1])))
            elif operation == 5:
                # integrity check failed
                # abnormal machine
                cursor.execute("update machines set state=%d, comment='%s' where id=%d" % (
                    2, comment, int(data_description[1])))
            elif operation == 9 or operation == 10:
                pass
            elif operation == 11:
                pass

        elif operation == 0:
            cursor.execute("update machines set state=%d, comment='%s' where id=%d" % (
                int(is_abnormal) + 1, comment, int(data_description[1])))
            for j in data_position[1:]:
                cursor.execute("update change_log set witness=%d where id=%d " %
                               (get_user_dict(request)["id"], j))
        elif operation == 7:
            for j in data_position[1:]:
                cursor.execute("update change_log set witness=%d where id=%d " %
                               (get_user_dict(request)["id"], j))

        conn.commit()
    conn.close()
    return redirect("/alert-hardware/")


def sort_helper(result):
    desc_list = result[3].split("@")
    if len(desc_list) == 2:
        return 0
    elif desc_list[1] == "1":
        return 0
    else:
        return 1


def alert_admin(request):
    global buffer_dict
    context = {}
    context.update(get_user_dict(request))
    conn = get_db()
    cursor = conn.cursor()
    context['title'] = '警告查看'

    cursor.execute("select * from admin_log where state=0")
    result_list = cursor.fetchall()
    result_list = list(result_list)
    result_list.sort(key=sort_helper)

    msg_list = list()
    buff_list = list()
    print(result_list)
    for i in range(len(result_list)):
        if result_list[i][2] == 0:
            admin_desc_list = result_list[i][3].split("@")
            cursor.execute("select description from change_log where id=%d" % int(admin_desc_list[0]))
            change_desc = cursor.fetchone()[0]
            description_str = "operator: " + str(result_list[i][1]) + "\n" + "operation: " + change_desc + "\n"
            receive = "check-box-" + str(len(msg_list) + 1)
            msg_list.append({"identity": i + 1, "description": description_str.split("\n"),
                             "status": str(sort_helper(result_list[i])), "receive": receive})
            buff_list.append(result_list[i][0])

    context["msg_list"] = msg_list
    print(context)
    buffer_dict[context["name"]] = buff_list
    return render(request, 'alert-admin.html', context)


def alert_admin_post(request):
    global buffer_dict
    trans_id_list = buffer_dict[get_user_dict(request)["name"]]
    for i in range(1, len(trans_id_list) + 1):
        check_box = "check-box-" + str(i)
        data_position = buffer_dict[get_user_dict(request)["name"]][i - 1]
        not_done = request.POST[check_box]
        conn = get_db()
        cursor = conn.cursor()
        if not_done == "0":
            cursor.execute("update admin_log set state=1 where id=%d" % data_position)

        conn.commit()
        conn.close()
    return redirect("/alert-admin/")


def search_post(request):
    return redirect("/search/")


def config_admin(request):
    global buffer_dict
    context = {}
    context.update(get_user_dict(request))
    context['title'] = '高级管理员配置'
    risk = []

    risk_status_dict = get_risk_status_dict()
    i = 0
    for change in risk_status_dict:
        risk.append({"name":change, "status": risk_status_dict[change], "to": str(i) + "_to"})
        i += 1

    config = ConfigParser()
    config.read("djangoProject/WebConf.conf")
    items = config.items("alert")
    alert_list = []

    for item in items:
        alert_list.append({"name": item[0], "check": item[0], "if": item[1]})

    context['risk_list'] = risk
    context['alert_list'] = alert_list
    conn = get_db()
    cursor = conn.cursor()

    conn.close()

    return render(request, 'config-admin.html', context)


def alert_post(request):
    config = ConfigParser()
    config.read("djangoProject/WebConf.conf")
    items = config.items("alert")

    for item in items:
        if item[0] in request.POST:
            config.set("alert", item[0], "1")
        else:
            config.set("alert", item[0], "0")

    config.write(open("djangoProject/WebConf.conf", "w"))

    server_addr = "127.0.0.1"
    server_port = 9556

    items = config.items("alert")
    info = {"type": "alert", "config": items}

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = ssl.wrap_socket(s, ca_certs="C:\\djangoProject\\djangoProject\\cert.pem", cert_reqs=ssl.CERT_REQUIRED)
    ssl_sock.bind(("127.0.0.1", 7776))
    ssl_sock.connect((server_addr, server_port))
    ssl_sock.send(str(info).encode())
    ssl_sock.close()

    return redirect("/admin-config/")


def risk_post(request):
    config = ConfigParser()
    config.read("djangoProject/WebConf.conf")
    items = config.items("risk")

    for i in range(len(items)):
        if request.POST[str(i)+"_to"] != "":
            config.set("risk", items[i][0], str(request.POST[str(i)+"_to"]))

    config.write(open("djangoProject/WebConf.conf", "w"))

    return redirect("/admin-config/")


def config_common(request):
    context = {}
    context.update(get_user_dict(request))
    context['title'] = '普通管理员配置'

    config = ConfigParser()
    config.read("djangoProject/WebConf.conf")
    items = config.items("interval")
    interval_list = []

    for item in items:
        interval_list.append({"name": item[0], "current": item[1], "to": item[0]})

    context['interval_list'] = interval_list
    context['proxy'] = {"if": config.get("proxy", "if_proxy"), "check": "proxy-checkbox", "query": "proxy-list"}

    return render(request, 'config-common.html', context)


def proxy_post(request):
    if_proxy = request.POST["proxy-checkbox"]
    proxy_list = request.POST["proxy-list"]

    config = ConfigParser()
    config.read("djangoProject/WebConf.conf")
    conf_if_proxy = config.get("proxy", "if_proxy")

    conn = get_db()
    cursor = conn.cursor()

    if if_proxy != conf_if_proxy:
        if if_proxy == "1":
            if proxy_list == "":
                pass
            else:
                proxy_list.split(",")
                cursor.execute("update config_info set conf_value=1 where conf='if_proxy' and conf_section='proxy'")
                cursor.execute("create table proxy_list (addr varchar(16))")
                for proxy in proxy_list:
                    cursor.execute("insert into proxy_list (addr) values ('%s')" % proxy)
        elif if_proxy == "0":
            cursor.execute("drop table proxy_list")
            cursor.execute("update config_info set conf_value=0 where conf='if_proxy' and conf_section='proxy'")

    conn.commit()
    conn.cursor()

    return redirect("/common-config/")


def interval_post(request):
    print("start...")
    config = ConfigParser()
    config.read("djangoProject/WebConf.conf")
    items = config.items("interval")
    conn = get_db()
    cursor = conn.cursor()

    for i in range(len(items)):
        if request.POST[items[i][0]] != "":
            config.set("interval", items[i][0], str(request.POST[items[i][0]]))
            cursor.execute("update config_info set conf_value=%d where conf_section='interval' and conf=%s"
                           % (int(request.POST[items[i][0]]), items[i][0]))

    config.write(open("djangoProject/WebConf.conf", "w"))

    conn.commit()
    conn.close()
    return redirect("/common-config/")


def search(request):
    context = {}
    context.update(get_user_dict(request))
    conn = get_db()
    cursor = conn.cursor()

    context['search_type'] = 'none'

    context['title'] = '查询'
    msg_list = list()
    switch_list = list()
    if request.POST:
        table = request.POST["select-table"]
        state = request.POST["state"]
        item_query = request.POST["query"]
        hardware_table = {"ram_info": "manufacturer", "cpu_info": "caption", "disk_info": "caption", "nic_info": "mac",
                          "gcard_info": "caption"}

        context['search_type'] = 'common'
        if table == "machines":
            state_dict = {"removed": 4, "in_use": 1, "abnormal": 2}
            state = state_dict[state]

            cursor.execute("select id from machines where id=%d and state=%d" % (int(item_query), state))
            if_exist = cursor.fetchall()
            if len(if_exist) == 0:
                pass
            else:
                msg_description = "machine [" + str(item_query) + "]:\n"
                for table in hardware_table:
                    cursor.execute("select * from %s where machine=%d" % (table, int(item_query)))
                    result_list = cursor.fetchall()
                    for result in result_list:
                        msg_description += table[:-5]
                        msg_description += ": "
                        for feature_index in range(2, len(result)):
                            msg_description += str(result[feature_index]) + " "
                        msg_description += "\n"
                msg_list.append({"identity": 1, "description": msg_description.split("\n")})

        elif table in hardware_table:
            state_dict = {"removed": "machine=-1 and", "in_use": "machine>0 and", "abnormal": ""}
            state = state_dict[state]
            print("select * from %s where %s %s like '%s'" % (
                table, state, hardware_table[table], "%" + item_query + "%"))
            cursor.execute("select * from %s where %s %s like '%s'" %
                           (table, state, hardware_table[table], "%" + item_query + "%"))
            result_list = cursor.fetchall()
            for result in result_list:
                msg_description = table[:-5] + ": "
                for feature_index in range(2, len(result)):
                    msg_description += str(result[feature_index])
                    msg_description += " "
                msg_list.append({"identity": len(msg_list) + 1, "description": msg_description.split("\n")})

        elif table == "switch_table":
            cursor.execute("select id from switch_table where switch_name = '%s'" % item_query)
            table_id = cursor.fetchone()[0]
            table_name = "switch_" + str(table_id)
            cursor.execute("select * from %s" % table_name)
            msg_list = list(cursor.fetchall())
            context["search_type"] = "switch"

    context["msg_list"] = msg_list
    conn.close()
    return render(request, 'search.html', context)


def login(request):
    conn = get_db()
    cursor = conn.cursor()

    if request.POST:
        user_email = request.POST["email"]
        user_password = request.POST["password"]

        salt = get_salt()
        sha256_hash = hashlib.sha256(salt.encode('utf8'))
        sha256_hash.update(user_password.encode('utf8'))
        hash_value = sha256_hash.hexdigest()
        cursor.execute("select * from staff_info where email='%s' and digest='%s'" % (user_email, hash_value))
        result = cursor.fetchone()
        conn.close()
        print("result:" + str(result))
        if result is not None:
            rep = redirect("/alert-hardware/")
            uname = (user_email.split("@"))[0]
            rep.set_cookie("name", uname)
            rep.set_cookie("id", int(result[0]))
            if result[3] == 1:
                role = "staff"
            else:
                role = "admin"
            rep.set_cookie("role", role)
            return rep

    return render(request, "login.html")


def reg_post(request):
    conn = get_db()
    cursor = conn.cursor()

    email = request.POST["email"]
    password = rand_string(25)

    cursor.execute("select * from staff_info where email='%s'" % email)
    ret = cursor.fetchone()

    if ret is None:
        salt = get_salt()
        sha256_hash = hashlib.sha256(salt.encode('utf8'))
        sha256_hash.update(password.encode('utf8'))
        hash_value = sha256_hash.hexdigest()
        send_reg_email(email, password)
        print(password)
        cursor.execute("insert into staff_info (email, digest) values ('%s', '%s')" % (email, hash_value))
        conn.commit()

    conn.close()
    return redirect("/admin-config")


def get_db():
    config = ConfigParser()
    config.read("djangoProject/WebConf.conf")
    host = config.get("mysql", "host")
    port = config.get("mysql", "port")
    database = config.get("mysql", "database")
    username = config.get("mysql", "username")
    password = config.get("mysql", "password")
    return pymysql.connect(host=host, user=username, port=int(port), password=password, db=database)


def get_risk():
    config = ConfigParser()
    config.read("djangoProject/WebConf.conf")
    risk_list = [config.get("risk", "registration") + "r", config.get("risk", "timeout") + "t",
                 config.get("risk", "removal") + "d", config.get("risk", "integrity") + "i",
                 config.get("risk", "switch_reg") + "n",
                 config.get("risk", "switch_remove") + "g", config.get("risk", "int_remove") + "u",
                 config.get("risk", "switch_timeout") + "l"]
    risk_list.sort()
    return risk_list


def get_op_risk_dict():
    config = ConfigParser()
    config.read("djangoProject/WebConf.conf")
    op_list = {0: config.get("risk", "registration"), 4: config.get("risk", "timeout"),
               2: config.get("risk", "removal"), 5: config.get("risk", "integrity"),
               3: config.get("risk", "registration"),
               7: config.get("risk", "switch_reg"), 8: config.get("risk", "switch_remove"),
               9: config.get("risk", "int_remove"), 10: config.get("risk", "switch_reg"),
               11: config.get("risk", "switch_timeout")}
    return op_list


def get_risk_status_dict():
    config = ConfigParser()
    config.read("djangoProject/WebConf.conf")
    op_list = {"registration": config.get("risk", "registration"), "machine timeout": config.get("risk", "timeout"),
               "hardware removal": config.get("risk", "removal"), "integrity check failed": config.get("risk", "integrity"),
               "switch reg": config.get("risk", "switch_reg"), "switch removal": config.get("risk", "switch_remove"),
               "module removed": config.get("risk", "int_remove"), "switch timeout": config.get("risk", "switch_timeout")}
    return op_list


def get_salt():
    config = ConfigParser()
    config.read("djangoProject/WebConf.conf")
    salt = config.get("security", "salt")
    return salt


def rand_string(length):
    random.seed(time.time())
    ret_string = ""
    char_list = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-_+={};:.?!@#$"
    list_len = len(char_list)
    for i in range(length):
        ret_string += str(char_list[random.randint(0, list_len - 1)])

    return ret_string


def send_reg_email(email, password):
    mail_host = "******"
    mail_user = "******"
    mail_pass = "******"

    sender = '******'
    receivers = [email]

    message = MIMEMultipart()
    message['From'] = Header(mail_user)
    message['To'] = Header("xh", 'utf-8')

    subject = '注册邮件'
    message['Subject'] = Header(subject, 'utf-8')

    content1 = MIMEText("密码："+password, 'plain', 'utf-8')
    message.attach(content1)
    try:
        smtpObj = smtplib.SMTP_SSL(mail_host)
        smtpObj.login(mail_user, mail_pass)
        smtpObj.sendmail(sender, receivers, message.as_string())
    except:
        print("something wrong...")
    finally:
        smtpObj.close()
