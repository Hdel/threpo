#!/usr/bin/sudo python

import re
import os


def collect_normal():
    resource_info = dict()
    resource_info.update(get_cpu_info())
    resource_info.update(get_ram_info())
    resource_info.update(get_disk_info())
    resource_info.update(get_nic_info())
    resource_info.update(get_gcard_info())

    for item in resource_info:
        resource_info[item].sort(key=str)
    return resource_info


def get_cpu_info():
    pre_name_strs = (os.popen("cat /proc/cpuinfo |grep \"model name\"").read()).split('\n')
    pre_core_strs = (os.popen("cat /proc/cpuinfo |grep \"cpu cores\"").read()).split('\n')

    pre_name_strs.pop()
    pre_core_strs.pop()

    if len(pre_name_strs) != len(pre_core_strs):
        print("cpu information collection error, in detail: ")
        print(pre_name_strs)
        print(pre_core_strs)
        return {"cpu_info": ["error while collecting"]}

    cpu_number = len(pre_name_strs)
    cpu_info = []

    for i in range(cpu_number):
        new_item = {
            "caption": pre_name_strs[i][13:],
            "core": int(pre_core_strs[i].split(' ')[-1])
        }
        cpu_info.append(new_item)

    return {"cpu_info": cpu_info}


def get_ram_size():
    pre_strs = ((os.popen("lshw -c memory")).read()).split('\n')
    i = 0
    ram_size = []

    while i < len(pre_strs):
        if "-memory" in pre_strs[i]:
            i += 1
            while i < len(pre_strs):
                if "size" in pre_strs[i]:
                    ram_size.append(int(re.findall(r'\d+', pre_strs[i])[0]))
                    i += 1
                    break
                else:
                    i += 1
        else:
            i += 1

    if len(ram_size)== 0:
        return [-1]
    else:
        ram_info = []
        for r_size in ram_size:
            ram_info.append({"size": r_size, "manufacturer": "not retrieved", "sn": "not retrieved"})
        return ram_info


def get_ram_info():
    pre_strs = (os.popen("dmidecode --type 17").read()).split('\n')

    ram_info = []
    lines = len(pre_strs)
    i = 0

    while i < lines:
        if "Size:" in pre_strs[i]:
            ram_item = dict()
            if bool(re.search(r'\d', pre_strs[i])):
                ram_size = int(re.findall(r'\d+', pre_strs[i])[0])
                ram_item["size"] = ram_size
                i += 1
                while i < lines:
                    if "Size:" in pre_strs[i]:
                        break
                    elif "Manufacturer:" in pre_strs[i]:
                        ram_manufacturer = ((pre_strs[i].strip())[13:]).strip()
                        ram_item["manufacturer"] = ram_manufacturer
                        i += 1
                        if "Serial Number" not in pre_strs[i]:
                            print("dmidecode info format not as expected. fix later.")
                            break
                        ram_sn = ((pre_strs[i].strip())[14:]).strip()
                        ram_item["sn"] = ram_sn
                        ram_info.append(ram_item)
                        i += 1
                        break
                    else:
                        i += 1
            else:
                i += 1
        else:
            i += 1

    if len(ram_info) < 1:
        # print("no valid ram info")
        ram_lshw = get_ram_size()
        if ram_lshw[0] != -1:
            return {"ram_info": ram_lshw}
        return {"ram_info": ["error while collecting"]}
    else:
        return {"ram_info": ram_info}


def get_disk_info():
    name_str = os.popen("fdisk -l | grep \"Disk /dev/sd\"").read()
    name_pattern = re.compile(r'/dev/sd[a-z]+')
    dev_name = re.findall(name_pattern, name_str)
    disk_info = []

    for i in range(len(dev_name)):
        pre_strs = os.popen("sudo hdparm -i "+dev_name[i]+"|grep Model=").read()
        pattern_model = re.compile(r'Model=.+?,')
        pattern_SN = re.compile(r'SerialNo=.+')

        size_str = os.popen("fdisk -l | grep \"Disk "+dev_name[i]+"\"").read()
        size_pattern = re.compile(r'\d+ [GMK]iB')
        disk_size = re.findall(size_pattern, size_str)

        if "M" in disk_size[0]:
            final_size = (int(disk_size[0][:-4]))/1024
        elif "K" in disk_size[0]:
            final_size = (int(disk_size[0][:-4]))/(1024**2)
        else:
            final_size = int(disk_size[0][:-4])

        model = re.findall(pattern_model, pre_strs)[0][6:-1]
        sn = re.findall(pattern_SN, pre_strs)[0][9:-1]
        disk_info.append({"caption": model, "sn": sn, "size": final_size})

    if len(disk_info) == 0:
        disk_info.append({"caption": "none", "sn": "none", "size":0})

    return {"disk_info": disk_info}


def get_gcard_info():
    pre_strs = os.popen("lspci | grep -i vga").read()
    pattern = re.compile(r'controller: (.+)\n')
    gcard_list = pattern.findall(pre_strs)

    return {"gcard_info": list(map(lambda i: {"caption": i}, gcard_list))}


def get_nic_info():
    nic_info = []
    for line in os.popen("ifconfig"):
        if 'ether' in line:
            nic_info.append({"mac": line.split()[1]})

    if len(nic_info) == 0:
        return {"nic_info": ["error while collecting"]}
    else:
        return {"nic_info": nic_info}


def ping_rtt(ip):
    pre_strs = os.popen("ping %s -c 1" % ip).read()
    print(pre_strs)

    str_list = pre_strs.split("\n")
    rtt = str_list[-2]

    pattern = r"([\d]+.?\d*)"
    re_result = re.search(pattern, rtt)

    return float(re_result.group())
