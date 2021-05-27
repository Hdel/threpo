import platform
import win32com
import wmi


class CollectInfo(object):

    def __init__(self):
        # as written in docs
        self.wmi_obj = wmi.WMI()
        self.wmi_service_obj = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        self.wmi_service_connector = self.wmi_service_obj.ConnectServer(".", "root\cimv2")

    def collect_normal(self):
        resource_info = {}

        # get different hardware information
        # including cpu, ram, disk, nic and gcard
        # cannot get performance information here
        resource_info.update(self.get_cpu_info())
        resource_info.update(self.get_ram_info())
        resource_info.update(self.get_disk_info())
        resource_info.update(self.get_nic_info())
        resource_info.update(self.get_gcard_info())

        for item in resource_info:
            # elements must be sorted
            # or may not pass the integrity check
            resource_info[item].sort(key=str)

        # return a sorted info dict
        return resource_info

    # get cpu caption and core
    def get_cpu_info(self):
        cpu_lists = self.wmi_obj.Win32_Processor()

        cpu_info = []
        for cpu in cpu_lists:
            cpu_info.append({"name": cpu.Name, 'core': cpu.NumberOfCores})

        return {'cpu_info': cpu_info}

    # get ram info: size, manufacturer and serial number
    def get_ram_info(self):
        ram_info = []
        ram_list = self.wmi_service_connector.ExecQuery("Select * from Win32_PhysicalMemory")
        for ram in ram_list:
            item_data = {
                "size": int(int(ram.Capacity) / (1024 ** 2)),
                "manufacturer": ram.Manufacturer,
                "sn": ram.SerialNumber,
            }
            ram_info.append(item_data)
        return {"ram_info": ram_info}

    # def get_baseboard_info(self):
    #     sn = self.wmi_obj.Win32_BaseBoard()[0].SerialNumber
    #     return {'baseboard_info': {'sn': sn}}

    # get disk info: caption, serial number, size
    def get_disk_info(self):
        disk_info = []
        for disk in self.wmi_obj.Win32_DiskDrive():  # 每块硬盘都要获取相应信息
            item_data = dict()
            item_data['name'] = disk.Model
            item_data['sn'] = disk.SerialNumber
            item_data['size'] = int(int(disk.Size) / (1024 ** 3))
            disk_info.append(item_data)

        return {'disk_info': disk_info}

    # get nic info: mac
    def get_nic_info(self):
        nic_info = []
        adapters = self.wmi_service_connector.ExecQuery("SELECT * FROM Win32_NetworkAdapter")
        for nic in adapters:
            # many adapters can be fetched by Win32_NetworkConfiguration
            # but real physical network adapter has PNPDeviceID that starts with "PCI"
            if nic.MACAddress is not None and nic.PNPDeviceID.startswith("PCI"):
                nic_info.append(nic.MACAddress)

        return {'nic_info': nic_info}

    # get gcard info: caption
    def get_gcard_info(self):
        gcard_list = self.wmi_service_connector.ExecQuery("SELECT * FROM Win32_VideoController")
        gcard_info = []

        for gcard in gcard_list:
            gcard_info.append(gcard.Name)

        return {"gcard_info": gcard_info}


# 连接地址：pc-bp18rn0tqu85a1600-public.rwlb.rds.aliyuncs.com
# 端口：3306
# 数据库名称：polardb_mysql_13045ydo
# 账号：lab_1919287857
# 密码：8068d4c15259_#@Aa


if __name__ == "__main__":
    data = CollectInfo().collect_normal()
    print(data)
