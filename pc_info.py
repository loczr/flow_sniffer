import time

import psutil

class pc_info():
    def net_dev(self):
        def netmask(netmask):
            b = ""
            for num in netmask.split('.'):
                temp = str(bin(int(num)))[2:]
                b = b + temp
            return len("".join(str(b.split('0')[0:1])))
        self.dev = psutil.net_if_addrs() #返回一个dict，key为网卡名称，dict内嵌列表，列表为网卡详细信息
        net_info = {}
        for i in self.dev:
            net_info[i]={}
            net_info[i]['mac'] =""
            net_info[i]['ipv4_addr']=[]
            net_info[i]['ipv6_addr']=[]
            for x in self.dev[i]:
                if x[0]==-1:
                    net_info[i]['mac']= x[1]
                elif x[0] == 2:
                    net_info[i]['ipv4_addr'].append(x[1]+'/'+str(netmask(x[2])))
                elif x[0] ==23:
                    net_info[i]['ipv6_addr'].append(x[1])

        return net_info

    def cpu_usage_info(self):
        return psutil.cpu_percent(interval=1)

    def virtual_memory(self):
        v = psutil.virtual_memory()
        virual_total = ('%.1f' %(v.total/1024**3))+'G'
        virual_used = ('%.1f' %(v.used/1024**3))+'G'
        virual_percent = v.percent
        return virual_total,virual_used,virual_percent

    def disk_info(self):
        disk_usage_info={}
        disk = psutil.disk_partitions()
        for d in disk:
            if d.fstype:
                disk_usage_info[d.device]=[]
                disk_total = ('%.1f' % (psutil.disk_usage(d.device).total / 1024 ** 3)) + 'G'
                disk_used = ('%.1f' % (psutil.disk_usage(d.device).used / 1024 ** 3)) + 'G'
                disk_percent = psutil.disk_usage(d.device).percent
                disk_usage_info[d.device].append(disk_total)
                disk_usage_info[d.device].append(disk_used)
                disk_usage_info[d.device].append(disk_percent)
        return disk_usage_info

    def net_io(self):
        old = psutil.net_io_counters()
        time.sleep(1)
        new = psutil.net_io_counters()
        sent_Kbps = ('%.1f' % ((new.bytes_sent - old.bytes_sent) * 8 / 1024))
        recv_Kbps = ('%.1f' % ((new.bytes_recv - old.bytes_recv) * 8 / 1024))
        return sent_Kbps,recv_Kbps
        print(sent_Kbps,recv_Kbps)

# if __name__ == '__main__':
#     a = pc_info()
#     print(list(a.net_dev().keys())[0])
#


