from PyQt5.QtCore import QThread,pyqtSignal
from pc_info import *


class flush_percent(QThread):
    _flush_cpu_sin = pyqtSignal(object)
    _flush_v_sin = pyqtSignal(object)

    def run(self):
        while True:
            time.sleep(0.5)
            self._flush_cpu_sin.emit(int(pc_info.cpu_usage_info(self)))
            self._flush_v_sin.emit(int(pc_info.virtual_memory(self)[2]))

class update_net_io(QThread):
    _send_sin=pyqtSignal(object,object)
    _recv_sin=pyqtSignal(object)

    def __init__(self):
        super(update_net_io,self).__init__()
        self.a = [0] * 60
        self.b = [0] * 60


    def run(self):
        while True:
            time.sleep(1)
            self.a[:-1] = self.a[1:]
            self.b[:-1] = self.b[1:]
            # data[:-1] = data[1:]
            a, b = pc_info.net_io(self)
            self.a[-1] = float(a)
            self.b[-1] = float(b)
            self._send_sin.emit(self.a, self.b)