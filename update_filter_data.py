from PyQt5.QtCore import QThread,pyqtSignal,QTimer
from PyQt5 import QtCore
from PyQt5.QtWidgets import QTableWidgetItem
from scapy.all import *
from scapy.all import IP
from scapy.all import Padding
from scapy.all import Raw
from collections import Counter
from queue import Queue


class Signal(QtCore.QObject):

    recv = pyqtSignal(object)

class update_filter_data(QThread):
    _data_sin = pyqtSignal(object)
    _text_sin = pyqtSignal(object)
    _tab_count_sin = pyqtSignal(object)
    _tab_sin = pyqtSignal(object,object,object,object)

    def __init__(self):
        super(update_filter_data, self).__init__()

        self.send_data = [0.0]*15
        self.capturedPacketsSize = 0
        self.packet_counts = Counter()
        self.stopflag = False
        self.pkt = None
        self.tab_count_row = 0
        self.queue = Queue()
        self.signal = Signal()
        self.signal.recv.connect(self.update_packet)

    def stopflag_t(self):

        if self.pkt :
            self.pkt.stop()
            self.pkt = None
            self.timer.stop()
        else:
            pass


    def update_pg_value(self):
        self.send_data[:-1] = self.send_data[1:]
        self.send_data[-1] = float('%.1f' % (self.capturedPacketsSize*8 / 1024))
        self._data_sin.emit(self.send_data)


    def sniff_start(self,iface,filter):
        self.filter = filter
        self.iface = iface
        self.pkt = AsyncSniffer(iface= iface,filter=filter, prn=self.sniff_action)
        self.pkt.start()
        self.timer = QTimer()
        self.timer.timeout.connect(self.TimeOutOpration)
        self.timer.start(1000)


    def get_packet_layers(self, packet):
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            yield layer
            counter += 1

    def sniff_action(self,packet):
        self.capturedPacketsSize += len(packet)
        #        packet = self.queue.get(False)

        if not self.pkt:
            return
        self.queue.put(packet)
        self.signal.recv.emit(1)


    def update_packet(self,packet):
        packet = self.queue.get(False)
        if not packet:
            return

        # if self.packetTable.rowCount() >= 1024:
        #     self.packetTable.removeRow(0)

        # row = self.ui.packetTable.rowCount()
        # self.ui.packetTable.insertRow(row)

        # No.
        # self.counter += 1
        # self.ui.packetTable.setItem(row, 0, QTItem(str(self.counter)))

        # Time
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        # self.ui.packetTable.setItem(row, 1, QTItem(f"{elapse:2f}"))

        # source
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
        else:
            src = packet.src
            dst = packet.dst

        # self.ui.packetTable.setItem(row, 2, QTItem(src))
        #
        # # destination
        # self.ui.packetTable.setItem(row, 3, QTItem(dst))

        # protocol

        layer = None
        for var in self.get_packet_layers(packet):
            if not isinstance(var, (Padding, Raw)):
                layer = var

        #protocol = layer.name
        # self.ui.packetTable.setItem(row, 4, QTItem(str(protocol)))

        # length
        #length = f"{len(packet)}"
        # self.ui.packetTable.setItem(row, 5, QTItem(length))

        # info
        info = str(packet.summary())
        item = QTableWidgetItem(info)
        item.packet = packet
        # self.ui.packetTable.setItem(row, 6, item)
        sd ="%s-->%s"%(src,dst)

        self._tab_sin.emit(self.tab_count_row,timestamp,sd,item)
        self.tab_count_row += 1


    def TimeOutOpration(self):
        #self.queue.clear()
        self.update_pg_value()
        self.capturedPacketsSize = 0

    def run(self):
        while self.stopflag:
            self.__del__()