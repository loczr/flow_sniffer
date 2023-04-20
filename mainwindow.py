from PyQt5.QtCore import QThread,pyqtSignal,QTimer,Qt,QSize
from PyQt5.QtWidgets import (QApplication,QTableWidget,QTableWidgetItem,QLineEdit,
        QHBoxLayout, QLabel, QComboBox,QProgressBar,QPushButton,QSpacerItem,QSizePolicy,QTextBrowser,QTextEdit,
        QVBoxLayout, QWidget,QTabWidget)

from datetime import  datetime
from pc_info import *
import pyqtgraph as pg
from scapy.all import *
from scapy import all as cap
from scapy.all import IP
from scapy.all import Padding
from scapy.all import Raw
from scapy.utils import hexdump
from scapy.arch.common import compile_filter
from collections import Counter
from scapy.all import sniff
from PyQt5.QtWidgets import QApplication,QWidget,QToolTip,QTableWidgetItem
from mtablewidget import MyTableWidget
from queue import Queue
from flush_percent import flush_percent,update_net_io
from PyQt5 import QtCore

class Signal(QtCore.QObject):

    recv = pyqtSignal(object)


class ImageTools(QWidget):

    def __init__(self):
        super(ImageTools, self).__init__()
        self.default_dev =""
        self.send_data = []

        self.queue = Queue()

        self.resize_value = QSize(200,100)

        self.dev_dict = pc_info.net_dev(self)
        self.tab1_layout()
        self.create_net_info_layout(self.dev_dict)
        self.create_cpu_memory_layout()

        self.create_tabwidget()
        rightlayout = QVBoxLayout()

        leftlayout = QHBoxLayout()
        leftlayout.addLayout(self.tab_layour)
        mainlayout = QHBoxLayout()
        mainlayout.addLayout(rightlayout)
        mainlayout.addLayout(leftlayout)

        #----------------------------------------
        self.send_data = [0.0]*15
        self.capturedPacketsSize = 0
        self.packet_counts = Counter()
        self.stopflag = False
        self.pkt = None
        self.tab_count_row = 0
        self.queue = Queue()
        self.signal = Signal()
        self.counter = 0
        self.signal.recv.connect(self.update_packet)
        #------------------------------------------


        self.net_dev_combobox.currentIndexChanged.connect(self.change_dev_info) #下拉框选择网卡绑定事件


        self.setLayout(mainlayout)
        self.setWindowTitle("QTtest")
        self.resize(800,400)

        self.start_update_net_io = update_net_io()
        self.start_update_net_io.start()

        self.start_filter_button.clicked.connect(self.start_done)
        self.stop_filter_button.clicked.connect(self.stop_sniff_done)
        self.refresh_table_button.clicked.connect(self.refresh_table)

        self.stop_filter_button.setEnabled(False)


        self.packet_table.cellPressed.connect(self.update_content)
        self.tab_filter.editingFinished.connect(self.validate_filter)
        proxy =self.proxy

        # 按钮开始操作
    def start_done(self):
        self.start_filter_button.setEnabled(False)
        self.stop_filter_button.setEnabled(True)
        self.tab_filter.setEnabled(False)
        self.tab_count_return()
        self.refresh_table_button.setEnabled(False)
        # self.packet_table.cellPressed.connect(self.update_content)
        self.sniff_start(self.sniff_combox.currentText(), self.tab_filter.text())

    # 按钮结束操作
    def stop_sniff_done(self):
        self.stop_filter_button.setEnabled(False)
        self.start_filter_button.setEnabled(True)
        self.tab_filter.setEnabled(True)
        self.refresh_table_button.setEnabled(True)
        #self.start_update_sniff.stopflag_t()
        self.stopflag_t()


    def sniff_start(self,iface,filter):
        self.filter = filter
        self.iface = iface
        self.pkt = AsyncSniffer(iface= iface,filter=filter, prn=self.sniff_action)
        self.pkt.start()
        self.timer = QTimer()
        self.timer.timeout.connect(self.TimeOutOpration)
        self.timer.start(1000)

    def sniff_action(self,packet):
        self.capturedPacketsSize += len(packet)
        #        packet = self.queue.get(False)

        if not self.pkt:
            return
        self.queue.put(packet)
        self.signal.recv.emit(1)

    def get_packet_layers(self, packet):
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            yield layer
            counter += 1

    def tab_count_return(self):
        return self.tab_count(self.packet_table.rowCount())


    def tab_count(self,row):
        self.tab_count_row = row

    def tab_setItem(self,row,timestamp,sd,info):
        self.packet_table.insertRow(row)
        self.packet_table.setItem(row,0,QTableWidgetItem(str(row+1)))
        self.packet_table.setItem(row,1,QTableWidgetItem(timestamp))
        self.packet_table.setItem(row,2,QTableWidgetItem(sd))
        self.packet_table.setItem(row,3,info)


    def update_packet(self,packet):
        packet = self.queue.get(False)
        if not packet:
            return

        if self.packet_table.rowCount() >= 1024:
            self.packet_table.removeRow(0)

        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        # No.
        self.counter += 1
        self.packet_table.setItem(row, 0, QTableWidgetItem(str(self.counter)))

        # Time
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        #elapse = time.time() - self.start_time
        self.packet_table.setItem(row, 1, QTableWidgetItem(timestamp))

        # source
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
        else:
            src = packet.src
            dst = packet.dst

        sd ="%s-->%s"%(src,dst)
        self.packet_table.setItem(row, 2, QTableWidgetItem(sd))
        #
        # #destination
        # self.packet_table.setItem(row, 3, QTableWidgetItem(dst))

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
        self.packet_table.setItem(row, 3, item)
        #self.tab_setItem(self.tab_count_row,timestamp, sd,item)
        #self.tab_count_row += 1

    def update_content(self, item):

        item = self.packet_table.item(x, 3)
        if not hasattr(item, 'packet'):
            return
        packet = item.packet

        self.packet_dump.setText(hexdump(packet, dump=True))


        self.packet_layer.setText("")
        for layer in self.get_packet_layers(packet):
            item.layer = layer
            self.packet_layer.append(layer.name)

            for name, value in layer.fields.items():
                self.packet_layer.append(f"{name}: {value}")

    def TimeOutOpration(self):
        #self.queue.clear()
        self.update_pg_value()
        self.capturedPacketsSize = 0
    def update_pg_value(self):
        self.send_data[:-1] = self.send_data[1:]
        self.send_data[-1] = float('%.1f' % (self.capturedPacketsSize*8 / 1024))
        #self._data_sin.emit(self.send_data)
        self.sniff_data(self.send_data)
    def stopflag_t(self):

        if self.pkt :
            self.pkt.stop()
            self.pkt = None
            self.timer.stop()
        else:
            pass


#输入框判断样式
    def validate_filter(self):
        exp = self.tab_filter.text().strip()
        if not exp:
            self.tab_filter.setStyleSheet('')
            self.start_filter_button.setEnabled(True)
            return

        try:
            compile_filter(filter_exp=exp)
            # 输入框背景变绿
            self.tab_filter.setStyleSheet('QLineEdit { background-color: rgb(33, 186, 69);}')
            self.start_filter_button.setEnabled(True)
        except Exception:
            # 将输入框背景变红
            self.start_filter_button.setEnabled(False)
            self.tab_filter.setStyleSheet('QLineEdit { background-color: rgb(219, 40, 40);}')
            return

    def change_dev_info(self):
        dev_dict = self.dev_dict
        self.a=""
        for i in dev_dict[self.net_dev_combobox.currentText()]:
            #if isinstance(dev_dict[self.default_dev][i],list):
            if i == "mac":
                self.a = self.a +i+":"+dev_dict[self.net_dev_combobox.currentText()][i]+'\n'
            else:
                for x in dev_dict[self.net_dev_combobox.currentText()][i]:
                    self.a = self.a +i+":"+x+'\n'
        self.net_info_label.setText(self.a)

    def create_net_info_layout(self,dev_dict):
        self.net_dev_combobox = QComboBox()
        self.a = ""
        for dev in dev_dict:
            self.net_dev_combobox.addItem(dev)
            self.sniff_combox.addItem(dev)

        self.default_dev = list(dev_dict.keys())[0]
        self.net_dev_label = QLabel().setText(self.default_dev)#net_dev_name
        self.net_info_label = QLabel()
        for i in dev_dict[self.default_dev]:
            #if isinstance(dev_dict[self.default_dev][i],list):
            if i == "mac":
                self.a = self.a +i+":"+dev_dict[self.default_dev][i]+'\n'
            else:
                for x in dev_dict[self.default_dev][i]:
                    self.a = self.a +i+":"+x+'\n'

        self.net_info_label.setText(self.a)
        self.net_info_label.resize(self.resize_value)
        self.net_dev_combobox.resize(self.resize_value)
        self.net_dev_combobox.setMaximumWidth(300)
        self.net_info_label.setMaximumWidth(300)
        self.dev_info_lyout =QVBoxLayout()

        self.dev_info_lyout.addWidget(self.net_dev_combobox,Qt.AlignTop)
        self.dev_info_lyout.addWidget(self.net_info_label,Qt.AlignTop)

    def cpu_useage_info(self):
        self.cpu_label = QLabel()
        self.cpu_label.setText("CPU ")
        self.cpu_label.setMaximumSize(QSize(40,25))
        self.cpu_percent =QProgressBar()
        self.cpu_percent.setMaximumWidth(250)
        # self.cpu_percent.setStyleSheet('''
        # QProgressBar::chunk{background-color: #F44336;}
        # QProgressBar {text-align: center; /*进度值居中*/}
        # ''')
        self.cpu_percent.setValue(pc_info.cpu_usage_info(self))

        def cpu_fulsh(value):
            self.cpu_percent.setValue(value)

        self.c_thead = flush_percent()
        self.c_thead._flush_cpu_sin.connect(cpu_fulsh)
        self.c_thead.start()


        self.cpu_percent.setTextVisible(False)
        self.cpu_label.resize(self.resize_value)
        self.cpu_percent.resize(self.resize_value)

        self.cpu_layout = QHBoxLayout()
        self.cpu_layout.addWidget(self.cpu_label,Qt.AlignTop)
        self.cpu_layout.addWidget(self.cpu_percent,Qt.AlignTop)

    def v_memory_info(self):
        self.v_memory_label = QLabel()
        self.v_memory_label.setText("内存")
        self.v_memory_label.setMaximumSize(QSize(40,25))
        self.v_memory_percent =QProgressBar()
        self.v_memory_percent.setMaximumWidth(250)

        def v_fulsh(value):
            self.v_memory_percent.setValue(value)

        self.v_thead = flush_percent()
        self.v_thead._flush_v_sin.connect(v_fulsh)
        self.v_thead.start()


        self.v_memory_percent.setValue(int(pc_info.virtual_memory(self)[2]))
        self.v_memory_percent.setTextVisible(False)
        self.v_memory_label.resize(self.resize_value)
        self.v_memory_percent.resize(self.resize_value)
        self.v_layout = QHBoxLayout()
        self.v_layout.addWidget(self.v_memory_label,Qt.AlignTop)
        self.v_layout.addWidget(self.v_memory_percent,Qt.AlignTop)

    def create_cpu_memory_layout(self):
        self.cpu_useage_info()
        self.v_memory_info()
        self.cpu_memory_layout =QVBoxLayout()
        self.cpu_memory_layout.addLayout(self.cpu_layout)
        self.cpu_memory_layout.addLayout(self.v_layout)

    def create_net_io_layout(self):

        self.pw = pg.PlotWidget(self)
        self.pw.setGeometry(1,1,300,150)
        self.pw.setMaximumWidth(300)

        self.pw.setBackground("w")
        pg.setConfigOptions(antialias=True)
        pg.setConfigOption('background', '#FFFFFF')
        pg.setConfigOption('foreground', 'k')

        self.send_data = [0] * 60
        self.recv_data = [0] * 60

        self.send = self.pw.plot(self.send_data, pen=(0, 0, 200),name="dev_send_kbps")
        self.recv = self.pw.plot(self.recv_data, pen=(0, 128, 0),name="dev_recv_kbps")

        self.pw.setXRange(0, 60)

        self.net_io_layout =QVBoxLayout()
        self.net_io_layout.addWidget(self.pw)

    def sniff_data(self,data):
        self.p.setData(data)

    def tab_text_data(self,data):
        self.tab_text.append(data)

    def refresh_table(self):
        self.packet_table.setRowCount(0)
        self.packet_table.clearContents()

    def enter_item_slot(self, item):
        self.tool_tip = item.text()
        print("self.tool_tip:", self.tool_tip)

    def tab1_layout(self):
        self.tab3 = QWidget()
        self.layout = QVBoxLayout()
        spacerItem = QSpacerItem(20,40,QSizePolicy.Minimum,QSizePolicy.Expanding)

        self.sniff_combox = QComboBox()
        self.sniff_combox.setMaximumWidth(150)

        #sniff_net_flow_graph

        self.win = pg.GraphicsLayoutWidget(self,show=True)
        self.win.setGeometry(1,1,300,150)
        self.win.setMaximumHeight(200)
        self.win.setBackground("w")

        pg.setConfigOptions(antialias=True)
        pg.setConfigOption('background', '#FFFFFF')
        pg.setConfigOption('foreground', 'k')
        vLine = pg.InfiniteLine(angle=90,movable=False)
        hLine = pg.InfiniteLine(angle=0,movable=False)
        self.plot1 = self.win.addPlot(row=1, col=0)
        self.plot1.setXRange(0,15)
        #self.plot1.showGrid(x=True)
        self.plot1.setLabel('left',units="Kbps")
        self.plot1.setLabel('bottom','time',units='s')
        self.p = self.plot1.plot(pen = "g")
        self.plot1.addItem(vLine,ignoreBounds=True)
        self.plot1.addItem(hLine,ignoreBounds=True)
        vb = self.plot1.vb
        # label = pg.LabelItem(justify="left")
        # self.win.addItem(label)


        def mouseMoveEvent(evt) :
            pos = evt[0]
            if self.plot1.sceneBoundingRect().contains(pos):
                mousePoint = vb.mapSceneToView(pos)
                self.plot1.setTitle("<span style='font-size: 10pt;color: red'>Kbps=%0.1f</span>" % (mousePoint.y()))
                # label.setText(
                #     "<span style='font-size: 14pt'>x=%0.1f,   <span style='color: red'>y1=%0.1f</span>" % (
                #     mousePoint.x(), mousePoint.y()))
                vLine.setPos(mousePoint.x())
                hLine.setPos(mousePoint.y())

        self.proxy = pg.SignalProxy(self.plot1.scene().sigMouseMoved, rateLimit=60, slot=mouseMoveEvent)


        #self.packet_table = QTableWidget()
        self.packet_table = MyTableWidget()
        self.packet_table.setColumnCount(4)
        self.packet_table.setHorizontalHeaderLabels(['NO.','time','src-->dst','info'])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        self.packet_table.verticalHeader().setVisible(False)

        self.packet_table.itemEntered.connect(self.enter_item_slot)


        self.filter_layout = QHBoxLayout()

        self.tab_filter = QLineEdit()
        self.tab_filter.setMinimumWidth(250)
        self.tab_filter.setMaximumHeight(24)

        self.start_filter_button = QPushButton()
        self.start_filter_button.setText("start")

        self.stop_filter_button = QPushButton()
        self.stop_filter_button.setText("stop")

        self.refresh_table_button = QPushButton()
        self.refresh_table_button.setText("refresh")


        self.filter_layout.addWidget(self.sniff_combox)
        self.filter_layout.addWidget(self.tab_filter)
        self.filter_layout.addWidget(self.start_filter_button)
        self.filter_layout.addWidget(self.stop_filter_button)
        self.filter_layout.addWidget(self.refresh_table_button)


        self.pg_windows_layout = QVBoxLayout()
        self.pg_windows_layout.addWidget(self.win)

        self.layout.addLayout(self.filter_layout)
        self.layout.addWidget(self.packet_table)

        self.layout.addLayout(self.pg_windows_layout)
        self.tab3.setLayout(self.layout)

    def create_tabwidget(self):
        self.tabwidget = QTabWidget(self)
        self.tabwidget.setMinimumWidth(600)

        self.tabwidget.addTab(self.tab3,"test")

        self.tab_layour=QHBoxLayout()
        self.tab_layour.addWidget(self.tabwidget)

if __name__ == '__main__':
    import sys
    app = QApplication(sys.argv)
    screenshot = ImageTools()
    screenshot.show()
    sys.exit(app.exec_())