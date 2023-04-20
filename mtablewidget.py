from PyQt5.QtWidgets import QTableWidget,QAbstractItemView
from PyQt5.QtWidgets import QApplication,QWidget,QToolTip
from PyQt5.QtWidgets import QHeaderView
from PyQt5.QtCore import pyqtSignal,QEvent,Qt,QRect
from PyQt5.QtGui import QCursor
import traceback

from scapy.all import *
from scapy import all as cap
from scapy.all import IP
from scapy.all import Padding
from scapy.all import Raw
from scapy.utils import hexdump



class MyTableWidget(QTableWidget):
  update_table_tooltip_signal = pyqtSignal(object)

  def __init__(self):
    super(MyTableWidget, self).__init__()
    self.ini_table()

  def ini_table(self):
    """---------初始化表格的常用选项(按需修改)------------"""
    QTableWidget.resizeColumnsToContents(self)
    QTableWidget.resizeRowsToContents(self)

    self.setEditTriggers(QAbstractItemView.NoEditTriggers) #设置整行选择
    """------------关键代码--------------"""
    self.installEventFilter(self)
    self.setMouseTracking(True)
    # 绑定槽函数
    self.itemEntered.connect(self.enter_item_slot)


  # 获得鼠标进入的单元格对应的QTableWidgetItem对象
  def enter_item_slot(self, item):
    #print(item)
    #item.setToolTip(item.packet)
    self.tool_tip =""
    str1 = ""
    packet = item.packet
    #self.tool_tip = hexdump(packet,dump=True)
    #self.tool_tip =item.text()
    #print("self.tool_tip:", self.tool_tip)

    #self.packet_layer.setText("")
    for layer in self.get_packet_layers(packet):
      item.layer = layer
      #self.packet_layer.append(layer.name)
      str1 +="\n"+layer.name

      for name, value in layer.fields.items():
        str1 += "\n" + f"{name}:{value}"
        #self.packet_layer.append(f"{name}: {value}")
    self.tool_tip = str1



  def get_packet_layers(self, packet):
    counter = 0
    while True:
      layer = packet.getlayer(counter)
      if layer is None:
        break
      yield layer
      counter += 1

  # def enter_item_slot(self, item):
  #
  #   item = self.packet_table.item(x, 3)
  #   if not hasattr(item, 'packet'):
  #     return
  #   packet = item.packet
  #
  #   self.tool_tip.setText(hexdump(packet, dump=True))
  #
  #   self.packet_layer.setText("")
  #   for layer in self.get_packet_layers(packet):
  #     item.layer = layer
  #     self.packet_layer.append(layer.name)
  #
  #     for name, value in layer.fields.items():
  #       self.packet_layer.append(f"{name}: {value}")

  def eventFilter(self, object, event):
    try:
      if event.type() == QEvent.ToolTip and self.tool_tip != None:
        #print("self.tool_tip:", self.tool_tip)
        self.setCursor(Qt.ArrowCursor)
        print("当前鼠标位置为:", event.pos())
        # 设置提示气泡显示范围矩形框,当鼠标离开该区域则ToolTip消失
        rect = QRect(event.pos().x(), event.pos().y(), 30, 10)  # QRect(x,y,width,height)
        #设置QSS样式
        self.setStyleSheet(
          """QToolTip{border:10px;
             border-top-left-radius:5px;
             border-top-right-radius:5px;
             border-bottom-left-radius:5px;
             border-bottom-right-radius:5px;
             background:#4F4F4F;
             color:#00BFFF;
             font-size:18px;
             font-family:"微软雅黑";
          }""")
        QApplication.processEvents()
        # 在指定位置展示ToolTip
        QToolTip.showText(QCursor.pos(), self.tool_tip, self, rect, 300000)



        self.tool_tip = None  # 重设tool_tip
        """
        showText(QPoint, str, QWidget, QRect, int)
        #############参数详解###########
        #QPoint指定tooptip显示的绝对坐标,QCursor.pos()返回当前鼠标所在位置
        #str为设定的tooptip
        #QWidget为要展示tooltip的控件
        #QRect指定tooltip显示的矩形框范围,当鼠标移出该范围,tooltip隐藏,使用该参数必须指定Qwidget!
        #int用于指定tooltip显示的时长(毫秒)
        """
      return QWidget.eventFilter(self, object, event)
    except Exception as e:
      traceback.print_exc()




