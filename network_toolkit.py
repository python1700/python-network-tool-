#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import csv
import json
import socket
import subprocess
from queue import Queue, Empty
from datetime import datetime

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QLineEdit, QTextEdit, QLabel,
    QTableWidget, QTableWidgetItem, QHBoxLayout, QCheckBox, QSpinBox, QProgressBar,
    QGroupBox, QTabWidget, QHeaderView, QFileDialog, QMainWindow, QAction, QMessageBox
)
from PyQt5.QtCore import QThread, pyqtSignal, Qt, QTimer
from PyQt5.QtGui import QColor, QTextCursor, QTextCharFormat

# ================================
# Sniffer
# ================================
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw


class SnifferThread(QThread):
    packet_signal = pyqtSignal(object)

    def __init__(self, selected_protocols, ip_filter=""):
        super().__init__()
        self.selected_protocols = [p.lower() for p in selected_protocols]
        self.ip_filter = ip_filter.lower()
        self.running = True

    def run(self):
        sniff(prn=self.packet_callback, stop_filter=lambda x: not self.running)

    def packet_callback(self, packet):
        proto = self.get_protocol(packet).lower()
        src = packet[IP].src if packet.haslayer(IP) else ""
        dst = packet[IP].dst if packet.haslayer(IP) else ""

        if self.selected_protocols and proto not in self.selected_protocols:
            return
        if self.ip_filter and self.ip_filter not in src.lower() and self.ip_filter not in dst.lower():
            return

        self.packet_signal.emit(packet)

    def get_protocol(self, packet):
        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            if packet.haslayer(DNS):
                return "DNS"
            else:
                return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(Raw) and b"HTTP" in packet[Raw].load:
            return "HTTP"
        else:
            return packet.summary().split()[0]

    def stop(self):
        self.running = False


class SnifferApp(QWidget):
    protocol_colors = {
        "TCP": QColor(200, 255, 200),
        "UDP": QColor(200, 200, 255),
        "ICMP": QColor(255, 200, 200),
        "HTTP": QColor(255, 255, 200),
        "DNS": QColor(200, 255, 255)
    }

    def __init__(self):
        super().__init__()
        self.sniffer_thread = None
        self.packet_list = []
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        ip_label = QLabel("Filter by IP (optional):")
        self.ip_input = QLineEdit()
        layout.addWidget(ip_label)
        layout.addWidget(self.ip_input)

        proto_layout = QHBoxLayout()
        self.tcp_cb = QCheckBox("TCP")
        self.udp_cb = QCheckBox("UDP")
        self.icmp_cb = QCheckBox("ICMP")
        self.http_cb = QCheckBox("HTTP")
        self.dns_cb = QCheckBox("DNS")
        for cb in [self.tcp_cb, self.udp_cb, self.icmp_cb, self.http_cb, self.dns_cb]:
            proto_layout.addWidget(cb)
        layout.addLayout(proto_layout)

        self.start_btn = QPushButton("Start Sniffing")
        self.start_btn.clicked.connect(self.start_sniff)
        layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop Sniffing")
        self.stop_btn.clicked.connect(self.stop_sniff)
        layout.addWidget(self.stop_btn)

        self.save_btn = QPushButton("Save to CSV")
        self.save_btn.clicked.connect(self.save_csv)
        layout.addWidget(self.save_btn)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Time", "Source", "Destination", "Protocol", "Length"])
        layout.addWidget(self.table)

        self.setLayout(layout)

    def start_sniff(self):
        selected_protocols = []
        if self.tcp_cb.isChecked():
            selected_protocols.append("TCP")
        if self.udp_cb.isChecked():
            selected_protocols.append("UDP")
        if self.icmp_cb.isChecked():
            selected_protocols.append("ICMP")
        if self.http_cb.isChecked():
            selected_protocols.append("HTTP")
        if self.dns_cb.isChecked():
            selected_protocols.append("DNS")

        ip_filter = self.ip_input.text()

        self.sniffer_thread = SnifferThread(selected_protocols, ip_filter)
        self.sniffer_thread.packet_signal.connect(self.add_packet)
        self.sniffer_thread.start()

    def stop_sniff(self):
        if self.sniffer_thread:
            self.sniffer_thread.stop()
            self.sniffer_thread.quit()
            self.sniffer_thread.wait()
            self.sniffer_thread = None

    def add_packet(self, packet):
        row_position = self.table.rowCount()
        self.table.insertRow(row_position)

        time = datetime.now().strftime("%H:%M:%S")
        src = packet[IP].src if packet.haslayer(IP) else "-"
        dst = packet[IP].dst if packet.haslayer(IP) else "-"
        proto = self.sniffer_thread.get_protocol(packet)
        length = len(packet)

        self.table.setItem(row_position, 0, QTableWidgetItem(time))
        self.table.setItem(row_position, 1, QTableWidgetItem(str(src)))
        self.table.setItem(row_position, 2, QTableWidgetItem(str(dst)))
        self.table.setItem(row_position, 3, QTableWidgetItem(proto))
        self.table.setItem(row_position, 4, QTableWidgetItem(str(length)))

        color = self.protocol_colors.get(proto, QColor(255, 255, 255))
        for col in range(5):
            self.table.item(row_position, col).setBackground(color)

        self.packet_list.append([time, src, dst, proto, length])

    def save_csv(self):
        if not self.packet_list:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "", "CSV Files (*.csv)")
        if path:
            with open(path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Time", "Source", "Destination", "Protocol", "Length"])
                writer.writerows(self.packet_list)


# ================================
# Ping
# ================================
class LivePingApp(QWidget):
    def __init__(self):
        super().__init__()
        self.timer = QTimer()
        self.timer.timeout.connect(self.ping)
        self.ping_count = 0
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        self.label = QLabel("Enter IP or Domain:")
        layout.addWidget(self.label)

        self.input = QLineEdit()
        layout.addWidget(self.input)

        self.start_button = QPushButton("Start Ping")
        self.start_button.clicked.connect(self.start_ping)
        layout.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Ping")
        self.stop_button.clicked.connect(self.stop_ping)
        layout.addWidget(self.stop_button)

        self.result = QTextEdit()
        self.result.setReadOnly(True)
        layout.addWidget(self.result)

        self.setLayout(layout)

    def start_ping(self):
        host = self.input.text()
        if not host:
            self.result.setText("Please enter an IP or domain.")
            return
        self.result.clear()
        self.host = host
        self.ping_count = 0
        self.timer.start(2000)

    def stop_ping(self):
        self.timer.stop()

    def ping(self):
        self.ping_count += 1
        try:
            output = subprocess.check_output(
                ["ping", "-c", "1", self.host],
                stderr=subprocess.STDOUT,
                universal_newlines=True
            )
            self.append_text(output.strip(), success=True)
        except subprocess.CalledProcessError as e:
            self.append_text(e.output.strip() if e.output else "Ping failed.", success=False)

    def append_text(self, text, success=True):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = f"[{self.ping_count}] {now} - {text}"
        cursor = self.result.textCursor()
        cursor.movePosition(QTextCursor.End)
        fmt = QTextCharFormat()
        fmt.setForeground(QColor("green") if success else QColor("red"))
        cursor.setCharFormat(fmt)
        cursor.insertText(message + "\n")
        self.result.setTextCursor(cursor)
        self.result.ensureCursorVisible()


# ================================
# Port Scanner (from port scanner.py)
# ================================
try:
    import openpyxl
    HAVE_OPENPYXL = True
except:
    HAVE_OPENPYXL = False

try:
    from scapy.all import sr1, IP as ScapyIP, ICMP as ScapyICMP, TCP as ScapyTCP, conf as ScapyConf
    HAVE_SCAPY = True
except:
    HAVE_SCAPY = False

COMMON_SERVICES = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    67:"DHCP",68:"DHCP",80:"HTTP",110:"POP3",123:"NTP",
    143:"IMAP",161:"SNMP",443:"HTTPS",3306:"MySQL",3389:"RDP",
    5000:"UPnP"
}

def banner_grab_tcp(ip,port):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        if s.connect_ex((ip,port))!=0: s.close(); return ""
        try:
            if port in (80,8080,8000):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n"%ip.encode())
            else:
                try: s.sendall(b"\r\n")
                except: pass
            data=b""
            try: data=s.recv(2048)
            except: data=b""
            return data.decode(errors="ignore").strip()
        finally: s.close()
    except: return ""

def tcp_is_open(ip,port):
    try: s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); ok=s.connect_ex((ip,port))==0; s.close(); return ok
    except: return False

def udp_probe(ip,port):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        try: s.sendto(b"", (ip, port))
        except: pass
        try: data,_=s.recvfrom(2048); return True,data.decode(errors="ignore").strip()
        except: return None,""
        finally: s.close()
    except: return None,""

def detect_os_simple(ip):
    for p in (80,22,21,443):
        try:
            s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.connect_ex((ip,p))
            try: ttl=s.getsockopt(socket.SOL_IP,socket.IP_TTL)
            except: ttl=None
            s.close()
            if ttl: return "Windows" if ttl>=128 else "Linux/Unix"
        except: pass
    return "Unknown"

def detect_os_precise_with_scapy(ip):
    if not HAVE_SCAPY: return "Scapy not available"
    ScapyConf.verb=0
    try:
        pkt=ScapyIP(dst=ip)/ScapyICMP(); resp=sr1(pkt,timeout=2)
        if resp is None: resp=sr1(ScapyIP(dst=ip)/ScapyTCP(dport=80,flags="S"),timeout=2)
        if resp is None: return "Unknown"
        ttl=getattr(resp,"ttl",None)
        if ttl: return "Windows" if ttl>=128 else "Linux/Unix"
        return "Unknown"
    except: return "Unknown"

class ScanWorker(QThread):
    progress_changed=pyqtSignal(int)
    result_found=pyqtSignal(int,str,str,str)
    finished_signal=pyqtSignal()
    def __init__(self,q,ip,do_tcp,do_udp,total_ports,parent=None):
        super().__init__(parent)
        self.q=q; self.ip=ip; self.do_tcp=do_tcp; self.do_udp=do_udp; self.total_ports=total_ports
        self.scanned=0; self._stopped=False
    def run(self):
        while not self._stopped:
            try: port=self.q.get_nowait()
            except Empty: break
            try:
                if self.do_tcp and tcp_is_open(self.ip,port):
                    banner=banner_grab_tcp(self.ip,port)
                    service=COMMON_SERVICES.get(port,"Unknown")
                    self.result_found.emit(port,"TCP",service,banner)
                if self.do_udp:
                    status,banner=udp_probe(self.ip,port)
                    service=COMMON_SERVICES.get(port,"Unknown")
                    if status is True: self.result_found.emit(port,"UDP",service,banner)
                    elif status is None: self.result_found.emit(port,"UDP",service+" (Possibly Open/Filtered)","")
                self.scanned+=1
                try:
                    self.progress_changed.emit(int(self.scanned/self.total_ports*100))
                except:
                    self.progress_changed.emit(0)
            except:
                self.scanned+=1
                try:
                    self.progress_changed.emit(int(self.scanned/self.total_ports*100))
                except:
                    self.progress_changed.emit(0)
            finally:
                try: self.q.task_done()
                except: pass
        self.finished_signal.emit()
    def stop(self): self._stopped=True

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Port Scanner")
        self.setGeometry(160,90,980,720)
        self._workers=[]; self._queue=None; self._results=[]; self._scapy_enabled=False
        self._theme="light"
        self.init_ui(); self.create_menu()
    def init_ui(self):
        central=QWidget(); layout=QVBoxLayout()
        tgt_group=QGroupBox("Target & Ports"); g_layout=QHBoxLayout()
        self.ip_input=QLineEdit(); self.ip_input.setPlaceholderText("Target IP or hostname")
        self.start_port_spin=QSpinBox(); self.start_port_spin.setRange(1,65535); self.start_port_spin.setValue(1)
        self.end_port_spin=QSpinBox(); self.end_port_spin.setRange(1,65535); self.end_port_spin.setValue(1024)
        g_layout.addWidget(QLabel("Target:")); g_layout.addWidget(self.ip_input)
        g_layout.addWidget(QLabel("Start Port:")); g_layout.addWidget(self.start_port_spin)
        g_layout.addWidget(QLabel("End Port:")); g_layout.addWidget(self.end_port_spin)
        tgt_group.setLayout(g_layout); layout.addWidget(tgt_group)
        opts_group=QGroupBox("Options"); o_layout=QHBoxLayout()
        self.tcp_chk=QCheckBox("TCP"); self.tcp_chk.setChecked(True)
        self.udp_chk=QCheckBox("UDP"); self.threads_spin=QSpinBox(); self.threads_spin.setRange(1,500); self.threads_spin.setValue(100)
        o_layout.addWidget(self.tcp_chk); o_layout.addWidget(self.udp_chk); o_layout.addWidget(QLabel("Threads:")); o_layout.addWidget(self.threads_spin)
        opts_group.setLayout(o_layout); layout.addWidget(opts_group)
        btn_layout=QHBoxLayout()
        self.start_btn=QPushButton("Start Scan"); self.start_btn.setStyleSheet("background-color:#4caf50;color:white;padding:8px;"); self.start_btn.clicked.connect(self.start_scan)
        self.stop_btn=QPushButton("Stop"); self.stop_btn.setStyleSheet("background-color:#f44336;color:white;padding:8px;"); self.stop_btn.clicked.connect(self.stop_scan)
        self.clear_btn=QPushButton("New Scan"); self.clear_btn.setStyleSheet("background-color:#2196f3;color:white;padding:8px;"); self.clear_btn.clicked.connect(self.reset_ui)
        btn_layout.addWidget(self.start_btn); btn_layout.addWidget(self.stop_btn); btn_layout.addWidget(self.clear_btn)
        layout.addLayout(btn_layout)
        self.progress=QProgressBar(); self.progress.setRange(0,100); self.progress.setValue(0); layout.addWidget(self.progress)
        self.table=QTableWidget(0,5); self.table.setHorizontalHeaderLabels(["Port","Proto","Service","Banner","OS Hint"]); self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table)
        self.status=QTextEdit(); self.status.setReadOnly(True); self.status.setFixedHeight(110); layout.addWidget(self.status)
        save_layout=QHBoxLayout()
        self.save_txt_btn=QPushButton("Save TXT"); self.save_txt_btn.clicked.connect(self.save_as_txt)
        self.save_csv_btn=QPushButton("Save CSV"); self.save_csv_btn.clicked.connect(self.save_as_csv)
        self.save_json_btn=QPushButton("Save JSON"); self.save_json_btn.clicked.connect(self.save_as_json)
        self.save_xlsx_btn=QPushButton("Save XLSX"); self.save_xlsx_btn.clicked.connect(self.save_as_xlsx)
        save_layout.addWidget(self.save_txt_btn); save_layout.addWidget(self.save_csv_btn); save_layout.addWidget(self.save_json_btn); save_layout.addWidget(self.save_xlsx_btn)
        layout.addLayout(save_layout)
        central.setLayout(layout); self.setCentralWidget(central)
    def create_menu(self):
        menubar=self.menuBar(); file_menu=menubar.addMenu("File"); new_action=QAction("New Scan",self); new_action.triggered.connect(self.reset_ui); exit_action=QAction("Exit",self); exit_action.triggered.connect(self.close)
        file_menu.addAction(new_action); file_menu.addSeparator(); file_menu.addAction(exit_action)
        help_menu=menubar.addMenu("Help"); about_action=QAction("About",self); about_action.triggered.connect(self.show_about); help_menu.addAction(about_action)
    def append_status(self,text): self.status.append(text)
    def reset_ui(self):
        self.stop_scan(); self.table.setRowCount(0); self._results=[]; self.progress.setValue(0); self.status.clear(); self.append_status("Ready for new scan.")
    def show_about(self): QMessageBox.information(self,"About","Advanced Port Scanner\nLight Theme\nPyQt5 GUI")
    def start_scan(self):
        target=self.ip_input.text().strip()
        if not target: QMessageBox.warning(self,"Input error","Enter target IP/hostname."); return
        try: target_ip=socket.gethostbyname(target)
        except Exception as e: QMessageBox.warning(self,"Error",f"Cannot resolve target: {e}"); return
        start_p=self.start_port_spin.value(); end_p=self.end_port_spin.value()
        if start_p>end_p: QMessageBox.warning(self,"Input error","Start port must <= End port."); return
        do_tcp=self.tcp_chk.isChecked(); do_udp=self.udp_chk.isChecked()
        if not do_tcp and not do_udp: QMessageBox.warning(self,"Input error","Select TCP or UDP."); return
        threads_count=self.threads_spin.value(); q=Queue()
        for p in range(start_p,end_p+1): q.put(p)
        total_ports=end_p-start_p+1; self.table.setRowCount(0); self._results=[]; self.progress.setValue(0)
        self.append_status(f"Scanning {target_ip} ports {start_p}-{end_p} TCP={do_tcp} UDP={do_udp}")
        oshint=detect_os_precise_with_scapy(target_ip) if self._scapy_enabled else detect_os_simple(target_ip)
        self.append_status(f"OS hint: {oshint}")
        self._workers=[]
        for _ in range(max(1,threads_count)):
            worker=ScanWorker(q,target_ip,do_tcp,do_udp,total_ports)
            worker.progress_changed.connect(self.progress.setValue)
            worker.result_found.connect(self.on_result)
            worker.finished_signal.connect(self.on_worker_finished)
            worker.start(); self._workers.append(worker)
        self._queue=q; self.start_btn.setEnabled(False)
    def stop_scan(self):
        for w in getattr(self,"_workers",[]):
            try: w.stop()
            except: pass
        self.append_status("Stopping scan...")
    def on_result(self,port,proto,service,banner):
        row=self.table.rowCount(); self.table.insertRow(row)
        os_hint=""
        lowb=(banner or "").lower()
        if "windows" in lowb: os_hint="Windows (banner)"
        elif any(k in lowb for k in ("linux","ubuntu","debian","centos")): os_hint="Linux (banner)"
        items=[QTableWidgetItem(str(port)),QTableWidgetItem(proto),QTableWidgetItem(service),QTableWidgetItem(banner or ""),QTableWidgetItem(os_hint)]
        color=Qt.green if proto=="TCP" else Qt.cyan
        for it in items: it.setForeground(color)
        for i,it in enumerate(items): self.table.setItem(row,i,it)
        self._results.append({"port":port,"proto":proto,"service":service,"banner":banner or "","os_hint":os_hint})
    def on_worker_finished(self):
        if not any(w.isRunning() for w in self._workers): self.append_status("Scan complete."); self.start_btn.setEnabled(True)
    def save_as_txt(self):
        if not self._results: QMessageBox.information(self,"No results","No results to save."); return
        path,_=QFileDialog.getSaveFileName(self,"Save as TXT","","Text files (*.txt)");
        if not path: return
        try:
            with open(path,"w",encoding="utf-8") as f:
                for r in sorted(self._results,key=lambda x:x["port"]):
                    f.write(f'{r["port"]:<6} {r["proto"]:<4} {r["service"]:<12} {r["os_hint"]} {r["banner"]}\n')
            QMessageBox.information(self,"Saved",f"Saved to {path}")
        except Exception as e: QMessageBox.warning(self,"Error",f"Could not save: {e}")
    def save_as_csv(self):
        if not self._results: QMessageBox.information(self,"No results","No results to save."); return
        path,_=QFileDialog.getSaveFileName(self,"Save as CSV","","CSV files (*.csv)");
        if not path: return
        try:
            with open(path,"w",encoding="utf-8") as f:
                f.write("port,proto,service,os_hint,banner\n")
                for r in sorted(self._results,key=lambda x:x["port"]):
                    b=r["banner"].replace("\n"," ").replace(","," ")
                    f.write(f'{r["port"]},{r["proto"]},{r["service"]},{r["os_hint"]},{b}\n')
            QMessageBox.information(self,"Saved",f"Saved to {path}")
        except Exception as e: QMessageBox.warning(self,"Error",f"Could not save: {e}")
    def save_as_json(self):
        if not self._results: QMessageBox.information(self,"No results","No results to save."); return
        path,_=QFileDialog.getSaveFileName(self,"Save as JSON","","JSON files (*.json)")
        if not path: return
        try:
            with open(path,"w",encoding="utf-8") as f: json.dump(sorted(self._results,key=lambda x:x["port"]),f,indent=2,ensure_ascii=False)
            QMessageBox.information(self,"Saved",f"Saved to {path}")
        except Exception as e: QMessageBox.warning(self,"Error",f"Could not save: {e}")
    def save_as_xlsx(self):
        if not self._results: QMessageBox.information(self,"No results","No results to save."); return
        if not HAVE_OPENPYXL: QMessageBox.warning(self,"Missing","openpyxl required for Excel"); return
        path,_=QFileDialog.getSaveFileName(self,"Save as Excel","","Excel files (*.xlsx)")
        if not path: return
        try:
            wb=openpyxl.Workbook(); ws=wb.active; ws.title="Scan Results"; ws.append(["port","proto","service","os_hint","banner"])
            for r in sorted(self._results,key=lambda x:x["port"]): ws.append([r["port"],r["proto"],r["service"],r["os_hint"],r["banner"]])
            wb.save(path); QMessageBox.information(self,"Saved",f"Saved to {path}")
        except Exception as e: QMessageBox.warning(self,"Error",f"Could not save: {e}")


# ================================
# Main Application (Tabs)
# ================================
class MainApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Toolkit")
        self.setGeometry(100, 100, 1000, 700)

        tabs = QTabWidget()
        tabs.addTab(SnifferApp(), "Sniffer")
        tabs.addTab(LivePingApp(), "Ping")
        tabs.addTab(MainWindow(), "Port Scanner")

        self.setCentralWidget(tabs)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainApp()
    window.show()
    sys.exit(app.exec_())
