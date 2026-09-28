import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import threading
import queue
import socket
import struct
import time
import ipaddress
import subprocess
import os
import json
import random
import configparser
import urllib.request
import urllib.parse
import http.cookiejar
import ssl
import re

# ============================================================
# Cloudflare & 第三方节点 IP 优选工具
# 扫描停止与 Xray 停止彻底分离版
# 新增：上传 Xray 成功节点到 CF /admin/ADD.txt
# ============================================================

CF_BASE_URL = "https://ngr.ccwu.cc"
CF_LOGIN_URL = CF_BASE_URL + "/login"
CF_ADD_URL = CF_BASE_URL + "/admin/ADD.txt"
CF_PASSWORD_FILE = "cf_upload_config.json"
CF_QUOTA_FILE = "cf_quota_config.json"
CF_QUOTA_REFRESH_SECONDS = 30


class NirSoftCFScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("IP 节点优选工具 - TCP + Xray + 下载测速")
        self.root.geometry("820x520")
        self.root.minsize(680, 400)

        self.running = False
        self.closing = False
        self.scan_start_time = None
        self.scan_elapsed = 0.0

        self.scan_stop_event = threading.Event()
        self.xray_stop_event = threading.Event()

        self.result_queue = queue.Queue()

        self.results = {}
        self.ip_list = []

        self.total = 0
        self.tested = 0
        self.scan_ports = [443]
        self.ip_scan_states = {}
        self.success = 0
        self.next_index = 0
        self.completed_ips = set()
        self.resume_available = False
        self.scan_state_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_state.json")

        self.workers = []
        self.xray_workers = []
        self.xray_task_queue = queue.Queue(maxsize=100)
        self.index_lock = threading.Lock()
        self.xray_lock = threading.Lock()
        self.xray_processes = set()
        self.xray_process_lock = threading.Lock()

        self.xray_process = None
        self.xray_port = 10819

        # UUID / SNI 配置（config.ini 持久保存）
        self.config_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.ini")
        self.node_configs = []
        self.config_index = 0
        self.config_mode = False
        self.saved_subnets = ""
        self.saved_ports = ""
        self.saved_workers = ""

        # Cloudflare 六账户额度读取配置。Token 不写入代码，首次使用时在“CF额度”中填写。
        self.cf_quota_accounts = self.load_cf_quota_config()
        self.cf_quota_refreshing = False
        self.cf_quota_dialog = None
        self.cf_quota_rows = []
        self.load_node_configs()

        # 表头排序状态
        self.sort_column = None
        self.sort_reverse = False

        # 下载测速状态：独立于 TCP/Xray 延迟重测
        self.speed_testing = set()
        self.speed_lock = threading.Lock()

        self.setup_styles()
        self.build_ui()
        self.load_scan_checkpoint()
        if self.saved_subnets:
            self.subnet_entry.delete(0, "end")
            self.subnet_entry.insert(0, self.saved_subnets)

        self.root.after(80, self.update_results)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_styles(self):
        self.style = ttk.Style()
        themes = self.style.theme_names()

        if "vista" in themes:
            self.style.theme_use("vista")
        elif "clam" in themes:
            self.style.theme_use("clam")

        font = ("Microsoft YaHei UI", 9)
        bold = ("Microsoft YaHei UI", 9, "bold")

        self.style.configure(
            "Nir.Treeview",
            font=font,
            rowheight=22,
            background="white",
            fieldbackground="white",
            borderwidth=0,
            relief="flat"
        )

        self.style.configure(
            "Nir.Treeview.Heading",
            font=bold,
            padding=(2, 1)
        )

        self.style.map(
            "Nir.Treeview",
            background=[("selected", "#0078D7")]
        )

    def build_ui(self):
        top = ttk.Frame(self.root, padding=(5, 5, 5, 3))
        top.pack(fill="x")

        # IP、端口、线程统一放到“配置”页面；这里保留隐藏输入控件，
        # 供原有扫描代码继续读取，扫描逻辑完全不变。
        self.subnet_entry = ttk.Entry(top, width=22)
        # 网段不再内置默认值，完全由 config.ini 配置
        self.subnet_entry.pack_forget()

        # 端口、线程改为放在“配置”页面显示；这里仍保留隐藏输入控件，
        # 以兼容原有扫描代码，扫描逻辑完全不变。
        self.port_entry = ttk.Entry(top, width=24)
        self.port_entry.insert(0, self.saved_ports or "443,8443,2053,2083,2087,2096")
        self.port_entry.pack_forget()

        self.worker_entry = ttk.Entry(top, width=5)
        self.worker_entry.insert(0, self.saved_workers or "30")
        self.worker_entry.pack_forget()

        self.start_button = ttk.Button(
            top,
            text="开始",
            width=9,
            command=self.toggle_scan
        )
        self.start_button.pack(side="left", padx=(0, 5))

        self.clear_button = ttk.Button(
            top,
            text="清空列表",
            width=9,
            command=self.clear_scan_list
        )
        self.clear_button.pack(side="left", padx=(0, 5))

        # 新增：上传到 CF
        self.upload_button = ttk.Button(
            top,
            text="上传到 CF",
            width=9,
            command=self.upload_to_cf
        )
        self.upload_button.pack(side="left", padx=(0, 5))

        # CF 账户管理
        self.account_button = ttk.Button(
            top,
            text="CF账户",
            width=8,
            command=self.open_cf_account_manager
        )
        self.account_button.pack(side="left")

        # 六账户 Workers 请求额度
        self.quota_button = ttk.Button(
            top,
            text="配置",
            width=7,
            command=self.open_cf_quota_manager
        )
        self.quota_button.pack(side="left", padx=(5, 0))

        self.config_button = ttk.Button(
            top,
            text="扫描配置",
            width=8,
            command=self.open_node_config
        )
        self.config_button.pack(side="left", padx=(5, 0))

        # ====================================================
        # 表格区域
        # ====================================================
        container = ttk.Frame(self.root, padding=(5, 0, 5, 5))
        container.pack(fill="both", expand=True)

        columns = ("ip", "ports", "tcp", "xray", "speed")

        # 列表区域：Treeview + 内嵌式滚动条
        tree_area = tk.Frame(
            container,
            bd=1,
            relief="sunken",
            highlightthickness=0
        )
        tree_area.pack(fill="both", expand=True)

        self.tree = ttk.Treeview(
            tree_area,
            columns=columns,
            show="headings",
            style="Nir.Treeview",
            selectmode="extended"
        )

        scrollbar = ttk.Scrollbar(
            tree_area,
            orient="vertical",
            command=self.tree.yview
        )

        self.tree.configure(yscrollcommand=scrollbar.set)

        headings = {
            "ip": "IP 地址",
            "ports": "可用端口",
            "tcp": "TCP 延迟",
            "xray": "Xray 真延迟",
            "speed": "下载测速"
        }
        for col, title in headings.items():
            self.tree.heading(
                col,
                text=title,
                command=lambda c=col: self.sort_by_column(c)
            )

        self.tree.column("ip", width=175, anchor="center")
        self.tree.column("ports", width=185, anchor="center")
        self.tree.column("tcp", width=135, anchor="center")
        self.tree.column("xray", width=145, anchor="center")
        self.tree.column("speed", width=145, anchor="center")

        # Treeview 占满整个“文本框”区域；
        # 滚动条覆盖在最右侧边缘，视觉上属于文本框内部。
        self.tree.place(
            x=0,
            y=0,
            relwidth=1.0,
            relheight=1.0
        )

        scrollbar.place(
            relx=1.0,
            rely=0.0,
            x=-1,
            relheight=1.0,
            anchor="ne"
        )
        scrollbar.lift()

        # ====================================================
        # 配置页：直接覆盖整个 IP 结果区域，不创建浮动窗口
        # ====================================================
        self.config_overlay = tk.Frame(
            tree_area,
            bd=0,
            relief="flat",
            bg="#f4f4f4",
            highlightthickness=0
        )
        self.config_overlay.place_forget()

        cfg_title = tk.Label(
            self.config_overlay,
            text="扫描 / 节点配置",
            bg="#f4f4f4",
            font=("Microsoft YaHei UI", 12, "bold")
        )
        cfg_title.pack(anchor="w", padx=18, pady=(18, 12))

        cfg_form = tk.Frame(self.config_overlay, bg="#f4f4f4")
        cfg_form.pack(anchor="nw", padx=18)

        def cfg_label(text, row, col):
            tk.Label(
                cfg_form, text=text, bg="#f4f4f4",
                font=("Microsoft YaHei UI", 9)
            ).grid(row=row, column=col, sticky="e", padx=(0, 8), pady=6)

        # 端口 / 线程：与下面 IP、SNI/UUID 文本框左边严格对齐
        cfg_label("端口", 0, 0)
        self.config_port_entry = ttk.Entry(cfg_form, width=42)
        self.config_port_entry.grid(row=0, column=1, sticky="w", pady=6)

        cfg_label("线程", 0, 2)
        self.config_worker_entry = ttk.Entry(cfg_form, width=6)
        self.config_worker_entry.grid(row=0, column=3, sticky="w", padx=(0, 0), pady=6)

        # IP待扫描 / 网段：大文本框，一行一个网段，支持滚动查看多条网段
        cfg_label("IP待扫描 / 网段", 1, 0)
        cfg_subnet_frame = tk.Frame(cfg_form, bg="#f4f4f4")
        cfg_subnet_frame.grid(row=1, column=1, columnspan=3, sticky="nsew", pady=6)
        self.config_subnet_entry = tk.Text(
            cfg_subnet_frame, width=62, height=6, wrap="none",
            font=("Consolas", 10), undo=True
        )
        self.config_subnet_entry.pack(side="left", fill="both", expand=True)
        cfg_subnet_scroll = ttk.Scrollbar(
            cfg_subnet_frame, orient="vertical",
            command=self.config_subnet_entry.yview
        )
        cfg_subnet_scroll.pack(side="right", fill="y")
        self.config_subnet_entry.configure(yscrollcommand=cfg_subnet_scroll.set)
        self._subnet_placeholder_active = False
        self.config_subnet_entry.bind("<FocusIn>", self._config_subnet_focus_in)
        self.config_subnet_entry.bind("<FocusOut>", self._config_subnet_focus_out)

        # SNI / UUID 合并成一个可滚动的大文本框，一行一条：SNI地址 / UUID号
        cfg_label("SNI / UUID", 2, 0)
        cfg_text_frame = tk.Frame(cfg_form, bg="#f4f4f4")
        cfg_text_frame.grid(row=2, column=1, columnspan=3, sticky="nsew", pady=6)
        self.config_sni_uuid_entry = tk.Text(
            cfg_text_frame, width=62, height=10, wrap="none",
            font=("Consolas", 10), undo=True
        )
        self.config_sni_uuid_entry.pack(side="left", fill="both", expand=True)
        cfg_text_scroll = ttk.Scrollbar(
            cfg_text_frame, orient="vertical", command=self.config_sni_uuid_entry.yview
        )
        cfg_text_scroll.pack(side="right", fill="y")
        self.config_sni_uuid_entry.configure(yscrollcommand=cfg_text_scroll.set)
        self._sni_uuid_placeholder_active = False
        self.config_sni_uuid_entry.bind("<FocusIn>", self._config_sni_uuid_focus_in)
        self.config_sni_uuid_entry.bind("<FocusOut>", self._config_sni_uuid_focus_out)
        self.config_sni_uuid_entry.bind("<ButtonRelease-1>", self._config_select_line)
        self.config_sni_uuid_entry.bind("<Delete>", self._config_delete_current_line)
        self.config_sni_uuid_entry.bind("<Control-v>", self._config_paste_next_line)
        self.config_sni_uuid_entry.bind("<Shift-Insert>", self._config_paste_next_line)

        self.tree.tag_configure("good", foreground="#008000")
        self.tree.tag_configure("normal", foreground="#333333")
        self.tree.tag_configure("testing", foreground="#0000FF")
        self.tree.tag_configure("fail", foreground="#999999")
        self.tree.tag_configure("speed", foreground="#0066CC")

        self.tree.bind("<MouseWheel>", self.fast_scroll)
        self.tree.bind("<Double-Button-1>", self.on_item_double_click)
        self.tree.bind("<Button-3>", self.show_context_menu)

        # ====================================================
        # 状态栏
        # ====================================================
        self.statusbar = ttk.Frame(
            self.root,
            relief="sunken",
            padding=(3, 2)
        )
        self.statusbar.pack(fill="x", side="bottom")

        self.lbl_progress = ttk.Label(
            self.statusbar,
            text="就绪（双击延迟区域重测；双击下载测速区域独立测速）",
            font=("Microsoft YaHei UI", 9)
        )
        self.lbl_progress.pack(side="left", padx=(2, 15))

        # Xray 状态平时不显示，只有真正发生 Xray 错误时才显示。
        self.lbl_xray_status = ttk.Label(
            self.statusbar,
            text="",
            font=("Microsoft YaHei UI", 9)
        )

        # ====================================================
        # 右键菜单
        # ====================================================
        self.context_menu = tk.Menu(self.root, tearoff=0)

        self.context_menu.add_command(
            label="🔄 重新测试此 IP (Xray 对齐)",
            command=self.retest_selected_ip
        )

        self.context_menu.add_separator()

        self.context_menu.add_command(
            label="复制选中 IP",
            command=self.copy_selected_ip
        )

        self.context_menu.add_command(
            label="复制选中 IP:端口",
            command=self.copy_selected_ip_port
        )

        self.context_menu.add_separator()

        self.context_menu.add_command(
            label="复制所有可用 IP",
            command=self.copy_all_valid_ips
        )

        self.context_menu.add_command(
            label="复制所有可用 IP:端口",
            command=self.copy_all_valid_ip_ports
        )

    def fast_scroll(self, event):
        self.tree.yview_scroll(int(-event.delta / 24), "units")
        return "break"

    def toggle_scan(self):
        if self.running:
            self.pause_scan()
        else:
            self.start_scan()

    def pause_scan(self):
        """暂停扫描：保留结果和进度，关闭程序前也会调用这里保存断点。"""
        if not self.running:
            return
        self.scan_stop_event.set()
        self.running = False
        self.scan_elapsed = (
            time.monotonic() - self.scan_start_time
            if self.scan_start_time is not None
            else self.scan_elapsed
        )
        self.start_button.config(text="开始")
        self.set_inputs_state(True)
        self.xray_stop_event.set()
        self.force_stop_all_xray()
        self.force_stop_xray()
        self.upload_button.config(state="normal")
        self.save_scan_checkpoint()
        self.update_status()

    def clear_scan_list(self):
        """清空结果、进度和续扫断点；不会启动扫描。"""
        if self.running:
            self.pause_scan()

        self.results.clear()
        self.ip_list = []
        self.completed_ips.clear()
        self.ip_scan_states.clear()
        self.total = 0
        self.tested = 0
        self.success = 0
        self.next_index = 0
        self.resume_available = False
        self.scan_elapsed = 0.0
        self.scan_start_time = None

        while True:
            try:
                self.result_queue.get_nowait()
            except queue.Empty:
                break
        while True:
            try:
                self.xray_task_queue.get_nowait()
                self.xray_task_queue.task_done()
            except queue.Empty:
                break
        for item in self.tree.get_children():
            self.tree.delete(item)
        try:
            if os.path.isfile(self.scan_state_file):
                os.remove(self.scan_state_file)
        except Exception as e:
            print("删除扫描断点失败:", e)
        self.start_button.config(text="开始")
        self.update_status()

    def load_scan_checkpoint(self):
        """启动时恢复上次未完成的扫描断点。"""
        if not os.path.isfile(self.scan_state_file):
            return
        try:
            with open(self.scan_state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            ips = [str(x).strip() for x in data.get("ip_list", []) if str(x).strip()]
            if not ips or not data.get("completed_ips") is not None:
                return
            self.ip_list = ips
            self.total = len(ips)
            self.completed_ips = set(str(x).strip() for x in data.get("completed_ips", []) if str(x).strip())
            self.tested = len(self.completed_ips)
            self.success = int(data.get("success", 0))
            self.scan_ports = [int(x) for x in data.get("scan_ports", []) if 1 <= int(x) <= 65535] or [443]
            self.scan_elapsed = float(data.get("scan_elapsed", 0.0))
            self.next_index = 0
            while self.next_index < self.total and self.ip_list[self.next_index] in self.completed_ips:
                self.next_index += 1
            self.resume_available = self.tested < self.total

            for row in data.get("results", []):
                ip = str(row.get("ip", "")).strip()
                values = row.get("values", [])
                if ip and values:
                    self.tree.insert("", "end", iid=ip, values=tuple(values), tags=("good",))
            self.update_status()
        except Exception as e:
            print("读取扫描断点失败:", e)

    def save_scan_checkpoint(self):
        """保存未完成扫描的 IP、已完成项和列表结果。"""
        if not self.ip_list or self.tested >= self.total:
            return
        rows = []
        for item_id in self.tree.get_children(""):
            rows.append({
                "ip": str(item_id),
                "values": list(self.tree.item(item_id).get("values", ()))
            })
        data = {
            "ip_list": self.ip_list,
            "completed_ips": sorted(self.completed_ips),
            "success": self.success,
            "scan_ports": self.scan_ports,
            "scan_elapsed": self.scan_elapsed,
            "results": rows,
        }
        try:
            with open(self.scan_state_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            self.resume_available = True
        except Exception as e:
            print("保存扫描断点失败:", e)

    def finish_scan(self):
        """扫描全部完成：清除断点，下一次开始重新扫描。"""
        self.running = False
        self.scan_stop_event.set()
        self.xray_stop_event.set()
        self.force_stop_all_xray()
        self.force_stop_xray()
        self.upload_button.config(state="normal")
        self.start_button.config(text="开始")
        self.set_inputs_state(True)
        self.resume_available = False
        try:
            if os.path.isfile(self.scan_state_file):
                os.remove(self.scan_state_file)
        except Exception:
            pass
        self.update_status()

    def is_port_in_use(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return False
            except socket.error:
                return True

    def get_free_port(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def prepare_xray_port_and_config(self):
        base = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base, "test.json")

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)

            inbounds = config.get("inbounds", [])
            if not inbounds:
                return False

            current_port = int(inbounds[0].get("port", 10819))

            if self.is_port_in_use(current_port):
                new_port = self.get_free_port()
                inbounds[0]["port"] = new_port
                current_port = new_port

                with open(config_path, "w", encoding="utf-8") as f:
                    json.dump(
                        config,
                        f,
                        indent=4,
                        ensure_ascii=False
                    )

            self.xray_port = current_port
            return True

        except Exception as e:
            print("解析 Xray 配置失败:", e)
            return False

    def start_scan(self):
        if self.running:
            return

        # 扫描计时在这里暂不重置。
        # 如果存在未完成断点，后面会继续使用已保存的累计时间。
        # 如果当前正在配置页，直接使用配置页里的最新内容，
        # 不要求用户先点“返回”或“保存”。
        if self.config_mode:
            self._config_read_current()

            raw = self._get_config_subnet_text().strip()
            subnet_value = raw.replace("\n", ",")

            self.subnet_entry.delete(0, "end")
            self.subnet_entry.insert(0, subnet_value)

            self.port_entry.delete(0, "end")
            self.port_entry.insert(0, self.config_port_entry.get().strip())

            self.worker_entry.delete(0, "end")
            self.worker_entry.insert(0, self.config_worker_entry.get().strip())

            # 开始扫描后退出配置页，恢复结果列表。
            self.config_overlay.place_forget()
            self.config_mode = False
            self.tree.lift()
            self.config_button.config(text="配置", command=self.open_node_config)
        else:
            raw = self.subnet_entry.get().strip()

            # 不在配置页时，也把主界面当前的端口/线程/网段同步到配置页，
            # 这样点击“开始打野”即可自动写入 config.ini。
            subnet_lines = [
                x.strip()
                for x in raw.replace("\n", ",").split(",")
                if x.strip()
            ]
            self.config_subnet_entry.delete("1.0", "end")
            self.config_subnet_entry.tag_remove("subnet_placeholder", "1.0", "end")
            self._subnet_placeholder_active = False
            if subnet_lines:
                self.config_subnet_entry.insert("1.0", "\n".join(subnet_lines))
            else:
                self._set_subnet_placeholder()

            self.config_port_entry.delete(0, "end")
            self.config_port_entry.insert(0, self.port_entry.get().strip())
            self.config_worker_entry.delete(0, "end")
            self.config_worker_entry.insert(0, self.worker_entry.get().strip())

        # 开始扫描时自动保存当前配置，无需再手动点击“保存”。
        # 注意：不在配置页时不能重新读取隐藏的 SNI/UUID 文本框，
        # 否则会把已经从 config.ini 读取的 UUID/SNI 清空。
        try:
            self.save_node_configs_file()
        except Exception as e:
            print("自动保存 config.ini 失败:", e)

        parts = [
            x.strip()
            for x in raw.replace("\n", ",").split(",")
            if x.strip()
        ]

        # UUID / SNI 必须由配置页或 config.ini 明确提供；不再允许 test.json 的内置值参与扫描。
        active_node = self.get_active_node_config()
        active_uuid = str(active_node.get("uuid", "")).strip()
        active_sni = str(active_node.get("sni", "")).strip()
        if not active_uuid or not active_sni:
            messagebox.showerror(
                "错误",
                "请先在配置中填写 UUID 和 SNI。\n\n"
                "程序不会再使用 test.json 内置的 UUID / SNI。"
            )
            return

        # 有未完成断点时，继续上次扫描，不重新生成/打乱 IP 列表。
        if self.resume_available and self.ip_list and self.tested < self.total:
            gathered_ips = self.ip_list
        else:
            gathered_ips = []
            try:
                for part in parts:
                    network = ipaddress.ip_network(part, strict=False)
                    hosts = [str(ip) for ip in network.hosts()]
                    if not hosts and network.num_addresses == 1:
                        hosts = [str(network.network_address)]
                    gathered_ips.extend(hosts)
                if not gathered_ips:
                    raise ValueError
            except Exception:
                messagebox.showerror("错误", "IP 或网段格式不正确。")
                return
            random.shuffle(gathered_ips)
            self.ip_list = gathered_ips
            self.completed_ips.clear()
            self.tested = 0
            self.success = 0
            self.next_index = 0
            self.resume_available = False

        try:
            ports = []
            for raw_port in self.port_entry.get().replace("，", ",").split(","):
                raw_port = raw_port.strip()
                if not raw_port:
                    continue
                port = int(raw_port)
                if not 1 <= port <= 65535:
                    raise ValueError
                if port not in ports:
                    ports.append(port)

            if not ports:
                raise ValueError

        except Exception:
            messagebox.showerror(
                "错误",
                "端口格式不正确，请使用逗号分隔，例如：443,8443,2053。"
            )
            return

        try:
            workers = int(self.worker_entry.get().strip())
            workers = min(max(workers, 1), 200)

        except Exception:
            messagebox.showerror(
                "错误",
                "线程数必须为正整数。"
            )
            return

        base = os.path.dirname(os.path.abspath(__file__))

        if (
            not os.path.isfile(os.path.join(base, "xray.exe"))
            or not os.path.isfile(os.path.join(base, "test.json"))
        ):
            messagebox.showerror(
                "错误",
                "程序目录缺失 xray.exe 或 test.json！"
            )
            return

        if not self.prepare_xray_port_and_config():
            messagebox.showerror(
                "错误",
                "无法解析 test.json！"
            )
            return

        self.total = len(self.ip_list)
        if not self.resume_available:
            self.tested = 0
            self.success = 0
            self.next_index = 0
            self.completed_ips.clear()
        else:
            self.next_index = 0
            while self.next_index < self.total and self.ip_list[self.next_index] in self.completed_ips:
                self.next_index += 1

        self.results.clear()
        self.scan_ports = ports
        self.ip_scan_states = {}
        with self.speed_lock:
            self.speed_testing.clear()

        # 清空上一轮遗留结果和 Xray 任务，避免新一轮扫描被旧任务拖慢。
        while True:
            try:
                self.result_queue.get_nowait()
            except queue.Empty:
                break

        while True:
            try:
                self.xray_task_queue.get_nowait()
                self.xray_task_queue.task_done()
            except queue.Empty:
                break

        self.scan_stop_event.clear()
        self.xray_stop_event.clear()

        if not self.resume_available:
            for item in self.tree.get_children():
                self.tree.delete(item)

        self.running = True
        if self.resume_available and self.ip_list and self.tested < self.total:
            # 续扫时保留上次累计计时，不从 0 开始。
            self.scan_start_time = time.monotonic() - max(0.0, self.scan_elapsed)
        else:
            # 新一轮扫描从 0 开始计时。
            self.scan_elapsed = 0.0
            self.scan_start_time = time.monotonic()

        self.start_button.config(text="暂停")
        self.set_inputs_state(False)

        self.upload_button.config(state="disabled")

        self.update_scan_timer()

        self.update_status()

        # Xray 单独使用 10 个 Worker。TCP Worker 不再占着线程等待 Xray，
        # 这样可以持续补位扫描，避免扫描尾部明显降速。
        self.xray_workers = []
        for _ in range(10):
            t = threading.Thread(
                target=self.xray_worker,
                args=(),
                daemon=True
            )
            self.xray_workers.append(t)
            t.start()

        self.workers = []

        for _ in range(workers):
            t = threading.Thread(
                target=self.worker,
                args=(),
                daemon=True
            )

            self.workers.append(t)
            t.start()

    def stop_scan(self):
        # 保留旧调用兼容；现在“停止”统一等同于暂停，不清空进度。
        self.pause_scan()

    def force_stop_xray(self):
        p = self.xray_process
        self.xray_process = None

        if p is not None:
            try:
                if p.poll() is None:
                    p.terminate()

                    try:
                        p.wait(timeout=0.4)
                    except subprocess.TimeoutExpired:
                        p.kill()

            except Exception:
                pass

        try:
            self.root.after(
                0,
                lambda: self.lbl_xray_status.pack_forget()
            )
        except Exception:
            pass

    def _show_xray_error(self, error_text):
        """仅在 Xray 真正报错时显示底部状态；正常运行时保持隐藏。"""
        try:
            self.lbl_xray_status.config(text=f"Xray 错误: {error_text}")
            self.lbl_xray_status.pack(side="left", padx=(0, 8))
        except Exception:
            pass

    # ========================================================
    # UUID / SNI 配置
    # ========================================================

    def load_node_configs(self):
        """从 config.ini 读取网段以及 UUID + SNI 配对配置。"""
        self.node_configs = []
        try:
            if os.path.isfile(self.config_file):
                parser = configparser.ConfigParser()
                parser.read(self.config_file, encoding="utf-8")
                self.saved_subnets = parser.get("Scan", "subnets", fallback="").strip()
                self.saved_ports = parser.get("Scan", "ports", fallback="").strip()
                self.saved_workers = parser.get("Scan", "workers", fallback="").strip()
                sections = []
                for section in parser.sections():
                    if not section.lower().startswith("node"):
                        continue
                    try:
                        number = int(section[4:])
                    except Exception:
                        number = 999999
                    sections.append((number, section))
                sections.sort(key=lambda x: x[0])
                for _, section in sections:
                    uuid = parser.get(section, "uuid", fallback="").strip()
                    sni = parser.get(section, "sni", fallback="").strip()
                    if uuid or sni:
                        self.node_configs.append({"uuid": uuid, "sni": sni})
        except Exception as e:
            print("读取 config.ini 失败:", e)

        if not self.node_configs:
            self.node_configs = [{"uuid": "", "sni": ""}]
        self.config_index = 0

    def save_node_configs_file(self):
        parser = configparser.ConfigParser()
        subnet_lines = [
            x.strip()
            for x in self._get_config_subnet_text().replace("\n", ",").split(",")
            if x.strip()
        ]
        parser["Scan"] = {
            "subnets": ",".join(subnet_lines),
            "ports": self.config_port_entry.get().strip(),
            "workers": self.config_worker_entry.get().strip(),
        }
        for i, item in enumerate(self.node_configs, 1):
            section = f"Node{i}"
            parser[section] = {
                "uuid": str(item.get("uuid", "")).strip(),
                "sni": str(item.get("sni", "")).strip(),
            }
        with open(self.config_file, "w", encoding="utf-8") as f:
            parser.write(f)

    def _set_subnet_placeholder(self):
        """网段文本框为空时显示浅色使用提示；提示文字不参与保存。"""
        try:
            if self.config_subnet_entry.get("1.0", "end-1c").strip():
                self._subnet_placeholder_active = False
                return
            self.config_subnet_entry.delete("1.0", "end")
            self.config_subnet_entry.insert("1.0", "支持多个网段，一行一个网段，例如：172.64.229.0/24")
            self.config_subnet_entry.tag_add("subnet_placeholder", "1.0", "end")
            self.config_subnet_entry.tag_configure("subnet_placeholder", foreground="#aaaaaa")
            self._subnet_placeholder_active = True
        except Exception:
            pass

    def _config_subnet_focus_in(self, event=None):
        if getattr(self, "_subnet_placeholder_active", False):
            self.config_subnet_entry.delete("1.0", "end")
            self.config_subnet_entry.tag_remove("subnet_placeholder", "1.0", "end")
            self._subnet_placeholder_active = False

    def _config_subnet_focus_out(self, event=None):
        if not self.config_subnet_entry.get("1.0", "end-1c").strip():
            self._set_subnet_placeholder()

    def _get_config_subnet_text(self):
        if getattr(self, "_subnet_placeholder_active", False):
            return ""
        return self.config_subnet_entry.get("1.0", "end-1c")

    def _set_sni_uuid_placeholder(self):
        """UUID / SNI 文本框为空时显示浅色使用提示；提示文字不参与保存。"""
        try:
            if self.config_sni_uuid_entry.get("1.0", "end-1c").strip():
                self._sni_uuid_placeholder_active = False
                return
            self.config_sni_uuid_entry.delete("1.0", "end")
            self.config_sni_uuid_entry.insert(
                "1.0",
                "格式：SNI地址 / UUID号，一行一个，例如：x.example.workers.dev / UUID"
            )
            self.config_sni_uuid_entry.tag_add("sni_uuid_placeholder", "1.0", "end")
            self.config_sni_uuid_entry.tag_configure("sni_uuid_placeholder", foreground="#aaaaaa")
            self._sni_uuid_placeholder_active = True
        except Exception:
            pass

    def _config_sni_uuid_focus_in(self, event=None):
        if getattr(self, "_sni_uuid_placeholder_active", False):
            self.config_sni_uuid_entry.delete("1.0", "end")
            self.config_sni_uuid_entry.tag_remove("sni_uuid_placeholder", "1.0", "end")
            self._sni_uuid_placeholder_active = False

    def _config_sni_uuid_focus_out(self, event=None):
        if not self.config_sni_uuid_entry.get("1.0", "end-1c").strip():
            self._set_sni_uuid_placeholder()

    def _config_read_current(self):
        """从多行文本框读取所有节点配置，每行格式：SNI地址 / UUID号。"""
        if not self.node_configs:
            self.node_configs = [{"uuid": "", "sni": ""}]
        if getattr(self, "_sni_uuid_placeholder_active", False):
            raw = ""
        else:
            raw = self.config_sni_uuid_entry.get("1.0", "end-1c")
        lines = raw.splitlines()
        configs = []
        for line in lines:
            value = line.strip()
            if not value:
                continue
            if "/" in value:
                sni, uuid = value.split("/", 1)
                configs.append({"sni": sni.strip(), "uuid": uuid.strip()})
            else:
                configs.append({"sni": value, "uuid": ""})
        if not configs:
            configs = [{"uuid": "", "sni": ""}]
        self.node_configs = configs
        self.config_index = min(self.config_index, len(self.node_configs) - 1)

    def _config_show_current(self):
        if not self.node_configs:
            self.node_configs = [{"uuid": "", "sni": ""}]
            self.config_index = 0
        self.config_sni_uuid_entry.delete("1.0", "end")
        self.config_sni_uuid_entry.tag_remove("sni_uuid_placeholder", "1.0", "end")
        self._sni_uuid_placeholder_active = False
        lines = []
        for item in self.node_configs:
            sni = str(item.get("sni", "")).strip()
            uuid = str(item.get("uuid", "")).strip()
            if sni and uuid:
                lines.append(f"{sni} / {uuid}")
            elif sni:
                lines.append(sni)
            elif uuid:
                lines.append(uuid)
        # 没有任何实际节点时显示浅色使用提示；有节点时始终保留最后一个空白行。
        if lines:
            self.config_sni_uuid_entry.insert("1.0", "\n".join(lines) + "\n")
        else:
            self._set_sni_uuid_placeholder()
        self._config_highlight_line()

    def _config_select_line(self, event=None):
        try:
            index = int(self.config_sni_uuid_entry.index("insert").split(".")[0]) - 1
            self._config_read_current()
            self.config_index = max(0, min(index, len(self.node_configs) - 1))
            self._config_highlight_line()
        except Exception:
            pass

    def _config_highlight_line(self):
        try:
            self.config_sni_uuid_entry.tag_remove("current_node", "1.0", "end")
            line = self.config_index + 1
            self.config_sni_uuid_entry.tag_add("current_node", f"{line}.0", f"{line}.0 lineend")
            self.config_sni_uuid_entry.tag_configure("current_node", background="#e6f2ff")
            self.config_sni_uuid_entry.see(f"{line}.0")
        except Exception:
            pass

    def _config_paste_next_line(self, event=None):
        """SNI/UUID 文本框粘贴时，无论光标在当前行什么位置，都从下一行开始粘贴。"""
        try:
            text = self.config_sni_uuid_entry
            if getattr(self, "_sni_uuid_placeholder_active", False):
                self._config_sni_uuid_focus_in()

            clip = self.root.clipboard_get()
            if clip is None:
                return "break"
            clip = str(clip).replace("\r\n", "\n").replace("\r", "\n")

            # 找到光标所在行，把粘贴点统一放到该行末尾的下一行。
            line = int(text.index("insert").split(".")[0])
            insert_at = f"{line}.end"
            text.mark_set("insert", insert_at)
            text.insert("insert", "\n" + clip)
            self._config_read_current()
            self.config_index = max(0, min(line, len(self.node_configs) - 1))
            self._config_highlight_line()
            return "break"
        except tk.TclError:
            return "break"
        except Exception:
            return "break"

    def _config_delete_current_line(self, event=None):
        """按 Del 键删除光标所在行；若选中了多行，则删除选中的整行。"""
        try:
            text = self.config_sni_uuid_entry
            sel_first = text.index("sel.first")
            sel_last = text.index("sel.last")
            start_line = int(sel_first.split(".")[0])
            end_line = int(sel_last.split(".")[0])
            # 选区刚好落在行尾时，不额外删除下一行。
            if sel_last.endswith(".0") and end_line > start_line:
                end_line -= 1
            text.delete(f"{start_line}.0", f"{end_line + 1}.0")
            self._config_read_current()
            self.config_index = max(0, min(start_line - 1, len(self.node_configs) - 1))
            self._config_highlight_line()
            return "break"
        except tk.TclError:
            pass
        except Exception:
            pass

        try:
            text = self.config_sni_uuid_entry
            line = int(text.index("insert").split(".")[0])
            text.delete(f"{line}.0", f"{line + 1}.0")
            self._config_read_current()
            self.config_index = max(0, min(line - 1, len(self.node_configs) - 1))
            self._config_highlight_line()
        except Exception:
            pass
        return "break"

    def open_node_config(self):
        if self.running:
            messagebox.showinfo("提示", "扫描进行中，请先停止扫描再修改配置。")
            return

        # 进入配置页时，把主窗口当前输入同步进去。
        # 网段支持逗号或换行分隔，进入配置页统一显示为“一行一个网段”。
        subnet_text = self.subnet_entry.get().strip()
        subnet_lines = [x.strip() for x in subnet_text.replace("\n", ",").split(",") if x.strip()]
        self.config_subnet_entry.delete("1.0", "end")
        self.config_subnet_entry.tag_remove("subnet_placeholder", "1.0", "end")
        self._subnet_placeholder_active = False
        if subnet_lines:
            self.config_subnet_entry.insert("1.0", "\n".join(subnet_lines))
        else:
            self._set_subnet_placeholder()

        for entry, value in (
            (self.config_port_entry, self.port_entry.get()),
            (self.config_worker_entry, self.worker_entry.get()),
        ):
            entry.delete(0, "end")
            entry.insert(0, value)

        self.config_mode = True
        self._config_show_current()
        self.config_overlay.place(x=0, y=0, relwidth=1.0, relheight=1.0)
        self.config_overlay.lift()
        self.config_button.config(text="返回", command=self.close_node_config)

    def close_node_config(self):
        # 返回时自动保存当前配置；配置页不再提供单独的“保存”按钮。
        self.config_save()
        self.config_overlay.place_forget()
        self.config_mode = False
        self.tree.lift()
        self.config_button.config(text="配置", command=self.open_node_config)

    def config_prev(self):
        self._config_read_current()
        if self.config_index > 0:
            self.config_index -= 1
            self._config_show_current()

    def config_next(self):
        self._config_read_current()
        if self.config_index < len(self.node_configs) - 1:
            self.config_index += 1
            self._config_show_current()

    def config_save(self):
        try:
            # 文本框内容直接作为全部节点配置保存，无需添加/删除按钮。
            self._config_read_current()

            subnet_lines = [
                x.strip()
                for x in self.config_subnet_entry.get("1.0", "end-1c").replace("\n", ",").split(",")
                if x.strip()
            ]
            self.subnet_entry.delete(0, "end")
            self.subnet_entry.insert(0, ",".join(subnet_lines))

            self.port_entry.delete(0, "end")
            self.port_entry.insert(0, self.config_port_entry.get().strip())
            self.worker_entry.delete(0, "end")
            self.worker_entry.insert(0, self.config_worker_entry.get().strip())

            self.save_node_configs_file()
        except Exception as e:
            messagebox.showerror("保存失败", f"无法保存配置：\n{e}")

    def get_active_node_config(self):
        """返回当前选中的 UUID/SNI；不再回退到 test.json 的内置值。"""
        if not self.node_configs:
            return {"uuid": "", "sni": ""}
        return self.node_configs[min(self.config_index, len(self.node_configs) - 1)]

    def apply_node_config(self, config):
        """把当前 UUID/SNI 应用到 Xray 配置；空值会清除模板中的内置值。"""
        node = self.get_active_node_config()
        uuid = str(node.get("uuid", "")).strip()
        sni = str(node.get("sni", "")).strip()

        outbounds = config.get("outbounds", [])
        if not outbounds:
            return
        outbound = outbounds[0]

        vnext = outbound.get("settings", {}).get("vnext", [])
        if vnext:
            users = vnext[0].get("users", [])
            if users:
                # 无论有没有输入，都覆盖模板里的 UUID，避免偷偷使用 test.json 内置值。
                users[0]["id"] = uuid

        stream = outbound.setdefault("streamSettings", {})
        tls = stream.setdefault("tlsSettings", {})
        # 无论有没有输入，都覆盖模板里的 SNI。
        tls["serverName"] = sni

        if stream.get("network") == "ws":
            ws = stream.setdefault("wsSettings", {})
            headers = ws.setdefault("headers", {})
            # 同样清掉模板可能残留的 Host，避免继续使用内置 SNI。
            headers["Host"] = sni

    def set_inputs_state(self, enabled):
        state = "normal" if enabled else "disabled"

        self.subnet_entry.config(state=state)
        self.port_entry.config(state=state)
        self.worker_entry.config(state=state)

    def write_dynamic_xray_config(self, target_ip, target_port):
        base = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(base, "test.json")

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)

            if "outbounds" in config:
                for outbound in config["outbounds"]:
                    if (
                        "streamSettings" in outbound
                        and "tlsSettings" in outbound["streamSettings"]
                    ):
                        if "allowInsecure" in outbound["streamSettings"]["tlsSettings"]:
                            del outbound["streamSettings"]["tlsSettings"]["allowInsecure"]

            outbounds = config.get("outbounds", [])

            if not outbounds:
                return False

            vnext = (
                outbounds[0]
                .get("settings", {})
                .get("vnext", [])
            )

            if not vnext:
                return False

            vnext[0]["address"] = target_ip
            vnext[0]["port"] = int(target_port)

            stream_settings = outbounds[0].setdefault(
                "streamSettings",
                {}
            )

            if stream_settings.get("network") == "ws":
                ws_settings = stream_settings.setdefault(
                    "wsSettings",
                    {}
                )

                if not ws_settings.get("path"):
                    ws_settings["path"] = "/"

                tls_settings = stream_settings.get("tlsSettings", {})
                server_name = str(
                    tls_settings.get("serverName", "")
                ).strip() if isinstance(tls_settings, dict) else ""
                if server_name:
                    headers = ws_settings.setdefault("headers", {})
                    if not str(headers.get("Host", "")).strip():
                        headers["Host"] = server_name

            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(
                    config,
                    f,
                    indent=4,
                    ensure_ascii=False
                )

            return True

        except Exception as e:
            print("修改 Xray 配置失败:", e)
            return False

    def start_xray(self):
        base = os.path.dirname(os.path.abspath(__file__))
        xray_path = os.path.join(base, "xray.exe")

        self.force_stop_xray()
        time.sleep(0.08)

        self.xray_stop_event.clear()

        try:
            creationflags = getattr(
                subprocess,
                "CREATE_NO_WINDOW",
                0
            )
            startupinfo = None
            if os.name == "nt":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE

            p = subprocess.Popen(
                [
                    xray_path,
                    "run",
                    "-c",
                    "test.json"
                ],
                cwd=base,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
                startupinfo=startupinfo
            )

            self.xray_process = p

        except Exception as e:
            print("启动 Xray 失败:", e)
            self.xray_process = None
            try:
                self.root.after(
                    0,
                    lambda msg=str(e): self._show_xray_error(msg)
                )
            except Exception:
                pass
            return False

        deadline = time.perf_counter() + 2.5

        while time.perf_counter() < deadline:

            if self.xray_stop_event.is_set() or self.closing:
                self.force_stop_xray()
                return False

            p = self.xray_process

            if p is None or p.poll() is not None:
                self.xray_process = None
                return False

            try:
                s = socket.socket(
                    socket.AF_INET,
                    socket.SOCK_STREAM
                )

                s.settimeout(0.1)

                result = s.connect_ex(
                    ("127.0.0.1", self.xray_port)
                )

                s.close()

                if result == 0:
                    return True

            except Exception:
                pass

            time.sleep(0.04)

        self.force_stop_xray()
        return False

    def worker(self):
        # 每个 IP 作为一个任务：依次测试多个端口。
        # TCP 成功的端口进入共享 Xray 队列；一个 IP 最终只产生一条列表记录。
        while not self.scan_stop_event.is_set():
            ip = None
            try:
                with self.index_lock:
                    if self.next_index >= self.total:
                        break
                    index = self.next_index
                    self.next_index += 1
                    if self.ip_list[index] in self.completed_ips:
                        continue

                ip = self.ip_list[index]
                tcp_successes = []

                for target_port in self.scan_ports:
                    if self.scan_stop_event.is_set():
                        break
                    tcp_delay, tcp_ok = self.test_tcp(ip, target_port)
                    if tcp_ok:
                        tcp_successes.append((target_port, tcp_delay))

                if self.scan_stop_event.is_set():
                    break

                with self.index_lock:
                    self.ip_scan_states[ip] = {
                        "pending": len(tcp_successes),
                        "ports": [],
                        "best_delay": None,
                        "best_tcp": None,
                    }

                if not tcp_successes:
                    self.result_queue.put(("ip_done", ip, [], None, None))
                    continue

                for target_port, tcp_delay in tcp_successes:
                    task = (ip, target_port, tcp_delay)
                    while not self.scan_stop_event.is_set():
                        try:
                            self.xray_task_queue.put(task, timeout=0.1)
                            break
                        except queue.Full:
                            continue

            except Exception as e:
                print("TCP 扫描线程异常:", e)
                if ip is not None and not self.scan_stop_event.is_set():
                    self.result_queue.put(("ip_done", ip, [], None, None))

    def xray_worker(self):
        # 10 路独立 Xray。每个 TCP 成功端口分别做真延迟，结果回收到同一个 IP。
        while not self.scan_stop_event.is_set():
            try:
                ip, target_port, tcp_delay = self.xray_task_queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                if self.scan_stop_event.is_set():
                    continue

                xray_delay, xray_ok = self.run_isolated_xray_test(ip, target_port)
                self.result_queue.put((
                    "port_done", ip, target_port, tcp_delay, xray_delay, xray_ok
                ))

            except Exception as e:
                print("Xray Worker 异常:", e)
                try:
                    self.result_queue.put((
                        "port_done", ip, target_port, tcp_delay, None, False
                    ))
                except Exception:
                    pass

            finally:
                try:
                    self.xray_task_queue.task_done()
                except Exception:
                    pass

    def run_isolated_xray_test(self, target_ip, target_port, manual_retest=False):
        """启动独立 Xray 测试。

        v2rayN 日志里的“Unables to find local process name”属于 v2rayN
        TUN/进程识别层，本扫描器不负责修改正在运行的 v2rayN。
        """
        base = os.path.dirname(os.path.abspath(__file__))
        xray_path = os.path.join(base, "xray.exe")
        template_path = os.path.join(base, "test.json")

        try:
            with open(template_path, "r", encoding="utf-8") as f:
                config = json.load(f)

            self.apply_node_config(config)

            # 为每个 Xray 实例分配独立 SOCKS 端口，避免 10 路互相抢端口。
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                socks_port = s.getsockname()[1]

            inbounds = config.get("inbounds", [])
            if not inbounds:
                return None, False
            inbounds[0]["listen"] = "127.0.0.1"
            inbounds[0]["port"] = socks_port

            outbounds = config.get("outbounds", [])
            if not outbounds:
                return None, False

            vnext = outbounds[0].get("settings", {}).get("vnext", [])
            if not vnext:
                return None, False

            vnext[0]["address"] = target_ip
            vnext[0]["port"] = int(target_port)

            stream = outbounds[0].setdefault("streamSettings", {})
            tls = stream.get("tlsSettings")
            if isinstance(tls, dict):
                tls.pop("allowInsecure", None)
            if stream.get("network") == "ws":
                ws_settings = stream.setdefault("wsSettings", {})
                ws_settings.setdefault("path", "/")

                # Cloudflare Worker / WS 节点的关键：
                # 扫描时连接的是候选 IP，但 HTTP Host 仍必须是原节点域名。
                # 仅修改 vnext.address 而不设置 Host，会导致 Cloudflare 路由不到
                # 正确的 Worker，表现为 TCP 正常、Xray 实测全部失败。
                tls_server_name = ""
                if isinstance(tls, dict):
                    tls_server_name = str(tls.get("serverName", "")).strip()
                if tls_server_name:
                    headers = ws_settings.setdefault("headers", {})
                    if not str(headers.get("Host", "")).strip():
                        headers["Host"] = tls_server_name

            config_path = os.path.join(
                base, f"_xray_test_{socks_port}_{threading.get_ident()}.json"
            )
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4, ensure_ascii=False)

            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            log_path = os.path.join(
                base, f"_xray_test_{socks_port}_{threading.get_ident()}.log"
            )
            log_file = open(log_path, "w", encoding="utf-8", errors="ignore")
            p = subprocess.Popen(
                [xray_path, "run", "-c", config_path],
                cwd=base, stdout=log_file, stderr=log_file,
                creationflags=creationflags
            )

            with self.xray_process_lock:
                self.xray_processes.add(p)

            deadline = time.perf_counter() + 2.5
            ready = False
            while time.perf_counter() < deadline:
                if ((self.scan_stop_event.is_set() and not manual_retest) or p.poll() is not None):
                    break
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.08)
                        if s.connect_ex(("127.0.0.1", socks_port)) == 0:
                            ready = True
                            break
                except Exception:
                    pass
                time.sleep(0.03)

            if not ready:
                return None, False

            return self.test_vless_real_ping(socks_port)

        except Exception as e:
            print("独立 Xray 测试失败:", e)
            try:
                self.root.after(
                    0,
                    lambda msg=str(e): self._show_xray_error(msg)
                )
            except Exception:
                pass
            return None, False

        finally:
            try:
                if 'p' in locals() and p is not None:
                    try:
                        if p.poll() is None:
                            p.terminate()
                            try:
                                p.wait(timeout=0.3)
                            except subprocess.TimeoutExpired:
                                p.kill()
                    except Exception:
                        pass
                    try:
                        with self.xray_process_lock:
                            self.xray_processes.discard(p)
                    except Exception:
                        pass
            finally:
                try:
                    if 'log_file' in locals() and log_file is not None:
                        log_file.close()
                except Exception:
                    pass
                try:
                    if 'config_path' in locals() and os.path.isfile(config_path):
                        os.remove(config_path)
                except Exception:
                    pass
                try:
                    if 'log_path' in locals() and os.path.isfile(log_path):
                        os.remove(log_path)
                except Exception:
                    pass

    def stop_process(self, p):
        """停止单个独立 Xray 进程，并从进程集合中移除。"""
        try:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=0.35)
                except subprocess.TimeoutExpired:
                    p.kill()
                    try:
                        p.wait(timeout=0.35)
                    except Exception:
                        pass
        except Exception:
            pass

        with self.xray_process_lock:
            self.xray_processes.discard(p)

    def force_stop_all_xray(self):
        with self.xray_process_lock:
            processes = list(self.xray_processes)
            self.xray_processes.clear()

        for p in processes:
            try:
                if p.poll() is None:
                    p.terminate()
                    try:
                        p.wait(timeout=0.25)
                    except subprocess.TimeoutExpired:
                        p.kill()
            except Exception:
                pass

    def _get_physical_ipv4_interfaces(self):
        """
        Windows 下获取可用于直连公网的本机 IPv4/接口索引。

        不使用 PowerShell，不在程序启动时执行。
        只在第一次 TCP 扫描时缓存一次结果。
        优先选择带网关、处于 UP 状态、且名称不像 TUN/VPN/虚拟网卡的接口。
        """
        if hasattr(self, "_physical_interfaces_cache"):
            return self._physical_interfaces_cache

        result = []

        if os.name != "nt":
            self._physical_interfaces_cache = result
            return result

        try:
            import ctypes
            from ctypes import wintypes

            class IP_ADDR_STRING(ctypes.Structure):
                pass

            IP_ADDR_STRING._fields_ = [
                ("Next", ctypes.POINTER(IP_ADDR_STRING)),
                ("IpAddress", ctypes.c_char * 16),
                ("IpMask", ctypes.c_char * 16),
                ("Context", wintypes.DWORD),
            ]

            class IP_ADAPTER_INFO(ctypes.Structure):
                pass

            IP_ADAPTER_INFO._fields_ = [
                ("Next", ctypes.POINTER(IP_ADAPTER_INFO)),
                ("ComboIndex", wintypes.DWORD),
                ("AdapterName", ctypes.c_char * 260),
                ("Description", ctypes.c_char * 132),
                ("AddressLength", wintypes.UINT),
                ("Address", ctypes.c_ubyte * 8),
                ("Index", wintypes.DWORD),
                ("Type", wintypes.UINT),
                ("DhcpEnabled", wintypes.UINT),
                ("CurrentIpAddress", ctypes.POINTER(IP_ADDR_STRING)),
                ("IpAddressList", IP_ADDR_STRING),
                ("GatewayList", IP_ADDR_STRING),
                ("DhcpServer", IP_ADDR_STRING),
                ("HaveWins", wintypes.BOOL),
                ("PrimaryWinsServer", IP_ADDR_STRING),
                ("SecondaryWinsServer", IP_ADDR_STRING),
                ("LeaseObtained", wintypes.c_ulong),
                ("LeaseExpires", wintypes.c_ulong),
            ]

            GetAdaptersInfo = ctypes.windll.iphlpapi.GetAdaptersInfo
            GetAdaptersInfo.argtypes = [
                ctypes.POINTER(IP_ADAPTER_INFO),
                ctypes.POINTER(wintypes.ULONG),
            ]
            GetAdaptersInfo.restype = wintypes.ULONG

            size = wintypes.ULONG(0)
            ERROR_BUFFER_OVERFLOW = 111
            rc = GetAdaptersInfo(None, ctypes.byref(size))
            if rc != ERROR_BUFFER_OVERFLOW or size.value <= 0:
                self._physical_interfaces_cache = result
                return result

            buffer = ctypes.create_string_buffer(size.value)
            adapter_ptr = ctypes.cast(
                buffer,
                ctypes.POINTER(IP_ADAPTER_INFO)
            )

            rc = GetAdaptersInfo(adapter_ptr, ctypes.byref(size))
            if rc != 0:
                self._physical_interfaces_cache = result
                return result

            blocked_words = (
                "tun", "wintun", "tap", "vpn", "wireguard",
                "v2ray", "clash", "sing-box", "zerotier",
                "tailscale", "virtual", "vmware", "virtualbox",
                "hyper-v", "hyperv", "loopback"
            )

            adapter = adapter_ptr
            while bool(adapter):
                a = adapter.contents

                try:
                    desc = bytes(a.Description).split(b"\0", 1)[0].decode(
                        errors="ignore"
                    ).strip()
                except Exception:
                    desc = ""

                desc_lower = desc.lower()

                # Ethernet=6；其他类型也允许，但虚拟/VPN 名称明确排除。
                if not any(word in desc_lower for word in blocked_words):
                    ip_node = a.IpAddressList
                    gateway_node = a.GatewayList

                    while True:
                        ip_text = bytes(ip_node.IpAddress).split(
                            b"\0", 1
                        )[0].decode(errors="ignore").strip()

                        gateway_text = bytes(gateway_node.IpAddress).split(
                            b"\0", 1
                        )[0].decode(errors="ignore").strip()

                        if ip_text and ip_text != "0.0.0.0":
                            try:
                                addr = ipaddress.ip_address(ip_text)
                                if addr.version == 4 and not addr.is_loopback:
                                    result.append({
                                        "ip": ip_text,
                                        "gateway": gateway_text,
                                        "index": int(a.Index),
                                        "description": desc,
                                    })
                            except Exception:
                                pass

                        if not ip_node.Next:
                            break
                        ip_node = ip_node.Next.contents

                        if gateway_node.Next:
                            gateway_node = gateway_node.Next.contents

                if not a.Next:
                    break
                adapter = a.Next

            # 有网关的接口优先；再优先 Ethernet 类型；最后按原顺序。
            result.sort(
                key=lambda x: (
                    0 if x.get("gateway") and x["gateway"] != "0.0.0.0" else 1,
                    0 if "ethernet" in x.get("description", "").lower() else 1
                )
            )

        except Exception as e:
            print("获取物理 IPv4 接口失败:", e)
            result = []

        self._physical_interfaces_cache = result
        return result

    def _select_direct_tcp_interface(self):
        """选择一个尽量绕过 TUN/VPN 的真实 IPv4 出口。"""
        interfaces = self._get_physical_ipv4_interfaces()
        if interfaces:
            return interfaces[0]
        return None

    def test_tcp(self, ip, port):
        """
        Windows 直连 TCP 延迟测试。

        关键区别：
        1. 不调用 PowerShell。
        2. 不做启动前网卡检测，因此不会拖慢扫描启动。
        3. Windows 上绑定真实 IPv4，并通过 IP_UNICAST_IF 指定接口。
        4. 使用 perf_counter_ns() 记录 0.1ms 精度。

        目的不是“让数字变大”，而是避免 v2rayN TUN 抢走普通 socket 的路由。
        """
        sock = None
        start_ns = time.perf_counter_ns()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.8)

            # 只在 Windows 下指定真实出口接口。
            # IP_UNICAST_IF = 31。接口索引使用 Windows 要求的网络字节序。
            if os.name == "nt":
                iface = self._select_direct_tcp_interface()
                if iface:
                    try:
                        sock.setsockopt(
                            socket.IPPROTO_IP,
                            31,
                            struct.pack("I", socket.htonl(iface["index"]))
                        )
                    except Exception as e:
                        # 某些 Windows/驱动不支持该选项时仍然尝试绑定本地地址。
                        print("设置 TCP 出口接口失败:", e)

                    try:
                        sock.bind((iface["ip"], 0))
                    except Exception as e:
                        print("绑定真实 IPv4 失败:", e)

            result = sock.connect_ex((ip, port))

            elapsed_ms = (
                time.perf_counter_ns() - start_ns
            ) / 1_000_000.0

            if result == 0:
                return round(elapsed_ms, 1), True

            return None, False

        except Exception:
            return None, False

        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def test_vless_real_ping(self, socks_port=None):
        """Xray real latency test aligned with v2rayN:
        establish SOCKS proxy once, then perform two HTTP requests on the same
        proxy connection and use the lower result. The measured interval starts
        immediately before each HTTP request, matching v2rayN's GetRealPingTime
        approach more closely.
        """
        sock = None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.5)

            if socks_port is None:
                socks_port = self.xray_port

            sock.connect(("127.0.0.1", socks_port))

            # SOCKS5 no-auth negotiation.
            sock.sendall(b"\x05\x01\x00")
            reply = self.recv_exact(sock, 2, 2.0)
            if reply != b"\x05\x00":
                return None, False

            host = "www.gstatic.com"
            request = (
                b"\x05\x01\x00\x03"
                + bytes([len(host)])
                + host.encode("ascii")
                + struct.pack(">H", 80)
            )
            sock.sendall(request)

            reply = self.recv_exact(sock, 4, 3.0)
            if (
                reply is None
                or len(reply) != 4
                or reply[0] != 5
                or reply[1] != 0
            ):
                return None, False

            atyp = reply[3]
            if atyp == 1:
                remain = self.recv_exact(sock, 6, 2.0)
            elif atyp == 3:
                length_data = self.recv_exact(sock, 1, 2.0)
                if not length_data:
                    return None, False
                remain = self.recv_exact(sock, length_data[0] + 2, 2.0)
            elif atyp == 4:
                remain = self.recv_exact(sock, 18, 2.0)
            else:
                return None, False

            if remain is None:
                return None, False

            # Keep the destination connection alive. v2rayN creates one HTTP
            # client and performs two requests, then keeps the lower result.
            http_get = (
                "GET /generate_204 HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                "User-Agent: v2rayN/7.24.9\r\n"
                "Connection: keep-alive\r\n\r\n"
            ).encode("ascii")

            samples = []

            for attempt in range(2):
                start = time.perf_counter()
                sock.sendall(http_get)

                # Read the complete HTTP header. For a 204 response there is
                # normally no body, so header completion is enough and avoids
                # waiting for an artificial body/connection close.
                header = bytearray()
                deadline = time.perf_counter() + 3.5
                while b"\r\n\r\n" not in header:
                    remaining = deadline - time.perf_counter()
                    if remaining <= 0:
                        return None, False
                    sock.settimeout(min(remaining, 1.0))
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    header.extend(chunk)
                    if len(header) > 65536:
                        return None, False

                elapsed = round((time.perf_counter() - start) * 1000)
                if header:
                    samples.append(elapsed)

                if attempt == 0:
                    time.sleep(0.1)

            if samples:
                return min(samples), True

            return None, False

        except Exception:
            return None, False

        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    def recv_exact(self, sock, n, timeout_sec):
        sock.settimeout(timeout_sec)

        data = bytearray()
        start = time.time()

        while len(data) < n:

            if time.time() - start > timeout_sec:
                return None

            try:
                chunk = sock.recv(n - len(data))

                if not chunk:
                    return None

                data.extend(chunk)

            except socket.timeout:
                continue

            except Exception:
                return None

        return bytes(data)

    # ========================================================
    # 下载测速
    # ========================================================

    def socks5_connect(self, socks_port, host, port, timeout=6.0):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect(("127.0.0.1", socks_port))

            # SOCKS5 无认证握手
            sock.sendall(b"\x05\x01\x00")
            reply = self.recv_exact(sock, 2, 2.0)
            if reply != b"\x05\x00":
                raise RuntimeError("SOCKS5 握手失败")

            host_bytes = host.encode("idna")
            if len(host_bytes) > 255:
                raise RuntimeError("目标域名过长")

            request = (
                b"\x05\x01\x00\x03"
                + bytes([len(host_bytes)])
                + host_bytes
                + struct.pack(">H", int(port))
            )
            sock.sendall(request)

            reply = self.recv_exact(sock, 4, timeout)
            if not reply or reply[0] != 5 or reply[1] != 0:
                raise RuntimeError("SOCKS5 连接目标失败")

            atyp = reply[3]
            if atyp == 1:
                remain = self.recv_exact(sock, 6, timeout)
            elif atyp == 3:
                n = self.recv_exact(sock, 1, timeout)
                if not n:
                    raise RuntimeError("SOCKS5 地址异常")
                remain = self.recv_exact(sock, n[0] + 2, timeout)
            elif atyp == 4:
                remain = self.recv_exact(sock, 18, timeout)
            else:
                remain = None

            if remain is None:
                raise RuntimeError("SOCKS5 地址读取失败")

            return sock
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise

    def download_speed_test(self, ip, port, item_id):
        """
        独立 Xray 下载测速。

        修复：
        1. 不再使用 speed.cloudflare.com 的 /__down 接口，改用稳定的
           http://hkg.download.datapacket.com/100mb.bin。
        2. 每次测速都新建独立 Xray + 独立 SOCKS 端口，第二次测速不会复用
           上一次连接。
        3. 使用 HTTP Range，只取前 8 MiB，避免每次下载完整 100 MB。
        4. 只统计 HTTP 正文实际传输时间，不把 Xray 建连时间算进速度。
        5. 必须至少收到 1 MiB 才接受结果，防止只收到几十/几百 KB 就显示
           一个虚高速度。
        """
        with self.speed_lock:
            if item_id in self.speed_testing:
                return
            self.speed_testing.add(item_id)

        process = None
        config_path = None
        sock = None

        try:
            self.root.after(
                0,
                lambda: self.set_speed_cell(item_id, "测速中...")
                if self.tree.exists(item_id) else None
            )

            process, socks_port, config_path = self.create_speed_xray(ip, port)

            if not self.wait_speed_xray_ready(process, socks_port, 5.0):
                raise RuntimeError("Xray 启动失败")

            host = "hkg.download.datapacket.com"
            target_port = 80

            # 每次只测速 8 MiB；服务器实际仍是 100mb.bin。
            test_bytes = 8 * 1024 * 1024
            range_end = test_bytes - 1

            sock = self.socks5_connect(
                socks_port,
                host,
                target_port,
                8.0
            )
            sock.settimeout(5.0)

            request = (
                "GET /100mb.bin HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Range: bytes=0-{range_end}\r\n"
                "User-Agent: CF-IP-Scanner/2.0\r\n"
                "Accept: */*\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")

            sock.sendall(request)

            # ----------------------------------------------------
            # 读取完整 HTTP 响应头
            # ----------------------------------------------------
            header = bytearray()
            header_deadline = time.perf_counter() + 8.0

            while b"\r\n\r\n" not in header:
                if self.closing:
                    raise RuntimeError("程序正在关闭")

                if time.perf_counter() >= header_deadline:
                    raise RuntimeError("等待测速响应超时")

                chunk = sock.recv(16384)
                if not chunk:
                    raise RuntimeError("测速连接提前关闭")

                header.extend(chunk)

                if len(header) > 65536:
                    raise RuntimeError("HTTP 响应头异常")

            pos = header.find(b"\r\n\r\n") + 4
            body = header[pos:]

            header_text = header[:pos].decode(
                "iso-8859-1",
                errors="replace"
            )

            status_line = header_text.split("\r\n", 1)[0]

            try:
                status_code = int(status_line.split()[1])
            except Exception:
                status_code = 0

            if status_code not in (200, 206):
                raise RuntimeError(
                    f"测速服务器返回 HTTP {status_code}"
                )

            # ----------------------------------------------------
            # 正文测速
            #
            # 注意：第一批 body 数据已经在读取响应头时收到，
            # 因此测速计时从这里开始。
            # ----------------------------------------------------
            total_bytes = len(body)
            start_time = time.perf_counter()

            # 只要达到目标大小就结束；如果服务器忽略 Range，
            # Connection: close 仍可让我们只读取自己需要的部分。
            while total_bytes < test_bytes:
                if self.closing:
                    raise RuntimeError("程序正在关闭")

                if time.perf_counter() - start_time >= 15.0:
                    break

                try:
                    chunk = sock.recv(128 * 1024)
                except socket.timeout:
                    continue

                if not chunk:
                    break

                total_bytes += len(chunk)

                # 防止服务器忽略 Range 并一次性返回超过目标的数据。
                if total_bytes > test_bytes:
                    total_bytes = test_bytes

            elapsed = time.perf_counter() - start_time

            # 至少 1 MiB 才认为这次测速有效。
            min_valid_bytes = 1 * 1024 * 1024

            if total_bytes < min_valid_bytes:
                raise RuntimeError(
                    f"测速数据不足：{total_bytes / 1024:.0f} KB"
                )

            if elapsed <= 0:
                raise RuntimeError("测速计时异常")

            speed = total_bytes / elapsed
            text = self.format_speed(speed)

            self.root.after(
                0,
                lambda t=text: self.set_speed_cell(item_id, t)
                if self.tree.exists(item_id) else None
            )

        except Exception as e:
            print(f"下载测速失败 [{ip}:{port}]: {e}")

            self.root.after(
                0,
                lambda: self.set_speed_cell(item_id, "失败")
                if self.tree.exists(item_id) else None
            )

        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

            if process is not None:
                self.stop_process(process)

            if config_path and os.path.isfile(config_path):
                try:
                    os.remove(config_path)
                except Exception:
                    pass

            with self.speed_lock:
                self.speed_testing.discard(item_id)

    def create_speed_xray(self, target_ip, target_port):
        """创建专用于下载测速的独立 Xray。"""
        base = os.path.dirname(os.path.abspath(__file__))
        xray_path = os.path.join(base, "xray.exe")
        template_path = os.path.join(base, "test.json")

        with open(template_path, "r", encoding="utf-8") as f:
            config = json.load(f)

        self.apply_node_config(config)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            socks_port = s.getsockname()[1]

        inbounds = config.get("inbounds", [])
        outbounds = config.get("outbounds", [])
        if not inbounds or not outbounds:
            raise RuntimeError("test.json 缺少 inbounds/outbounds")

        inbounds[0]["listen"] = "127.0.0.1"
        inbounds[0]["port"] = socks_port

        vnext = outbounds[0].get("settings", {}).get("vnext", [])
        if not vnext:
            raise RuntimeError("test.json 缺少 vnext")
        vnext[0]["address"] = target_ip
        vnext[0]["port"] = int(target_port)

        stream = outbounds[0].setdefault("streamSettings", {})
        tls = stream.get("tlsSettings")
        if isinstance(tls, dict):
            tls.pop("allowInsecure", None)
        if stream.get("network") == "ws":
            ws_settings = stream.setdefault("wsSettings", {})
            ws_settings.setdefault("path", "/")
            tls_server_name = ""
            if isinstance(tls, dict):
                tls_server_name = str(tls.get("serverName", "")).strip()
            if tls_server_name:
                headers = ws_settings.setdefault("headers", {})
                if not str(headers.get("Host", "")).strip():
                    headers["Host"] = tls_server_name

        config_path = os.path.join(
            base, f"_xray_speed_{socks_port}_{threading.get_ident()}.json"
        )
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)

        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        startupinfo = None
        if os.name == "nt":
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        try:
            process = subprocess.Popen(
                [xray_path, "run", "-c", config_path],
                cwd=base,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
                startupinfo=startupinfo
            )
        except Exception:
            try:
                os.remove(config_path)
            except Exception:
                pass
            raise

        with self.xray_process_lock:
            self.xray_processes.add(process)

        return process, socks_port, config_path

    def wait_speed_xray_ready(self, process, socks_port, timeout=4.0):
        deadline = time.perf_counter() + timeout
        while time.perf_counter() < deadline:
            if self.closing or process.poll() is not None:
                return False
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.1)
                    if s.connect_ex(("127.0.0.1", socks_port)) == 0:
                        return True
            except Exception:
                pass
            time.sleep(0.03)
        return False

    def format_speed(self, bytes_per_sec):
        if bytes_per_sec >= 1024 * 1024:
            return f"{bytes_per_sec / (1024 * 1024):.2f} MB/s"
        return f"{bytes_per_sec / 1024:.0f} KB/s"

    def set_speed_cell(self, item_id, text):
        if not self.tree.exists(item_id):
            return
        values = list(self.tree.item(item_id)["values"])
        while len(values) < 5:
            values.append("-")
        values[4] = text
        if text == "测速中...":
            tag = "testing"
        elif text == "失败":
            # 测速失败不能反过来把一个 Xray 有效节点标成失败。
            old_tags = self.tree.item(item_id).get("tags", ())
            tag = old_tags[0] if old_tags else "good"
        else:
            tag = "speed"
        self.tree.item(item_id, values=values, tags=(tag,))

    def update_results(self):
        while True:
            try:
                msg = self.result_queue.get_nowait()
            except queue.Empty:
                break

            if not msg:
                continue

            if msg[0] == "ip_done":
                _, ip, ports, best_tcp, best_xray = msg
                self.tested += 1
                if ports:
                    self.success += 1
                    self._display_ip_result(ip, ports, best_tcp, best_xray)
                self.ip_scan_states.pop(ip, None)
                self.completed_ips.add(ip)
                self.save_scan_checkpoint()
                self.update_status()
                continue

            if msg[0] == "port_done":
                _, ip, target_port, tcp_delay, xray_delay, xray_ok = msg
                state = self.ip_scan_states.get(ip)
                if state is None:
                    continue

                state["pending"] -= 1
                if xray_ok and xray_delay is not None:
                    state["ports"].append((target_port, tcp_delay, xray_delay))
                    if (
                        state["best_delay"] is None
                        or xray_delay < state["best_delay"]
                    ):
                        state["best_delay"] = xray_delay
                        state["best_tcp"] = tcp_delay

                if state["pending"] <= 0:
                    self.tested += 1
                    valid = state["ports"]
                    if valid:
                        self.success += 1
                        valid.sort(key=lambda x: x[2])
                        ports = [x[0] for x in valid]
                        self._display_ip_result(
                            ip,
                            ports,
                            state["best_tcp"],
                            state["best_delay"]
                        )
                    self.ip_scan_states.pop(ip, None)
                    self.completed_ips.add(ip)
                    self.save_scan_checkpoint()
                    self.update_status()

        if (
            self.running
            and self.tested >= self.total
            and self.total > 0
        ):
            self.finish_scan()

        self.root.after(80, self.update_results)

    def _display_ip_result(self, ip, ports, tcp_delay, xray_delay):
        values = (
            ip,
            ", ".join(str(p) for p in ports),
            f"{tcp_delay:.1f} ms" if isinstance(tcp_delay, (int, float)) else "-",
            f"{xray_delay} ms" if xray_delay is not None else "失败",
            "测速"
        )

        if not self.tree.exists(ip):
            self.tree.insert(
                "", "end", iid=ip, values=values, tags=("good",)
            )
        else:
            old = list(self.tree.item(ip)["values"])
            speed = old[4] if len(old) >= 5 else "测速"
            values = values[:4] + (speed,)
            self.tree.item(ip, values=values, tags=("good",))

    def update_status(self):
        if self.running:
            state_str = "打野中..."
        elif self.resume_available and self.ip_list and self.tested < self.total:
            state_str = "暂停"
        else:
            state_str = "就绪/完成"

        if self.running and self.scan_start_time is not None:
            elapsed = time.monotonic() - self.scan_start_time
        else:
            elapsed = self.scan_elapsed

        total_seconds = max(0, int(elapsed))
        hours, rem = divmod(total_seconds, 3600)
        minutes, seconds = divmod(rem, 60)
        elapsed_text = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

        self.lbl_progress.config(
            text=(
                f"状态: {state_str} | "
                f"进度: {self.tested}/{self.total} | "
                f"捕获可用节点: {self.success} | "
                f"扫描用时: {elapsed_text}"
            )
        )

    def update_scan_timer(self):
        if self.closing:
            return
        if self.running and self.scan_start_time is not None:
            self.scan_elapsed = time.monotonic() - self.scan_start_time
            self.update_status()
            self.root.after(500, self.update_scan_timer)

    # ========================================================
    # 表头点击排序
    # ========================================================

    def sort_by_column(self, column):
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = False

        items = []
        for iid in self.tree.get_children(""):
            values = self.tree.item(iid)["values"]
            tags = self.tree.item(iid)["tags"]
            items.append((self._sort_key(column, values), iid, values, tags))

        items.sort(key=lambda x: x[0], reverse=self.sort_reverse)
        for index, (_, iid, _, _) in enumerate(items):
            self.tree.move(iid, "", index)

        self._update_heading_indicators(column)

    def _sort_key(self, column, values):
        try:
            if column == "ip":
                parts = str(values[0]).strip().split(".")
                if len(parts) == 4:
                    return tuple(int(p) for p in parts)
                return (999, 999, 999, 999)

            if column == "ports":
                text = str(values[1]).replace("，", ",").strip()
                ports = []
                for p in text.split(","):
                    p = p.strip()
                    if p.isdigit():
                        ports.append(int(p))
                return tuple(sorted(ports)) if ports else (99999,)

            if column == "tcp":
                text = str(values[2]).strip()
                if text.endswith(" ms"):
                    return (0, float(text[:-3].strip()))
                return (1, 99999.0)

            if column == "xray":
                text = str(values[3]).strip()
                if text.endswith(" ms"):
                    return (0, float(text[:-3].strip()))
                return (1, 99999.0)

            if column == "speed":
                text = str(values[4]).strip() if len(values) >= 5 else "-"
                if text.endswith(" MB/s"):
                    return (0, float(text[:-5].strip()) * 1024 * 1024)
                if text.endswith(" KB/s"):
                    return (0, float(text[:-5].strip()) * 1024)
                return (1, 999999999.0)
        except Exception:
            pass
        return (1, 999999999.0)

    def _update_heading_indicators(self, active_column):
        titles = {
            "ip": "IP 地址",
            "ports": "可用端口",
            "tcp": "TCP 延迟",
            "xray": "Xray 真延迟",
            "speed": "下载测速"
        }
        arrow = " ▼" if self.sort_reverse else " ▲"
        for col, title in titles.items():
            self.tree.heading(
                col,
                text=title + (arrow if col == active_column else ""),
                command=lambda c=col: self.sort_by_column(c)
            )

    # ========================================================
    # 双击单独刷新
    # ========================================================

    def on_item_double_click(self, event):
        # 直接以双击位置确定行。第五列只做下载测速，其他列保持原来的延迟重测。
        item_id = self.tree.identify_row(event.y)
        if not item_id:
            return

        self.tree.selection_set(item_id)
        self.tree.focus(item_id)

        column = self.tree.identify_column(event.x)
        if column == "#5":
            values = self.tree.item(item_id)["values"]
            if len(values) < 4:
                return

            ip = str(values[0]).strip()
            port_text = str(values[1]).strip()
            ports = []
            for raw_port in port_text.replace("，", ",").split(","):
                try:
                    p = int(raw_port.strip())
                    if 1 <= p <= 65535 and p not in ports:
                        ports.append(p)
                except Exception:
                    pass

            if not ports:
                return

            # 可用端口已经按 Xray 真延迟排序，第一项为当前最佳端口。
            threading.Thread(
                target=self.download_speed_test,
                args=(ip, ports[0], item_id),
                daemon=True
            ).start()
            return

        self.retest_selected_ip()

    def retest_selected_ip(self):
        selected = self.tree.selection()
        if not selected:
            return

        item_id = selected[0]
        values = self.tree.item(item_id)["values"]
        if not values:
            return

        ip = str(values[0]).strip()
        port_text = str(values[1]).strip() if len(values) > 1 else ""
        ports = []
        for raw in port_text.replace("，", ",").split(","):
            try:
                p = int(raw.strip())
                if 1 <= p <= 65535 and p not in ports:
                    ports.append(p)
            except Exception:
                pass

        if not ports:
            ports = list(self.scan_ports)

        threading.Thread(
            target=self.background_retest_single,
            args=(ip, ports, item_id),
            daemon=True
        ).start()

    def background_retest_single(self, ip, ports, item_id):
        # 重测期间不要把“原来可用的端口”继续显示成当前可用端口，
        # 避免出现“失败 + 五个端口可用”这种矛盾状态。
        self.root.after(
            0,
            lambda: self.tree.item(
                item_id,
                values=(ip, "测试中...", "重新测试中...", "Xray测速中...", "-"),
                tags=("testing",)
            )
        )

        valid = []
        for port in ports:
            tcp_delay, tcp_ok = self.test_tcp(ip, port)
            if not tcp_ok:
                continue
            try:
                xray_delay, xray_ok = self.run_isolated_xray_test(ip, port, manual_retest=True)
            except Exception as e:
                print("独立重测异常:", e)
                xray_delay, xray_ok = None, False
            if xray_ok and xray_delay is not None:
                valid.append((port, tcp_delay, xray_delay))

        if valid:
            valid.sort(key=lambda x: x[2])
            best = valid[0]
            values = (
                ip,
                ", ".join(str(x[0]) for x in valid),
                f"{best[1]} ms",
                f"{best[2]} ms",
                "测速"
            )
            self.root.after(
                0,
                lambda: self.tree.item(item_id, values=values, tags=("good",))
                if self.tree.exists(item_id) else None
            )
        else:
            self.root.after(
                0,
                lambda: self.tree.item(
                    item_id,
                    values=(ip, "无可用端口", "失败", "失败", "-"),
                    tags=("fail",)
                ) if self.tree.exists(item_id) else None
            )

    # ========================================================
    # CF 上传功能
    # ========================================================

    # ========================================================
    # Cloudflare 六账户 Workers 请求额度
    # ========================================================

    def load_cf_quota_config(self):
        """读取额度后台连接配置；客户端不保存六个 Cloudflare Account ID / Token。"""
        base = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base, CF_QUOTA_FILE)
        default = {
            "backend_url": "",
            "username": "",
            "password": "",
            "remember": False,
        }

        try:
            if not os.path.isfile(path):
                return default
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return default
            return {
                "backend_url": str(data.get("backend_url", "")).strip().rstrip("/"),
                "username": str(data.get("username", "")).strip(),
                "password": str(data.get("password", "")),
                "remember": bool(data.get("remember", False)),
            }
        except Exception as e:
            print("读取 CF 额度后台配置失败:", e)
            return default

    def save_cf_quota_config(self, config):
        base = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base, CF_QUOTA_FILE)
        try:
            safe = {
                "backend_url": str(config.get("backend_url", "")).strip().rstrip("/"),
                "username": str(config.get("username", "")).strip(),
                "password": str(config.get("password", "")) if config.get("remember") else "",
                "remember": bool(config.get("remember", False)),
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(safe, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print("保存 CF 额度后台配置失败:", e)
            return False

    def _normalize_cf_quota_backend_url(self, backend_url):
        """额度后台只需要填写域名；内部自动补 https:// 并定位到根地址。"""
        value = str(backend_url or "").strip()
        if not value:
            return ""
        if not re.match(r"^https?://", value, re.I):
            value = "https://" + value
        parsed = urllib.parse.urlsplit(value)
        if not parsed.netloc:
            raise RuntimeError("额度后台地址格式错误，请填写域名，例如：rrx.ccwu.cc")
        return f"{parsed.scheme.lower()}://{parsed.netloc}"

    def _cf_quota_login_and_query(self, backend_url, username, password, progress_callback=None):
        """登录账户1后台，然后由账户1后台统一返回账户1~6额度。"""
        if progress_callback:
            progress_callback("正在登录账户1后台……")
        backend_url = self._normalize_cf_quota_backend_url(backend_url)
        if not backend_url:
            raise RuntimeError("请先填写额度后台地址")
        if not password:
            raise RuntimeError("请先填写后台密码")

        cookie_jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookie_jar)
        )

        # 当前 workers.js 的 /login 按原 CF账户按钮方式只提交 password。
        # 登录名仅作为界面兼容字段，不参与实际登录请求。
        login_data = urllib.parse.urlencode({
            "password": password,
        }).encode("utf-8")

        login_request = urllib.request.Request(
            backend_url + "/login",
            data=login_data,
            method="POST",
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": "CF-IP-Scanner/1.0",
            },
        )

        with opener.open(login_request, timeout=15) as response:
            login_body = response.read().decode("utf-8-sig", errors="replace")

        try:
            login_json = json.loads(login_body)
        except Exception:
            login_json = {}

        if not login_json.get("success"):
            raise RuntimeError("额度后台登录失败，请检查后台地址和密码")

        if progress_callback:
            progress_callback("登录成功，正在读取账户1~6额度……")

        usage_request = urllib.request.Request(
            backend_url + "/admin/get6AccountUsage",
            method="GET",
            headers={
                "Accept": "application/json",
                "User-Agent": "CF-IP-Scanner/1.0",
            },
        )

        # 当前 workers.js 的 admin 接口支持 X-Admin-Password，
        # 这里直接带密码请求，避免 Cookie 在某些环境下没有被正确保留。
        usage_request.add_header("X-Admin-Password", password)

        try:
            with opener.open(usage_request, timeout=20) as response:
                body = response.read().decode("utf-8-sig", errors="replace")
                status_code = response.getcode()
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8-sig", errors="replace").strip()[:300]
            raise RuntimeError(
                f"六账户接口返回 HTTP {e.code}"
                + (f"：{detail}" if detail else "")
            ) from e

        if status_code != 200:
            detail = body.strip()[:300]
            raise RuntimeError(
                f"六账户接口返回 HTTP {status_code}"
                + (f"：{detail}" if detail else "")
            )

        body_clean = body.strip().lstrip("\ufeff")
        if not body_clean:
            raise RuntimeError("六账户接口返回空内容：后台没有返回额度数据")

        try:
            data = json.loads(body_clean)
        except Exception as e:
            detail = body_clean[:300].replace("\r", " ").replace("\n", " ")
            raise RuntimeError(
                f"六账户接口返回的不是有效 JSON：{detail}"
            ) from e
        if not data.get("success"):
            raise RuntimeError(
                str(data.get("error") or data.get("msg") or "六账户额度读取失败")
            )

        accounts = data.get("accounts")
        if not isinstance(accounts, list) or len(accounts) != 6:
            raise RuntimeError("后台没有返回完整的账户1~6数据")

        if progress_callback:
            progress_callback("登录成功，六账户额度读取完成")

        return data

    def open_cf_quota_manager(self):
        """六账户额度配置：直接覆盖主IP列表区域，不创建浮动窗口。"""
        if self.cf_quota_dialog is not None and self.cf_quota_dialog.winfo_exists():
            self.cf_quota_dialog.lift()
            return

        # 直接覆盖主 IP 列表区域
        tree_area = self.tree.master
        dialog = tk.Frame(
            tree_area,
            bd=0,
            relief="flat",
            bg="#f4f4f4",
            highlightthickness=0
        )
        self.cf_quota_dialog = dialog
        dialog.place(relx=0, rely=0, relwidth=1, relheight=1)
        dialog.lift()

        frame = ttk.Frame(dialog, padding=12)
        frame.pack(fill="both", expand=True)

        ttk.Label(
            frame,
            text="CF额度后台",
            font=("Microsoft YaHei UI", 11, "bold")
        ).pack(anchor="w", pady=(0, 8))

        form = ttk.Frame(frame)
        form.pack(fill="x", pady=(0, 10))

        ttk.Label(form, text="后台地址：").grid(row=0, column=0, sticky="e", padx=(0, 6), pady=4)
        backend_saved = str(self.cf_quota_accounts.get("backend_url", "")).strip()
        if not backend_saved:
            backend_saved = "rrx.ccwu.cc"
        elif re.match(r"^https?://", backend_saved, re.I):
            parsed_saved = urllib.parse.urlsplit(backend_saved)
            backend_saved = parsed_saved.netloc or backend_saved
        else:
            backend_saved = backend_saved.split("/", 1)[0]
        backend_var = tk.StringVar(value=backend_saved)
        backend_entry = ttk.Entry(form, textvariable=backend_var, width=58)
        backend_entry.grid(row=0, column=1, columnspan=3, sticky="ew", pady=4)

        ttk.Label(form, text="登录名：").grid(row=1, column=0, sticky="e", padx=(0, 6), pady=4)
        username_var = tk.StringVar(value=self.cf_quota_accounts.get("username", ""))
        username_entry = ttk.Entry(form, textvariable=username_var, width=24)
        username_entry.grid(row=1, column=1, sticky="w", pady=4)

        ttk.Label(form, text="密码：").grid(row=1, column=2, sticky="e", padx=(12, 6), pady=4)
        password_var = tk.StringVar(
            value=self.cf_quota_accounts.get("password", "")
            if self.cf_quota_accounts.get("remember")
            else ""
        )
        password_entry = ttk.Entry(form, textvariable=password_var, width=24, show="*")
        password_entry.grid(row=1, column=3, sticky="w", pady=4)

        remember_var = tk.BooleanVar(value=bool(self.cf_quota_accounts.get("remember")))
        ttk.Checkbutton(
            form,
            text="保存登录信息",
            variable=remember_var
        ).grid(row=2, column=1, sticky="w", pady=(2, 6))

        login_status_var = tk.StringVar(value="登录状态：未登录")
        ttk.Label(
            form,
            textvariable=login_status_var
        ).grid(row=2, column=2, columnspan=2, sticky="w", padx=(12, 0), pady=(2, 6))

        table = ttk.Frame(frame)
        table.pack(fill="both", expand=True)

        headers = ["账户", "今日请求", "今日剩余", "额度", "状态"]
        widths = [12, 18, 18, 15, 16]
        for col, (title, width) in enumerate(zip(headers, widths)):
            ttk.Label(
                table, text=title, anchor="center", width=width
            ).grid(row=0, column=col, padx=2, pady=(0, 6), sticky="ew")

        self.cf_quota_rows = []
        for i in range(6):
            name_var = tk.StringVar(value=f"账户{i + 1}")
            requests_var = tk.StringVar(value="—")
            remain_var = tk.StringVar(value="—")
            limit_var = tk.StringVar(value="—")
            status_var = tk.StringVar(value="未连接")

            ttk.Label(table, textvariable=name_var, anchor="center", width=widths[0]).grid(
                row=i + 1, column=0, padx=2, pady=3
            )
            ttk.Label(table, textvariable=requests_var, anchor="center", width=widths[1]).grid(
                row=i + 1, column=1, padx=2, pady=3
            )
            ttk.Label(table, textvariable=remain_var, anchor="center", width=widths[2]).grid(
                row=i + 1, column=2, padx=2, pady=3
            )
            ttk.Label(table, textvariable=limit_var, anchor="center", width=widths[3]).grid(
                row=i + 1, column=3, padx=2, pady=3
            )
            ttk.Label(table, textvariable=status_var, anchor="center", width=widths[4]).grid(
                row=i + 1, column=4, padx=2, pady=3
            )

            self.cf_quota_rows.append({
                "name": name_var,
                "requests": requests_var,
                "remain": remain_var,
                "limit": limit_var,
                "status": status_var,
            })

        bottom = ttk.Frame(frame)
        bottom.pack(fill="x", pady=(10, 0))

        total_var = tk.StringVar(value="总请求：—    总剩余：—")
        ttk.Label(bottom, textvariable=total_var).pack(side="left")

        def on_close():
            self.cf_quota_dialog = None
            self.cf_quota_refreshing = False
            dialog.destroy()

        refresh_button = ttk.Button(bottom, text="刷新额度", width=11)
        refresh_button.pack(side="right", padx=(6, 0))
        save_button = ttk.Button(bottom, text="保存配置", width=11)
        save_button.pack(side="right", padx=(6, 0))
        ttk.Button(bottom, text="返回", width=9, command=on_close).pack(side="right")

        def save_config():
            config = {
                "backend_url": backend_var.get().strip().rstrip("/"),
                "username": username_var.get().strip(),
                "password": password_var.get(),
                "remember": bool(remember_var.get()),
            }
            if not config["backend_url"]:
                messagebox.showwarning("提示", "请填写额度后台地址。", parent=dialog)
                return
            if self.save_cf_quota_config(config):
                self.cf_quota_accounts = config
                if not config["remember"]:
                    password_var.set("")
                messagebox.showinfo("提示", "额度后台配置已保存。", parent=dialog)
            else:
                messagebox.showerror("错误", "额度后台配置保存失败。", parent=dialog)

        def refresh():
            if self.cf_quota_refreshing:
                return

            backend_url = backend_var.get().strip().rstrip("/")
            username = username_var.get().strip()
            password = password_var.get()

            if not backend_url:
                messagebox.showwarning("提示", "请先填写额度后台地址。", parent=dialog)
                return
            if not password:
                messagebox.showwarning("提示", "请先填写后台密码。", parent=dialog)
                return

            self.cf_quota_accounts = {
                "backend_url": backend_url,
                "username": username,
                "password": password if remember_var.get() else "",
                "remember": bool(remember_var.get()),
            }

            self.cf_quota_refreshing = True
            refresh_button.config(state="disabled")
            login_status_var.set("登录状态：正在登录……")
            total_var.set("正在连接账户1后台并读取账户1~6……")
            for row in self.cf_quota_rows:
                row["status"].set("读取中…")
                row["requests"].set("—")
                row["remain"].set("—")
                row["limit"].set("—")

            def progress_callback(message):
                if dialog.winfo_exists():
                    try:
                        dialog.after(0, lambda m=message: login_status_var.set("登录状态：" + m))
                    except Exception:
                        pass

            threading.Thread(
                target=self._refresh_cf_quota_worker,
                args=(dialog, refresh_button, total_var, backend_url, username, password, progress_callback, login_status_var),
                daemon=True
            ).start()

        refresh_button.config(command=refresh)
        save_button.config(command=save_config)

        # 打开后立即尝试读取一次；之后每 30 秒自动刷新。
        refresh()

    def _refresh_cf_quota_worker(
        self, dialog, refresh_button, total_var,
        backend_url, username, password, progress_callback=None, login_status_var=None
    ):
        try:
            data = self._cf_quota_login_and_query(
                backend_url, username, password, progress_callback=progress_callback
            )
            accounts = data.get("accounts", [])
            total_requests = int(data.get("todayUsedTotal", 0) or 0)
            total_remaining = int(data.get("todayRemainingTotal", 0) or 0)
            results = []

            for i in range(6):
                item = accounts[i] if i < len(accounts) else {}
                used = int(item.get("todayUsed", 0) or 0)
                remain = int(item.get("todayRemaining", 0) or 0)
                limit = int(item.get("todayLimit", 0) or 0)
                results.append((i, used, remain, limit, None))

        except Exception as e:
            results = [(i, None, None, None, str(e)) for i in range(6)]
            total_requests = None
            total_remaining = None

        def apply_results():
            if self.closing:
                return

            for i, used, remain, limit, error in results:
                if i >= len(self.cf_quota_rows):
                    continue
                row = self.cf_quota_rows[i]

                if error:
                    row["status"].set("读取失败")
                    row["requests"].set("—")
                    row["remain"].set("—")
                    row["limit"].set("—")
                    continue

                row["name"].set(f"账户{i + 1}")
                row["requests"].set(f"{used:,}")
                row["remain"].set(f"{remain:,}")
                row["limit"].set(f"{limit:,}")
                row["status"].set("正常" if remain > 0 else "已到上限")

            if total_requests is None:
                error_text = next((x[4] for x in results if x[4]), "未知错误")
                login_status_var.set(f"登录状态：失败 — {error_text}") if login_status_var is not None else None
                total_var.set("连接失败，请检查后台地址 / 登录信息")
            else:
                if login_status_var is not None:
                    login_status_var.set("登录状态：已登录 ✓")
                total_var.set(
                    f"总请求：{total_requests:,}    总剩余：{total_remaining:,}"
                )

            self.cf_quota_refreshing = False
            if refresh_button.winfo_exists():
                refresh_button.config(state="normal")

            # 自动刷新：只在窗口仍存在时继续。
            if dialog.winfo_exists() and not self.closing:
                try:
                    dialog.after(
                        CF_QUOTA_REFRESH_SECONDS * 1000,
                        lambda: refresh_button.invoke()
                        if dialog.winfo_exists() and not self.cf_quota_refreshing
                        else None
                    )
                except Exception:
                    pass

        if dialog.winfo_exists():
            self.root.after(0, apply_results)
        else:
            self.cf_quota_refreshing = False

    def get_cf_account_config(self):
        base = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base, CF_PASSWORD_FILE)

        try:
            if not os.path.isfile(path):
                return {"username": "", "password": ""}

            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            return {
                "username": str(data.get("username", "")),
                "password": str(data.get("password", ""))
            }
        except Exception:
            return {"username": "", "password": ""}

    def get_cf_saved_password(self):
        return self.get_cf_account_config().get("password", "")

    def save_cf_account(self, username, password):
        base = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base, CF_PASSWORD_FILE)

        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(
                    {
                        "username": username,
                        "password": password
                    },
                    f,
                    ensure_ascii=False,
                    indent=2
                )
            return True
        except Exception as e:
            print("保存 CF 账户失败:", e)
            return False

    def save_cf_password(self, password):
        old = self.get_cf_account_config()
        return self.save_cf_account(old.get("username", ""), password)

    def delete_cf_saved_password(self):
        base = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(base, CF_PASSWORD_FILE)

        try:
            if os.path.isfile(path):
                os.remove(path)
        except Exception:
            pass

    def open_cf_account_manager(self):
        """CF账户管理：可切换账户、保存/取消保存本机登录信息。"""
        saved = self.get_cf_account_config()

        dialog = tk.Toplevel(self.root)
        dialog.title("CF 账户管理")
        dialog.resizable(False, False)
        dialog.transient(self.root)

        # 居中到软件主窗口内部，而不是居中到整个屏幕。
        dialog.update_idletasks()
        root_x = self.root.winfo_rootx()
        root_y = self.root.winfo_rooty()
        root_w = self.root.winfo_width()
        root_h = self.root.winfo_height()
        dialog_w = dialog.winfo_width()
        dialog_h = dialog.winfo_height()
        pos_x = root_x + max(0, (root_w - dialog_w) // 2)
        pos_y = root_y + max(0, (root_h - dialog_h) // 2)
        dialog.geometry(f"+{pos_x}+{pos_y}")
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding=15)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="管理账户:").grid(
            row=0, column=0, sticky="e", padx=(0, 8), pady=(0, 10)
        )

        username_var = tk.StringVar(value=saved.get("username", ""))
        username_entry = ttk.Entry(
            frame, textvariable=username_var, width=30
        )
        username_entry.grid(row=0, column=1, pady=(0, 10))

        ttk.Label(frame, text="管理员密码:").grid(
            row=1, column=0, sticky="e", padx=(0, 8), pady=(0, 10)
        )

        password_var = tk.StringVar(value=saved.get("password", ""))
        password_entry = ttk.Entry(
            frame, textvariable=password_var, width=30, show="*"
        )
        password_entry.grid(row=1, column=1, pady=(0, 10))

        save_var = tk.BooleanVar(value=bool(saved.get("password", "")))
        ttk.Checkbutton(
            frame,
            text="保存账户信息到本机",
            variable=save_var
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 5))

        ttk.Label(
            frame,
            text="取消保存会立即删除本机保存的账户信息。",
            foreground="#666666"
        ).grid(row=3, column=0, columnspan=2, sticky="w", pady=(0, 12))

        buttons = ttk.Frame(frame)
        buttons.grid(row=4, column=0, columnspan=2)

        def save_and_close():
            username = username_var.get().strip()
            password = password_var.get().strip()

            if not password:
                messagebox.showwarning(
                    "提示", "管理员密码不能为空。", parent=dialog
                )
                return

            if save_var.get():
                if not self.save_cf_account(username, password):
                    messagebox.showerror(
                        "错误", "账户信息保存失败。", parent=dialog
                    )
                    return
            else:
                self.delete_cf_saved_password()

            dialog.destroy()

        def clear_saved():
            self.delete_cf_saved_password()
            username_var.set("")
            password_var.set("")
            save_var.set(False)
            messagebox.showinfo(
                "提示", "已取消保存并删除本机账户信息。", parent=dialog
            )

        def cancel():
            dialog.destroy()

        ttk.Button(
            buttons, text="保存", width=10, command=save_and_close
        ).pack(side="left", padx=4)
        ttk.Button(
            buttons, text="取消保存", width=10, command=clear_saved
        ).pack(side="left", padx=4)
        ttk.Button(
            buttons, text="关闭", width=10, command=cancel
        ).pack(side="left", padx=4)

        dialog.bind("<Return>", lambda e: save_and_close())
        dialog.bind("<Escape>", lambda e: cancel())

        username_entry.focus_set()
        self.root.wait_window(dialog)

    def ask_cf_password(self):
        saved = self.get_cf_account_config()

        dialog = tk.Toplevel(self.root)
        dialog.title("CF 登录")
        dialog.resizable(False, False)
        dialog.transient(self.root)

        # 居中到软件主窗口内部，而不是居中到整个屏幕。
        dialog.update_idletasks()
        root_x = self.root.winfo_rootx()
        root_y = self.root.winfo_rooty()
        root_w = self.root.winfo_width()
        root_h = self.root.winfo_height()
        dialog_w = dialog.winfo_width()
        dialog_h = dialog.winfo_height()
        pos_x = root_x + max(0, (root_w - dialog_w) // 2)
        pos_y = root_y + max(0, (root_h - dialog_h) // 2)
        dialog.geometry(f"+{pos_x}+{pos_y}")
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding=15)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="CF 管理账户:").grid(
            row=0, column=0, sticky="e", padx=(0, 8), pady=(0, 10)
        )
        username_var = tk.StringVar(value=saved.get("username", ""))
        ttk.Entry(
            frame, textvariable=username_var, width=30
        ).grid(row=0, column=1, pady=(0, 10))

        ttk.Label(frame, text="管理员密码:").grid(
            row=1, column=0, sticky="e", padx=(0, 8), pady=(0, 10)
        )
        password_var = tk.StringVar(value=saved.get("password", ""))
        entry = ttk.Entry(
            frame, textvariable=password_var, width=30, show="*"
        )
        entry.grid(row=1, column=1, pady=(0, 10))
        entry.focus_set()

        save_var = tk.BooleanVar(value=bool(saved.get("password", "")))
        ttk.Checkbutton(
            frame, text="保存账户信息到本机", variable=save_var
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 12))

        result = {"password": None, "save": False, "username": ""}

        def confirm():
            password = password_var.get().strip()
            if not password:
                messagebox.showwarning(
                    "提示", "请输入 CF 管理员密码。", parent=dialog
                )
                return
            result["password"] = password
            result["save"] = save_var.get()
            result["username"] = username_var.get().strip()
            dialog.destroy()

        def cancel():
            dialog.destroy()

        buttons = ttk.Frame(frame)
        buttons.grid(row=3, column=0, columnspan=2)
        ttk.Button(buttons, text="登录", width=10, command=confirm).pack(side="left", padx=5)
        ttk.Button(buttons, text="取消", width=10, command=cancel).pack(side="left", padx=5)

        dialog.bind("<Return>", lambda e: confirm())
        dialog.bind("<Escape>", lambda e: cancel())

        self.root.wait_window(dialog)

        if result["password"] is not None:
            if result["save"]:
                self.save_cf_account(result["username"], result["password"])
            else:
                self.delete_cf_saved_password()

        return result["password"]

    def collect_success_ips(self):
        result = []
        for item_id in self.tree.get_children(""):
            values = self.tree.item(item_id)["values"]
            if len(values) < 4:
                continue
            ip = str(values[0]).strip()
            ports_text = str(values[1]).strip()
            xray_value = str(values[3]).strip()
            if not ip or not xray_value.endswith(" ms"):
                continue
            for raw_port in ports_text.replace("，", ",").split(","):
                raw_port = raw_port.strip()
                if raw_port.isdigit() and 1 <= int(raw_port) <= 65535:
                    result.append(f"{ip}:{raw_port}")
        return result

    def upload_to_cf(self):
        if self.running:
            messagebox.showinfo(
                "提示",
                "扫描进行中，请先停止扫描再上传。"
            )
            return

        nodes = self.collect_success_ips()

        if not nodes:
            messagebox.showinfo(
                "提示",
                "当前列表没有可上传的 Xray 成功节点。"
            )
            return

        password = self.get_cf_saved_password()

        if not password:
            password = self.ask_cf_password()

        if not password:
            return

        self.upload_button.config(state="disabled")
        self.lbl_progress.config(
            text=f"正在上传 {len(nodes)} 个节点到 CF..."
        )

        threading.Thread(
            target=self._upload_to_cf_worker,
            args=(nodes, password),
            daemon=True
        ).start()

    def _upload_to_cf_worker(self, nodes, password):
        try:
            cookie_jar = http.cookiejar.CookieJar()

            opener = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(cookie_jar)
            )

            # 登录
            login_data = urllib.parse.urlencode({
                "password": password
            }).encode("utf-8")

            login_request = urllib.request.Request(
                CF_LOGIN_URL,
                data=login_data,
                method="POST",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "CF-IP-Scanner/1.0"
                }
            )

            with opener.open(login_request, timeout=15) as response:
                login_body = response.read().decode(
                    "utf-8",
                    errors="ignore"
                )

            try:
                login_json = json.loads(login_body)
            except Exception:
                login_json = {}

            if not login_json.get("success"):
                raise RuntimeError("CF 登录失败，请检查管理员密码。")

            # 上传
            upload_text = "\n".join(nodes)

            upload_request = urllib.request.Request(
                CF_ADD_URL,
                data=upload_text.encode("utf-8"),
                method="POST",
                headers={
                    "Content-Type": "text/plain; charset=utf-8",
                    "User-Agent": "CF-IP-Scanner/1.0"
                }
            )

            with opener.open(upload_request, timeout=20) as response:
                body = response.read().decode(
                    "utf-8",
                    errors="ignore"
                )

            try:
                result_json = json.loads(body)
            except Exception:
                result_json = {}

            if response.status != 200 or not result_json.get("success"):
                message = result_json.get(
                    "error",
                    result_json.get("message", "CF 返回失败")
                )
                raise RuntimeError(str(message))

            self.root.after(
                0,
                lambda: self._upload_success(len(nodes))
            )

        except Exception as e:
            error_text = str(e)

            self.root.after(
                0,
                lambda: self._upload_failed(error_text)
            )

    def _upload_success(self, count):
        self.upload_button.config(state="normal")

        self.update_status()

        # 上传成功属于正常提示，不占用 Xray 错误状态区域。
        self.lbl_progress.config(
            text=f"上传成功：已上传 {count} 个 Xray 可用节点到 CF"
        )

    def _upload_failed(self, error):
        self.upload_button.config(state="normal")

        self.update_status()

        messagebox.showerror(
            "上传失败",
            f"上传到 CF 失败：\n\n{error}"
        )

    # ========================================================
    # 右键菜单
    # ========================================================

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)

        if item:
            self.tree.selection_set(item)

            self.context_menu.tk_popup(
                event.x_root,
                event.y_root
            )

    def copy_selected_ip(self):
        selected = self.tree.selection()
        if selected:
            ip = self.tree.item(selected[0])["values"][0]
            self.root.clipboard_clear()
            self.root.clipboard_append(ip)

    def copy_selected_ip_port(self):
        selected = self.tree.selection()
        if selected:
            values = self.tree.item(selected[0])["values"]
            if len(values) >= 2:
                ip = values[0]
                ports = str(values[1]).replace("，", ",")
                nodes = [f"{ip}:{p.strip()}" for p in ports.split(",") if p.strip()]
                self.root.clipboard_clear()
                self.root.clipboard_append("\n".join(nodes))

    def copy_all_valid_ips(self):
        valid_items = [
            self.tree.item(k)["values"][0]
            for k in self.tree.get_children("")
            if len(self.tree.item(k)["values"]) >= 4
            and str(self.tree.item(k)["values"][3]).endswith(" ms")
        ]
        if valid_items:
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(valid_items))
            messagebox.showinfo("提示", f"已成功复制 {len(valid_items)} 个可用 IP 到剪贴板！")

    def copy_all_valid_ip_ports(self):
        ip_ports = []
        for k in self.tree.get_children(""):
            values = self.tree.item(k)["values"]
            if len(values) < 4 or not str(values[3]).endswith(" ms"):
                continue
            ip = str(values[0]).strip()
            ports = str(values[1]).replace("，", ",")
            for p in ports.split(","):
                p = p.strip()
                if p:
                    ip_ports.append(f"{ip}:{p}")
        if ip_ports:
            self.root.clipboard_clear()
            self.root.clipboard_append("\n".join(ip_ports))
            messagebox.showinfo("提示", f"已成功复制 {len(ip_ports)} 个可用 IP:端口 到剪贴板！")

    def on_close(self, event=None):
        self.closing = True
        if self.running:
            self.pause_scan()
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = NirSoftCFScanner(root)
    root.mainloop()



