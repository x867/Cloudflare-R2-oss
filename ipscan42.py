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
import http.client
import ssl
import re

# ============================================================
# Cloudflare & 第三方节点 IP 优选工具
# IPv4 / IPv6 双栈扫描；扫描停止与 Xray 停止彻底分离版
# 新增：上传 Xray 成功节点到 CF /admin/ADD.txt
# ============================================================

CF_BASE_URL = "https://ngr.ccwu.cc"
CF_LOGIN_URL = CF_BASE_URL + "/login"
CF_ADD_URL = CF_BASE_URL + "/admin/ADD.txt"
CF_PASSWORD_FILE = "cf_upload_config.json"
CF_QUOTA_FILE = "cf_quota_config.json"
CF_QUOTA_REFRESH_SECONDS = 5


class NirSoftCFScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("魔法探测器")
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
        self.config_readonly = False
        self.saved_subnets = ""
        self.saved_ports = ""
        self.saved_workers = ""

        # Cloudflare 六账户额度读取配置。Token 不写入代码，首次使用时在“CF额度”中填写。
        self.cf_quota_accounts = self.load_cf_quota_config()
        self.cf_quota_refreshing = False
        self.cf_quota_dialog = None
        self.cf_quota_logged_in = False
        self.cf_quota_login_key = None
        self.cf_quota_refresh_after_id = None
        self.cf_quota_active_refresh_after_id = None
        self.cf_quota_active_refreshing = False
        self.cf_quota_rows = []
        # 默认使用平衡模式；勾选“放干模式”后才按放干策略运行。
        self.cf_schedule_mode = str(self.cf_quota_accounts.get("schedule_mode", "balance") or "balance").lower()
        if self.cf_schedule_mode not in ("drain", "balance"):
            self.cf_schedule_mode = "balance"
        # 账户1固定控制在 5000~10000 请求范围；2~6继续使用百分比保留线。
        self.cf_account1_min_remaining = 5000
        self.cf_account1_max_remaining = 10000
        self.cf_reserve_accounts2_6 = max(0, min(100, int(self.cf_quota_accounts.get("reserve_accounts2_6", 3) or 3)))
        self.cf_balance_rotation_percent = int(self.cf_quota_accounts.get("balance_rotation_percent", 5) or 5)
        if self.cf_balance_rotation_percent not in (3, 5, 10, 15, 20):
            self.cf_balance_rotation_percent = 5
        self.cf_schedule_order = [6, 5, 4, 3, 2, 1]
        self.cf_schedule_pos = 0
        self.cf_current_account = 6
        self.cf_schedule_lock = threading.Lock()
        # CF 后台请求计数有延迟，因此维护一份本地“虚拟剩余额度”。
        self.cf_balance_remaining = {}
        self.cf_balance_reported_used = {}
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
        self.root.after(300, self._keep_ip_scrollbar_visible)
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

        # 六账户 Workers 请求额度
        self.quota_button = ttk.Button(
            top,
            text="CF配置",
            width=8,
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
        # 保存引用，返回主界面时确保滚动条重新显示在 Treeview 上层。
        self.tree_scrollbar = scrollbar

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
        cfg_subnet_frame.grid(row=1, column=1, columnspan=3, sticky="nw", pady=6)
        cfg_subnet_frame.grid_rowconfigure(0, weight=1)
        cfg_subnet_frame.grid_columnconfigure(0, weight=1)
        self.config_subnet_entry = tk.Text(
            cfg_subnet_frame, width=62, height=6, wrap="none",
            font=("Consolas", 10), undo=True
        )
        self.config_subnet_entry.grid(row=0, column=0, sticky="nsew")
        # 滚动条直接放在文本框内部右侧，和主 IP 框的滚动条位置一致。
        cfg_subnet_scroll = ttk.Scrollbar(
            cfg_subnet_frame, orient="vertical",
            command=self.config_subnet_entry.yview
        )
        cfg_subnet_scroll.place(relx=1.0, rely=0.0, x=-1, relheight=1.0, anchor="ne")
        cfg_subnet_scroll.lift()
        self.config_subnet_entry.configure(yscrollcommand=cfg_subnet_scroll.set)
        self._subnet_placeholder_active = False
        self.config_subnet_entry.bind("<FocusIn>", self._config_subnet_focus_in)
        self.config_subnet_entry.bind("<FocusOut>", self._config_subnet_focus_out)

        # SNI / UUID：单独整理成“标题 + 自动获取按钮”一行，下面整块显示内容。
        # 这样按钮和滚动条不会挤压文本框，六个 SNI + UUID 看起来更整齐。
        cfg_label("SNI / UUID", 2, 0)

        cfg_sni_header = tk.Frame(cfg_form, bg="#f4f4f4")
        cfg_sni_header.grid(row=2, column=1, columnspan=3, sticky="ew", pady=(6, 2))
        self.config_auto_fetch_button = ttk.Button(
            cfg_sni_header,
            text="自动获取六账户",
            width=14,
            command=self.auto_fetch_six_worker_configs
        )
        self.config_auto_fetch_button.pack(side="right")

        cfg_text_frame = tk.Frame(cfg_form, bg="#f4f4f4")
        cfg_text_frame.grid(row=3, column=1, columnspan=3, sticky="nw", pady=(0, 6))
        cfg_text_frame.grid_rowconfigure(0, weight=1)
        cfg_text_frame.grid_columnconfigure(0, weight=1)
        self.config_sni_uuid_entry = tk.Text(
            cfg_text_frame, width=62, height=8, wrap="none",
            font=("Consolas", 10), undo=True
        )
        self.config_sni_uuid_entry.grid(row=0, column=0, sticky="nsew")
        # 滚动条直接放在文本框内部右侧，和主 IP 框的滚动条位置一致。
        cfg_text_scroll = ttk.Scrollbar(
            cfg_text_frame, orient="vertical",
            command=self.config_sni_uuid_entry.yview
        )
        cfg_text_scroll.place(relx=1.0, rely=0.0, x=-1, relheight=1.0, anchor="ne")
        cfg_text_scroll.lift()
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
        self.save_scan_checkpoint(force=True)
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

        # 清空列表后强制恢复主 IP 框右侧滚动条。
        # 配置页/CF页覆盖主列表时可能改变了控件层级，清空后统一重新定位并提升。
        try:
            self.tree.place(
                x=0,
                y=0,
                relwidth=1.0,
                relheight=1.0
            )
            self.tree_scrollbar.place(
                relx=1.0,
                rely=0.0,
                x=-1,
                relheight=1.0,
                anchor="ne"
            )
            self.tree.lift()
            self.tree_scrollbar.lift()
            self.root.after_idle(self.tree_scrollbar.lift)
        except Exception as e:
            print("恢复主IP框滚动条失败:", e)

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

    def save_scan_checkpoint(self, force=False):
        """保存扫描断点。

        扫描过程中不再每完成一个 IP 就同步写整个 JSON 文件。
        普通调用最多每 2 秒提交一次后台写盘，避免 Tk 主线程被磁盘 IO /
        JSON 序列化卡住；暂停或关闭时传 force=True，立即保存最后状态。
        """
        if not self.ip_list:
            return

        now = time.monotonic()
        if not force:
            last = float(getattr(self, "_checkpoint_last_request", 0.0) or 0.0)
            if now - last < 2.0:
                return
            self._checkpoint_last_request = now

        rows = []
        for item_id in self.tree.get_children(""):
            rows.append({
                "ip": str(item_id),
                "values": list(self.tree.item(item_id).get("values", ()))
            })

        data = {
            "ip_list": list(self.ip_list),
            "completed_ips": sorted(self.completed_ips),
            "success": self.success,
            "scan_ports": list(self.scan_ports),
            "scan_elapsed": self.scan_elapsed,
            "results": rows,
        }

        def write_snapshot(snapshot):
            try:
                with open(self.scan_state_file, "w", encoding="utf-8") as f:
                    json.dump(snapshot, f, ensure_ascii=False, indent=2)
                self.resume_available = True
            except Exception as e:
                print("保存扫描断点失败:", e)

        if force:
            write_snapshot(data)
        else:
            threading.Thread(
                target=write_snapshot,
                args=(data,),
                daemon=True
            ).start()

    def finish_scan(self):
        """扫描全部完成：清除断点，下一次开始重新扫描。"""
        self.running = False
        self.scan_stop_event.set()
        self.xray_stop_event.set()
        self.force_stop_all_xray()
        self.force_stop_xray()
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
                    gathered_ips.extend(self._expand_scan_network(part))
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
        """读取六账户配置：一个账户一个 UUID，可绑定多个 SNI/域名。"""
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
                    low = section.lower()
                    prefix = "account" if low.startswith("account") else ("node" if low.startswith("node") else "")
                    if not prefix: continue
                    try: number = int(section[len(prefix):])
                    except Exception: number = 999999
                    sections.append((number, section))
                sections.sort(key=lambda x: x[0])
                shared_uuid = ""
                for number, section in sections:
                    uuid = parser.get(section, "uuid", fallback="").strip()
                    raw = parser.get(section, "sni", fallback="").strip()
                    snis = list(dict.fromkeys([x.strip() for x in re.split(r"[,，;；\n]+", raw) if x.strip()]))
                    if number == 1 and uuid:
                        shared_uuid = uuid
                    if snis or uuid:
                        self.node_configs.append({"account": number, "uuid": uuid, "snis": snis, "sni": snis[0] if snis else ""})
                if shared_uuid:
                    for item in self.node_configs:
                        item["uuid"] = shared_uuid
        except Exception as e:
            print("读取 config.ini 失败:", e)
        while len(self.node_configs) < 6:
            self.node_configs.append({"account": len(self.node_configs)+1, "uuid": "", "snis": [], "sni": ""})
        self.node_configs = self.node_configs[:6]
        self.config_index = 0
        self._account_sni_pos = [0] * len(self.node_configs)

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
        for i, item in enumerate(self.node_configs[:6], 1):
            section = f"Account{i}"
            snis = item.get("snis", [])
            if not isinstance(snis, list):
                snis = [str(item.get("sni", "")).strip()] if item.get("sni") else []
            snis = list(dict.fromkeys([str(x).strip() for x in snis if str(x).strip()]))
            # 六个子账户共用账户1的 UUID；这里只保存一份逻辑上的公共 UUID。
            shared_uuid = str(self.node_configs[0].get("uuid", "")).strip() if self.node_configs else ""
            parser[section] = {
                "uuid": shared_uuid,
                "sni": ",".join(snis),
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

    def _normalize_worker_info_url(self, value):
        value = str(value or "").strip()
        if not value:
            return ""
        if " / " in value:
            value = value.split(" / ", 1)[0].strip()
        value = re.sub(r"^https?://", "", value, flags=re.I).split("/", 1)[0].strip()
        if not value:
            return ""
        return "https://" + value

    def _fetch_worker_nodeinfo(self, worker_url, password):
        worker_url = self._normalize_worker_info_url(worker_url)
        if not worker_url:
            raise RuntimeError("Worker 地址为空")
        request = urllib.request.Request(
            worker_url.rstrip("/") + "/admin/nodeinfo",
            method="GET",
            headers={
                "Accept": "application/json",
                "User-Agent": "CF-IP-Scanner/1.0",
                "X-Admin-Password": str(password or ""),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=12) as response:
                body = response.read().decode("utf-8-sig", errors="replace")
                status = response.getcode()
                content_type = str(response.headers.get("Content-Type") or "").strip()
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8-sig", errors="replace").strip()[:180]
            raise RuntimeError(
                f"HTTP {e.code}" + (f"：{detail}" if detail else "")
            ) from e
        if status != 200:
            raise RuntimeError(f"HTTP {status}")
        try:
            data = json.loads(body or "{}")
        except Exception as e:
            preview = re.sub(r"\s+", " ", body).strip()[:120]
            if "text/html" in content_type.lower() or body.lstrip().lower().startswith("<!doctype") or body.lstrip().lower().startswith("<html"):
                title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:80] if title_match else ""
                detail = f"返回 HTML" + (f"（{title}）" if title else "")
            else:
                detail = f"返回非 JSON" + (f"（Content-Type: {content_type}）" if content_type else "")
            raise RuntimeError(detail) from e
        if not data.get("success"):
            raise RuntimeError(str(data.get("error") or data.get("msg") or "Worker 信息读取失败"))
        uuid = str(data.get("uuid", "")).strip()
        sni = str(data.get("sni", "")).strip()
        if not uuid:
            raise RuntimeError("Worker 没有返回 UUID")
        # 保留 nodeinfo 的其它字段，账户6可能需要从内部 Worker 的返回数据中发现外部域名。
        result = dict(data)
        result["uuid"] = uuid
        result["sni"] = sni
        return result

    def auto_fetch_six_worker_configs(self):
        """只从账户1获取公共 UUID；账户1~6分别发现自己的 SNI/域名。"""
        if getattr(self, "config_readonly", False):
            return

        backend_url = self._normalize_worker_info_url(
            str(self.cf_quota_accounts.get("backend_url", "")).strip()
        )
        password = str(self.cf_quota_accounts.get("password", "") or "").strip()

        if not backend_url:
            messagebox.showwarning("无法自动获取", "没有配置账户1 Worker 地址。\n请先在“CF配置”中设置账户1的 Worker 地址。")
            return
        if not password:
            messagebox.showwarning("提示", "自动获取需要账户1 Worker 管理员密码。\n请在“CF配置”中保存登录信息后再获取。")
            return

        try:
            self.config_auto_fetch_button.config(state="disabled")
        except Exception:
            pass

        def worker():
            results = []
            shared_uuid = ""
            try:
                request = urllib.request.Request(
                    backend_url.rstrip("/") + "/admin/get6workerinfo",
                    method="GET",
                    headers={
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                        "Connection": "close",
                        "User-Agent": "CF-IP-Scanner/1.0",
                        "X-Admin-Password": password,
                    },
                )
                try:
                    with urllib.request.urlopen(request, timeout=30) as response:
                        chunks = []
                        while True:
                            chunk = response.read(65536)
                            if not chunk:
                                break
                            chunks.append(chunk)
                        body = b"".join(chunks).decode("utf-8-sig", errors="replace")
                        status = response.getcode()
                except Exception as e:
                    raise RuntimeError(f"读取账户1 Worker 自动发现结果失败：{e}") from e

                if status != 200:
                    raise RuntimeError(f"账户1 Worker 自动发现接口 HTTP {status}")

                try:
                    data = json.loads(body or "{}")
                except Exception as e:
                    raise RuntimeError("账户1 Worker 返回的不是有效 JSON") from e

                if not data.get("success"):
                    raise RuntimeError(str(data.get("error") or data.get("msg") or "六账户 Worker 自动发现失败"))

                discovered = data.get("accounts") or []
                if len(discovered) != 6:
                    raise RuntimeError("Worker 返回的六账户发现结果不完整")

                # 只认账户1的 UUID。账户2~6即使返回 uuid 也完全忽略。
                account1 = next((item for item in discovered if int(item.get("account") or 0) == 1), None)
                if not isinstance(account1, dict):
                    raise RuntimeError("自动发现结果中没有账户1")

                direct1 = account1.get("nodeinfo")
                if isinstance(direct1, dict):
                    shared_uuid = str(direct1.get("uuid") or "").strip()

                # 如果后台没有直接给账户1 nodeinfo，则尝试账户1候选地址。
                if not shared_uuid:
                    candidates1 = [backend_url] + (account1.get("candidates") or [])
                    for candidate in candidates1:
                        url = str(candidate.get("url") or candidate.get("hostname") or "").strip() if isinstance(candidate, dict) else str(candidate or "").strip()
                        if not url:
                            continue
                        try:
                            info1 = self._fetch_worker_nodeinfo(url, password)
                            shared_uuid = str(info1.get("uuid") or "").strip()
                            if shared_uuid:
                                break
                        except Exception:
                            continue

                if not shared_uuid:
                    raise RuntimeError("账户1没有获取到 UUID，请检查账户1权限或 Worker 配置。")

                # 六个子账户只取自己的 SNI/域名，统一使用账户1 UUID。
                for item in discovered:
                    account = int(item.get("account") or 0)
                    if not 1 <= account <= 6:
                        continue

                    candidates = item.get("candidates") or []
                    info = None
                    error = str(item.get("error") or "").strip()

                    # 账户2~6按原来的方式直接读取自己的 nodeinfo。
                    # 只有账户1需要特殊处理多个域名。
                    if account != 1:
                        direct = item.get("nodeinfo")
                        if isinstance(direct, dict):
                            raw_snis = direct.get("snis") if isinstance(direct.get("snis"), list) else []
                            direct_sni = str(direct.get("sni") or "").strip()
                            snis = list(dict.fromkeys([str(x).strip() for x in raw_snis if str(x).strip()]))
                            if direct_sni and direct_sni not in snis:
                                snis.insert(0, direct_sni)
                            if snis:
                                info = {"snis": snis}


                    # 六个账户统一通过 candidates 寻找自己的外部 SNI/域名。
                    # 账户1的 cvx.ccwu.cc 是邮件转发 Worker，不属于 EdgeTunnel SNI；
                    # 账户6的 *.workers.dev 是内部 Worker 域名，过滤后继续找其它候选。
                    for candidate in candidates:
                        if info and info.get("snis"):
                            break
                        if isinstance(candidate, dict):
                            direct_snis = []
                            for key in ("sni", "hostname", "host", "domain", "domainName", "worker", "workerDomain"):
                                value = str(candidate.get(key) or "").strip()
                                if value:
                                    value = re.sub(r"^https?://", "", value, flags=re.I).split("/", 1)[0].strip()
                                    if account == 1 and value.lower() == "cvx.ccwu.cc":
                                        continue
                                    if value and value not in direct_snis:
                                        direct_snis.append(value)
                            if direct_snis:
                                info = {"snis": direct_snis}
                                break
                        url = str(candidate.get("url") or candidate.get("hostname") or "").strip() if isinstance(candidate, dict) else str(candidate or "").strip()
                        if not url:
                            continue
                        try:
                            ni = self._fetch_worker_nodeinfo(url, password)
                            candidate_sni = str(ni.get("sni") or "").strip()
                            candidate_sni = re.sub(r"^https?://", "", candidate_sni, flags=re.I).split("/", 1)[0].strip()
                            if account == 1 and candidate_sni.lower() == "cvx.ccwu.cc":
                                continue
                            if candidate_sni:
                                info = {"snis": [candidate_sni]}
                                break
                        except Exception as e:
                            error = f"{url}: {e}"

                    if info and info.get("snis"):
                        results.append((account - 1, info, None))
                    else:
                        results.append((account - 1, None, error or "未找到可访问的 SNI/域名"))

            except Exception as e:
                error = str(e)
                results = [(i, None, error) for i in range(6)]

            def apply():
                try:
                    # 公共 UUID 永远只来自账户1。
                    for i, info, error in results:
                        if info is not None:
                            while len(self.node_configs) <= i:
                                self.node_configs.append({"account": len(self.node_configs)+1, "uuid": "", "snis": [], "sni": ""})
                            snis = list(dict.fromkeys([str(x).strip() for x in (info.get("snis") or []) if str(x).strip()]))
                            self.node_configs[i] = {
                                "account": i + 1,
                                "uuid": shared_uuid,
                                "snis": snis,
                                "sni": snis[0] if snis else ""
                            }

                    # 即使某些账户 SNI 读取失败，也让所有已有账户共用账户1 UUID。
                    if shared_uuid:
                        while len(self.node_configs) < 6:
                            self.node_configs.append({"account": len(self.node_configs)+1, "uuid": "", "snis": [], "sni": ""})
                        for item in self.node_configs[:6]:
                            item["uuid"] = shared_uuid

                    success_count = sum(1 for _, info, _ in results if info is not None)

                    # 自动获取结果直接写入 SNI 文本框，不经过当前行/配置页状态转换。
                    # 这样获取到的 6 个域名会立即按账户 1→6 显示。
                    display_lines = []
                    for i in range(6):
                        result_item = next((x for x in results if x[0] == i), None)
                        info = result_item[1] if result_item else None
                        snis = []
                        if isinstance(info, dict):
                            snis = [str(x).strip() for x in (info.get("snis") or []) if str(x).strip()]
                        display_lines.append(",".join(dict.fromkeys(snis)))
                    if shared_uuid:
                        display_lines.append(shared_uuid)

                    self.config_sni_uuid_entry.config(state="normal")
                    self.config_sni_uuid_entry.delete("1.0", "end")
                    self.config_sni_uuid_entry.tag_remove("sni_uuid_placeholder", "1.0", "end")
                    self._sni_uuid_placeholder_active = False
                    self.config_sni_uuid_entry.insert("1.0", "\n".join(display_lines) + "\n")
                    self._config_read_current()

                    if shared_uuid:
                        self.save_node_configs_file()
                    self.config_index = min(self.config_index, len(self.node_configs) - 1)
                    self._config_highlight_line()

                    # 自动获取只更新界面，不弹成功/失败窗口，避免干扰用户操作。
                finally:
                    try:
                        self.config_auto_fetch_button.config(state="normal")
                    except Exception:
                        pass

            self.root.after(0, apply)

        threading.Thread(target=worker, daemon=True).start()

    def _set_sni_uuid_placeholder(self):
        """SNI 文本框为空时显示浅色使用提示；提示文字不参与保存。"""
        try:
            if self.config_sni_uuid_entry.get("1.0", "end-1c").strip():
                self._sni_uuid_placeholder_active = False
                return
            self.config_sni_uuid_entry.delete("1.0", "end")
            self.config_sni_uuid_entry.insert(
                "1.0",
                "一行一个 SNI/域名（按账户1→6顺序）"
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
        """读取六个 SNI/域名；公共 UUID 只读取一次并应用到六个子账户。"""
        raw = "" if getattr(self, "_sni_uuid_placeholder_active", False) else self.config_sni_uuid_entry.get("1.0", "end-1c")
        configs = []
        shared_uuid = ""
        sni_lines = []

        for line in raw.splitlines():
            value = line.strip()
            if not value:
                continue
            if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value):
                shared_uuid = value
                continue
            if value.startswith("公共UUID"):
                if "/" in value:
                    shared_uuid = value.split("/", 1)[1].strip()
                elif ":" in value:
                    shared_uuid = value.split(":", 1)[1].strip()
                continue
            sni_lines.append(value)

        for index, value in enumerate(sni_lines[:6], 1):
            # 兼容旧配置格式：如果用户手工保留了“账户N | ... / UUID”，仍能读取。
            if "|" in value:
                _, value = value.split("|", 1)
            if "/" in value:
                left, inline_uuid = value.split("/", 1)
                value = left.strip()
                if not shared_uuid:
                    shared_uuid = inline_uuid.strip()

            snis = list(dict.fromkeys([x.strip() for x in re.split(r"[,，;；]+", value) if x.strip()]))
            configs.append({
                "account": index,
                "uuid": shared_uuid,
                "snis": snis,
                "sni": snis[0] if snis else ""
            })

        while len(configs) < 6:
            configs.append({
                "account": len(configs) + 1,
                "uuid": shared_uuid,
                "snis": [],
                "sni": ""
            })

        self.node_configs = configs[:6]
        self._account_sni_pos = [0] * len(self.node_configs)
        self.config_index = min(self.config_index, len(self.node_configs) - 1)

    def _config_show_current(self):
        if not self.node_configs:
            self.node_configs = [{"uuid": "", "sni": ""}]
            self.config_index = 0
        self.config_sni_uuid_entry.delete("1.0", "end")
        self.config_sni_uuid_entry.tag_remove("sni_uuid_placeholder", "1.0", "end")
        self._sni_uuid_placeholder_active = False

        lines = []
        for item in self.node_configs[:6]:
            snis = item.get("snis", [])
            if not isinstance(snis, list):
                snis = [str(item.get("sni", "")).strip()] if item.get("sni") else []
            snis = [str(x).strip() for x in snis if str(x).strip()]
            lines.append(",".join(snis))

        # 公共 UUID 与六个 SNI 一起显示；扫描/返回配置页后也必须保留。
        shared_uuid = ""
        if self.node_configs:
            shared_uuid = str(self.node_configs[0].get("uuid", "")).strip()
        if shared_uuid:
            lines.append(shared_uuid)

        if any(x.strip() for x in lines):
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

    def _keep_ip_scrollbar_visible(self):
        """保持主界面 IP/网段文本框滚动条稳定可见；不参与扫描逻辑。"""
        try:
            sb = getattr(self, "config_subnet_scrollbar", None)
            txt = getattr(self, "config_subnet_entry", None)
            if sb is not None and txt is not None and sb.winfo_exists() and txt.winfo_exists():
                sb.grid(row=0, column=1, sticky="ns")
                txt.grid(row=0, column=0, sticky="nsew")
                parent = txt.master
                parent.grid_rowconfigure(0, weight=1)
                parent.grid_columnconfigure(0, weight=1)
        except Exception:
            pass
        try:
            self.root.after(500, self._keep_ip_scrollbar_visible)
        except Exception:
            pass

    def open_node_config(self):
        # 两个配置页互斥：打开扫描配置前，先自动关闭 CF 配置页。
        try:
            if self.cf_quota_dialog is not None and self.cf_quota_dialog.winfo_exists():
                if self.quota_button.cget("text") == "返回":
                    self.quota_button.invoke()
        except Exception:
            pass

        readonly = bool(self.running)

        # 进入配置页时，把主窗口当前输入同步进去。
        # 扫描进行中允许查看配置，但全部控件只读，不允许修改。
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
        self.config_readonly = readonly
        self._config_show_current()

        # 扫描中：配置页仅供查看，控件全部灰色不可编辑。
        entry_state = "disabled" if readonly else "normal"
        self.config_port_entry.config(state=entry_state)
        self.config_worker_entry.config(state=entry_state)
        self.config_subnet_entry.config(state="disabled" if readonly else "normal")
        self.config_sni_uuid_entry.config(state="disabled" if readonly else "normal")

        self.config_overlay.place(x=0, y=0, relwidth=1.0, relheight=1.0)
        self.config_overlay.lift()
        self.config_button.config(text="返回", command=self.close_node_config)

    def close_node_config(self):
        # 扫描中只是查看配置，返回时绝对不保存/修改任何配置。
        if not getattr(self, "config_readonly", False):
            self.config_save()

        # 恢复控件可编辑状态，供下一次停止扫描后的配置使用。
        self.config_port_entry.config(state="normal")
        self.config_worker_entry.config(state="normal")
        self.config_subnet_entry.config(state="normal")
        self.config_sni_uuid_entry.config(state="normal")

        # 返回统一回到 IP 主窗口，不进入其他配置页面。
        self.config_overlay.place_forget()
        self.config_mode = False
        self.config_readonly = False
        self.tree.lift()
        # 配置页覆盖 Treeview 时会把滚动条压到下面；
        # 返回后必须把滚动条重新提升到最上层，否则滚动条会消失。
        try:
            self.tree_scrollbar.lift()
        except Exception:
            pass
        self.config_button.config(text="扫描配置", command=self.open_node_config)
        try:
            self.quota_button.config(text="CF配置", command=self.open_cf_quota_manager)
        except Exception:
            pass

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

    def _set_cf_schedule(self, data):
        """更新六账户额度状态。平衡模式下不重置当前账户，实际轮换统一由取节点函数决定。"""
        accounts = data.get("accounts", []) if isinstance(data, dict) else []
        fixed_order = [6, 5, 4, 3, 2, 1]
        available = {}

        try:
            for account in fixed_order:
                i = account - 1
                item = accounts[i] if i < len(accounts) else {}
                limit = max(0, int(item.get("todayLimit", 0) or 0))
                remain = max(0, int(item.get("todayRemaining", 0) or 0))
                used = max(0, int(item.get("todayUsed", 0) or 0))

                old_used = self.cf_balance_reported_used.get(account)
                old_virtual = self.cf_balance_remaining.get(account)
                new_day = old_used is not None and used < old_used
                if new_day or old_virtual is None:
                    virtual_remain = remain
                else:
                    # CF 后台统计可能延迟，本地虚拟额度只允许继续下降，不被旧统计拉高。
                    virtual_remain = min(old_virtual, remain)

                self.cf_balance_reported_used[account] = used
                self.cf_balance_remaining[account] = virtual_remain

                if account == 1:
                    effective_remain = min(virtual_remain, self.cf_account1_max_remaining)
                    reserve = self.cf_account1_min_remaining
                else:
                    reserve = int(limit * self.cf_reserve_accounts2_6 / 100)
                    effective_remain = virtual_remain

                available[account] = {
                    "remain": max(0, effective_remain),
                    "raw_remain": virtual_remain,
                    "reserve": max(0, reserve),
                    "limit": limit,
                }
        except Exception:
            return

        with self.cf_schedule_lock:
            current = int(getattr(self, "cf_current_account", 6) or 6)
            if current not in fixed_order:
                current = 6

            if self.cf_schedule_mode == "drain":
                # 放干模式：只有当前账户跌到保留线，才切到下一个账户。
                info = available.get(current, {})
                if info.get("remain", 0) <= info.get("reserve", 0):
                    start_pos = fixed_order.index(current)
                    for offset in range(1, len(fixed_order) + 1):
                        candidate = fixed_order[(start_pos + offset) % len(fixed_order)]
                        candidate_info = available.get(candidate, {})
                        if candidate_info.get("remain", 0) > candidate_info.get("reserve", 0):
                            current = candidate
                            break
                self.cf_current_account = current
            else:
                # 平衡模式：这里绝不因为一次额度刷新就重选账户。
                # 当前账户只要仍有可用额度，就保持；真正的轮换由
                # _cf_balance_select_account() 按轮换比例决定。
                current_info = available.get(current, {})
                if current_info.get("remain", 0) > current_info.get("reserve", 0):
                    self.cf_current_account = current
                else:
                    # 当前账户已经到保留线，立即找剩余最高的可用账户接替。
                    candidates = [
                        a for a in fixed_order
                        if available.get(a, {}).get("remain", 0) > available.get(a, {}).get("reserve", 0)
                    ]
                    if candidates:
                        self.cf_current_account = max(
                            candidates,
                            key=lambda a: (available[a]["remain"], -fixed_order.index(a))
                        )
                    else:
                        self.cf_current_account = current

            self.cf_schedule_order = [self.cf_current_account]
            self.cf_schedule_pos = 0

    def _cf_balance_select_account(self):
        """平衡模式实际取节点：当前账户达到轮换带后才切换，并让绿色标识同步当前账户。"""
        fixed_order = [6, 5, 4, 3, 2, 1]
        current = int(getattr(self, "cf_current_account", 6) or 6)
        if current not in fixed_order:
            current = 6

        def get_reserve(account):
            if account == 1:
                return self.cf_account1_min_remaining
            last = getattr(self, "_last_cf_quota_data", {}) or {}
            accounts = last.get("accounts", []) if isinstance(last, dict) else []
            limit = int(accounts[account - 1].get("todayLimit", 0) or 0) if account - 1 < len(accounts) else 0
            return int(limit * self.cf_reserve_accounts2_6 / 100)

        def get_remain(account):
            remain = int(self.cf_balance_remaining.get(account, 0) or 0)
            if account == 1:
                remain = min(remain, self.cf_account1_max_remaining)
            return remain

        current_remain = get_remain(current)
        current_reserve = get_reserve(current)

        # 当前账户已经到保留线：按 6→5→4→3→2→1 找下一个可用账户。
        if current_remain <= current_reserve:
            start_pos = fixed_order.index(current)
            for offset in range(1, len(fixed_order) + 1):
                candidate = fixed_order[(start_pos + offset) % len(fixed_order)]
                if get_remain(candidate) > get_reserve(candidate):
                    current = candidate
                    current_remain = get_remain(current)
                    break

        # 当前账户正常使用时，找“剩余最高”的其他账户。
        # 只有当前额度已经进入设定的轮换百分比带，才切过去。
        best_other = None
        best_other_remain = -1
        for account in fixed_order:
            if account == current:
                continue
            remain = get_remain(account)
            if remain > get_reserve(account) and remain > best_other_remain:
                best_other = account
                best_other_remain = remain

        if best_other is not None and current_remain > current_reserve:
            threshold = best_other_remain * (1.0 + self.cf_balance_rotation_percent / 100.0)
            if current_remain <= threshold:
                current = best_other

        # 记录本次真正使用的账户；绿色 SNI 标识也直接读取这个状态。
        self.cf_current_account = current
        self.cf_schedule_order = [current]
        self.cf_schedule_pos = 0

        # 本地虚拟消耗 1 次，抵消 CF 后台统计延迟。
        self.cf_balance_remaining[current] = max(
            0, int(self.cf_balance_remaining.get(current, 0) or 0) - 1
        )
        return current

    def _sync_cf_schedule_to_worker(self, backend_url, password, mode, reserve1, reserve26, rotation_percent):
        """把软件里的调度设置同步到账户1 Worker；失败只记录日志，不影响扫描。"""
        try:
            backend_url = self._normalize_cf_quota_backend_url(backend_url)
            if not backend_url or not password:
                return False
            payload = json.dumps({
                "scheduleMode": "drain" if str(mode).lower() == "drain" else "balance",
                "reserve1Percent": max(0, min(100, int(reserve1))),
                "reserveOtherPercent": max(0, min(100, int(reserve26))),
                "rotationPercent": max(1, min(100, int(rotation_percent))),
            }, ensure_ascii=False).encode("utf-8")
            request = urllib.request.Request(
                backend_url + "/admin/setschedule",
                data=payload,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "User-Agent": "CF-IP-Scanner/1.0",
                    "X-Admin-Password": password,
                },
            )
            with urllib.request.urlopen(request, timeout=15) as response:
                body = response.read().decode("utf-8-sig", errors="replace")
            data = json.loads(body or "{}")
            if not data.get("success"):
                raise RuntimeError(str(data.get("error") or data.get("msg") or "调度设置同步失败"))
            return True
        except Exception as e:
            print("CF调度设置同步失败:", e)
            return False

    def _next_cf_node_config(self):
        """按当前调度模式选择账户，并轮换该账户的 SNI。"""
        if not self.node_configs:
            return {"uuid": "", "sni": ""}

        with self.cf_schedule_lock:
            if self.cf_schedule_mode == "balance" and self.cf_balance_remaining:
                account = self._cf_balance_select_account()
            else:
                order = list(self.cf_schedule_order) or [6, 5, 4, 3, 2, 1]
                account = int(getattr(self, "cf_current_account", order[0]) or order[0])
                if account not in order:
                    account = order[0]

            index = account - 1
            if 0 <= index < len(self.node_configs):
                node = self.node_configs[index]
                uuid = str(node.get("uuid", "")).strip()
                snis = node.get("snis", [])
                if not isinstance(snis, list):
                    snis = [str(node.get("sni", "")).strip()] if node.get("sni") else []
                snis = [str(x).strip() for x in snis if str(x).strip()]
                if snis:
                    pos = self._account_sni_pos[index] % len(snis)
                    self._account_sni_pos[index] += 1
                    return {"uuid": uuid, "sni": snis[pos]}
                return {"uuid": uuid, "sni": ""}

        return self.get_active_node_config()

    def get_active_node_config(self):
        """返回当前账户的 UUID 和第一个 SNI。"""
        if not self.node_configs: return {"uuid": "", "sni": ""}
        node = self.node_configs[min(self.config_index, len(self.node_configs)-1)]
        snis = node.get("snis", [])
        if not isinstance(snis, list): snis = [str(node.get("sni", "")).strip()] if node.get("sni") else []
        return {"account": self.config_index+1, "uuid": str(node.get("uuid", "")).strip(),
                "snis": snis, "sni": snis[0] if snis else ""}

    def apply_node_config(self, config, node_override=None):
        """把 UUID/SNI 应用到 Xray 配置；空值会清除模板中的内置值。"""
        node = node_override if node_override is not None else self.get_active_node_config()
        uuid = str(node.get("uuid", "")).strip()
        snis = node.get("snis", [])
        if not isinstance(snis, list): snis = [str(node.get("sni", "")).strip()] if node.get("sni") else []
        sni = str(node.get("sni", "")).strip() or (snis[0] if snis else "")

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
            creationflags = getattr(subprocess, "DETACHED_PROCESS", 0)
            if os.name == "nt":
                creationflags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
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
                        "tcp_successes": list(tcp_successes),
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

            scheduled_node = self._next_cf_node_config()
            self.apply_node_config(config, scheduled_node)

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

            # IPv6 候选 IP 单独记录；IPv4 保持原有扫描路径。
            try:
                target_is_ipv6 = ipaddress.ip_address(str(target_ip).strip()).version == 6
            except Exception:
                target_is_ipv6 = False

            # 只有 IPv6 候选使用 IPv6 专用路由设置，IPv4 不添加任何 IPv6 参数。
            if target_is_ipv6:
                sockopt = stream.setdefault("sockopt", {})
                sockopt["domainStrategy"] = "ForceIPv6"

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

            creationflags = getattr(subprocess, "DETACHED_PROCESS", 0)
            if os.name == "nt":
                creationflags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
            startupinfo = None
            if os.name == "nt":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE

            log_path = os.path.join(
                base, f"_xray_test_{socks_port}_{threading.get_ident()}.log"
            )
            log_file = open(log_path, "w", encoding="utf-8", errors="ignore")
            p = subprocess.Popen(
                [xray_path, "run", "-c", config_path],
                cwd=base, stdout=log_file, stderr=log_file,
                creationflags=creationflags,
                startupinfo=startupinfo
            )

            with self.xray_process_lock:
                self.xray_processes.add(p)

            # IPv6 Xray 首次建连可能明显慢于 IPv4；只放宽 IPv6。
            deadline = time.perf_counter() + (6.0 if target_is_ipv6 else 2.5)
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
                if target_is_ipv6:
                    print("IPv6 Xray 启动失败，保留日志:", log_path)
                return None, False

            # IPv4 完全沿用原来的 Xray 实测调用，不进入 IPv6 专用分支。
            # IPv6 才使用放宽后的超时参数。
            if target_is_ipv6:
                xray_result = self.test_vless_real_ping(socks_port, ipv6=True)
                if not xray_result[1]:
                    print("IPv6 Xray 实测失败，保留日志:", log_path)
            else:
                xray_result = self.test_vless_real_ping(socks_port)
            return xray_result

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
                    # IPv6 失败时保留 Xray 日志，方便定位真实原因；
                    # 成功或 IPv4 测试仍按原逻辑清理。
                    keep_ipv6_log = bool(locals().get("target_is_ipv6", False)) and (
                        locals().get("ready", False) is False or
                        locals().get("xray_result", (None, True))[1] is False
                    )
                    if not keep_ipv6_log and 'log_path' in locals() and os.path.isfile(log_path):
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

    def _expand_scan_network(self, value, max_ipv6_hosts=4096):
        """展开扫描目标，支持 IPv4 / IPv6 双栈。

        IPv4 保持原来的完整展开方式。
        IPv6 对很大的网段采用随机抽样，避免 /64 之类前缀被展开成天文数字。
        单个 IPv6 地址始终只扫描该地址。
        """
        value = str(value).strip()
        if not value:
            return []

        target = ipaddress.ip_network(value, strict=False)
        if target.version == 4:
            hosts = [str(ip) for ip in target.hosts()]
            if not hosts and target.num_addresses == 1:
                hosts = [str(target.network_address)]
            return hosts

        # IPv6：小网段完整扫描，大网段随机抽样。
        if target.num_addresses <= max_ipv6_hosts:
            hosts = [str(ip) for ip in target.hosts()]
            if not hosts and target.num_addresses == 1:
                hosts = [str(target.network_address)]
            return hosts

        # /64 等超大 IPv6 网段不能完整展开。
        # 抽样范围避开全 0 网络地址，最多生成 max_ipv6_hosts 个唯一地址。
        first = int(target.network_address)
        last = int(target.broadcast_address)
        if last <= first:
            return [str(target.network_address)]

        sample_count = min(max_ipv6_hosts, max(1, last - first))
        # Python 的 random.sample(range(...)) 对 2^64 / 2^128 级别的 range
        # 可能触发 OverflowError，因此这里按主机位随机生成偏移。
        host_bits = target.max_prefixlen - target.prefixlen
        values = set()
        while len(values) < sample_count:
            offset = random.getrandbits(host_bits)
            # 跳过网络地址，保留最多 max_ipv6_hosts 个唯一主机地址。
            if offset:
                values.add(offset)
        return [
            str(ipaddress.IPv6Address(first + offset))
            for offset in values
        ]

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
        """Windows 直连 TCP 延迟测试，支持 IPv4 / IPv6 双栈。

        IPv4 继续使用现有真实 IPv4 出口选择机制，避免 TUN/VPN 抢路由。
        IPv6 使用 AF_INET6，由 Windows IPv6 路由选择实际出口，不绑定 IPv4 地址。
        """
        sock = None
        start_ns = time.perf_counter_ns()

        try:
            ip_obj = ipaddress.ip_address(str(ip).strip())
            is_ipv6 = ip_obj.version == 6
            family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
            sock = socket.socket(family, socket.SOCK_STREAM)
            # IPv6 节点的实际公网 RTT 可能明显高于 IPv4。
            # IPv4 保持原来的 0.8 秒，不影响现有扫描速度；
            # IPv6 单独放宽到 3 秒，避免“V2能连、扫描器却判失败”。
            sock.settimeout(3.0 if is_ipv6 else 0.8)

            if os.name == "nt" and not is_ipv6:
                # IPv4 保留现有出口选择机制；IPv6 不走这里。
                iface = self._select_direct_tcp_interface()
                if iface:
                    try:
                        sock.setsockopt(
                            socket.IPPROTO_IP,
                            31,
                            struct.pack("I", socket.htonl(iface["index"]))
                        )
                    except Exception as e:
                        print("设置 TCP IPv4 出口接口失败:", e)

                    try:
                        sock.bind((iface["ip"], 0))
                    except Exception as e:
                        print("绑定真实 IPv4 失败:", e)

            if is_ipv6:
                result = sock.connect_ex((str(ip_obj), int(port), 0, 0))
            else:
                result = sock.connect_ex((str(ip_obj), int(port)))

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

    def test_vless_real_ping(self, socks_port=None, ipv6=False):
        """Xray real latency test aligned with v2rayN:
        establish SOCKS proxy once, then perform two HTTP requests on the same
        proxy connection and use the lower result. The measured interval starts
        immediately before each HTTP request, matching v2rayN's GetRealPingTime
        approach more closely.
        """
        sock = None

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # IPv4 保持原来的超时；IPv6 允许更长的建连和 HTTP 等待。
            proxy_timeout = 8.0 if ipv6 else 3.5
            handshake_timeout = 5.0 if ipv6 else 2.0
            http_timeout = 8.0 if ipv6 else 3.5
            sock.settimeout(proxy_timeout)

            if socks_port is None:
                socks_port = self.xray_port

            sock.connect(("127.0.0.1", socks_port))

            # SOCKS5 no-auth negotiation.
            sock.sendall(b"\x05\x01\x00")
            reply = self.recv_exact(sock, 2, handshake_timeout)
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

            reply = self.recv_exact(sock, 4, handshake_timeout)
            if (
                reply is None
                or len(reply) != 4
                or reply[0] != 5
                or reply[1] != 0
            ):
                return None, False

            atyp = reply[3]
            if atyp == 1:
                remain = self.recv_exact(sock, 6, handshake_timeout)
            elif atyp == 3:
                length_data = self.recv_exact(sock, 1, handshake_timeout)
                if not length_data:
                    return None, False
                remain = self.recv_exact(sock, length_data[0] + 2, handshake_timeout)
            elif atyp == 4:
                remain = self.recv_exact(sock, 18, handshake_timeout)
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
                deadline = time.perf_counter() + http_timeout
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

        # 下载测速也必须使用当前六账户轮换节点，不能回退到账户1。
        scheduled_node = self._next_cf_node_config()
        self.apply_node_config(config, scheduled_node)

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

        creationflags = getattr(subprocess, "DETACHED_PROCESS", 0)
        if os.name == "nt":
            creationflags |= getattr(subprocess, "CREATE_NO_WINDOW", 0)
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
        processed = 0
        max_per_cycle = 100

        while processed < max_per_cycle:
            try:
                msg = self.result_queue.get_nowait()
            except queue.Empty:
                break

            processed += 1

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
                    # TCP 成功但 Xray 实测失败的节点不进入主列表。
                    # 主列表只显示真正通过 Xray 实测的可用节点。
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

        row_tag = "good"
        if not self.tree.exists(ip):
            self.tree.insert(
                "", "end", iid=ip, values=values, tags=(row_tag,)
            )
        else:
            old = list(self.tree.item(ip)["values"])
            speed = old[4] if len(old) >= 5 else "测速"
            values = values[:4] + (speed,)
            self.tree.item(ip, values=values, tags=(row_tag,))

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
            "schedule_mode": "balance",
            "reserve_account1": 5000,
            "reserve_accounts2_6": 5,
            "balance_rotation_percent": 5,
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
                "schedule_mode": "drain" if str(data.get("schedule_mode", "balance")).lower() == "drain" else "balance",
                "reserve_account1": 5000,
                "reserve_accounts2_6": max(0, min(100, int(data.get("reserve_accounts2_6", 5) or 5))),
                "balance_rotation_percent": (
                    int(data.get("balance_rotation_percent", 5) or 5)
                    if int(data.get("balance_rotation_percent", 5) or 5) in (3, 5, 10, 15, 20)
                    else 5
                ),
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
                "schedule_mode": "drain" if str(config.get("schedule_mode", "balance")).lower() == "drain" else "balance",
                "reserve_account1": 5000,
                "reserve_accounts2_6": max(0, min(100, int(config.get("reserve_accounts2_6", 5) or 5))),
                "balance_rotation_percent": (
                    int(config.get("balance_rotation_percent", 5) or 5)
                    if int(config.get("balance_rotation_percent", 5) or 5) in (3, 5, 10, 15, 20)
                    else 5
                ),
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
            raise RuntimeError("额度后台地址格式错误，请填写实际配置的后台域名")
        return f"{parsed.scheme.lower()}://{parsed.netloc}"

    def _cf_quota_login_and_query(self, backend_url, username, password, progress_callback=None):
        """登录账户1后台，然后由账户1后台统一返回账户1~6额度。"""
        backend_url = self._normalize_cf_quota_backend_url(backend_url)
        if not backend_url:
            raise RuntimeError("请先填写额度后台地址")
        if not password:
            raise RuntimeError("请先填写后台密码")

        cookie_jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cookie_jar)
        )

        # 同一个后台地址 + 密码在本次程序运行期间只登录一次。
        # 返回再进入额度页面时直接复用已登录状态，不再重复调用 /login。
        login_key = (backend_url, password)
        if not self.cf_quota_logged_in or self.cf_quota_login_key != login_key:
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
                self.cf_quota_logged_in = False
                self.cf_quota_login_key = None
                raise RuntimeError("额度后台登录失败，请检查后台地址和密码")

            self.cf_quota_logged_in = True
            self.cf_quota_login_key = login_key

        usage_request = urllib.request.Request(
            backend_url + "/admin/get6AccountUsage?mode=" + urllib.parse.quote(self.cf_schedule_mode),
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


        return data

    def _refresh_cf_active_row(self, dialog, backend_url, password):
        """仅快速刷新当前正在使用账户的今日请求/剩余，不改变完整六账户刷新周期。"""
        if self.closing or self.cf_quota_dialog is not dialog or self.cf_quota_active_refreshing:
            return
        if not backend_url or not password:
            return

        self.cf_quota_active_refreshing = True

        def worker():
            try:
                data = self._cf_quota_login_and_query(backend_url, "", password)
                accounts = data.get("accounts", [])
                with self.cf_schedule_lock:
                    active_account = int(getattr(self, "cf_current_account", 6) or 6)
                idx = active_account - 1
                if 0 <= idx < len(accounts):
                    item = accounts[idx] or {}
                    used = int(item.get("todayUsed", 0) or 0)
                    remain = int(item.get("todayRemaining", 0) or 0)
                    limit = int(item.get("todayLimit", 0) or 0)
                    def apply():
                        if self.closing or self.cf_quota_dialog is not dialog:
                            return
                        if idx < len(self.cf_quota_rows):
                            row = self.cf_quota_rows[idx]
                            row["requests"].set(f"{used:,}")
                            row["remain"].set(f"{remain:,}")
                            row["limit"].set(f"{limit:,}")
                    self.root.after(0, apply)
            except Exception:
                pass
            finally:
                self.cf_quota_active_refreshing = False
                if dialog.winfo_exists() and not self.closing and self.cf_quota_dialog is dialog:
                    try:
                        self.cf_quota_active_refresh_after_id = dialog.after(
                            1000,
                            lambda: self._refresh_cf_active_row(dialog, backend_url, password)
                            if dialog.winfo_exists() and not self.closing and self.cf_quota_dialog is dialog
                            else None
                        )
                    except Exception:
                        self.cf_quota_active_refresh_after_id = None

    def open_cf_quota_manager(self):
        """六账户额度配置：直接覆盖主IP列表区域，不创建浮动窗口。"""
        # 两个配置页互斥：打开 CF 配置前，先自动返回 IP 主窗口。
        try:
            if getattr(self, "config_mode", False):
                self.close_node_config()
        except Exception:
            pass

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
        if backend_saved and re.match(r"^https?://", backend_saved, re.I):
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
        login_status_label = ttk.Label(
            form,
            textvariable=login_status_var
        )
        login_status_label.grid(row=2, column=2, columnspan=2, sticky="w", padx=(12, 0), pady=(2, 6))
        def set_login_status(text, logged_in=False):
            login_status_var.set("登录状态：" + text)
            try:
                login_status_label.configure(foreground="#000000" if logged_in else "#d00000")
            except Exception:
                pass
        set_login_status("已登录" if self.cf_quota_logged_in else "未登录", self.cf_quota_logged_in)

        table = ttk.Frame(frame)
        table.pack(fill="both", expand=True)

        headers = ["账户", "今日请求", "今日剩余", "UUID", "SNI"]
        widths = [8, 12, 12, 34, 24]
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
            node = self.node_configs[i] if i < len(self.node_configs) else {}
            uuid_var = tk.StringVar(value=str(node.get("uuid", "")).strip() or "—")
            snis = node.get("snis", [])
            if not isinstance(snis, list): snis = [str(node.get("sni", "")).strip()] if node.get("sni") else []
            sni_var = tk.StringVar(value=" | ".join([str(x).strip() for x in snis if str(x).strip()]) or "—")

            ttk.Label(table, textvariable=name_var, anchor="center", width=widths[0]).grid(
                row=i + 1, column=0, padx=2, pady=3
            )
            ttk.Label(table, textvariable=requests_var, anchor="center", width=widths[1]).grid(
                row=i + 1, column=1, padx=2, pady=3
            )
            ttk.Label(table, textvariable=remain_var, anchor="center", width=widths[2]).grid(
                row=i + 1, column=2, padx=2, pady=3
            )
            ttk.Label(table, textvariable=uuid_var, anchor="center", width=widths[3]).grid(
                row=i + 1, column=3, padx=2, pady=3
            )
            sni_label = ttk.Label(table, textvariable=sni_var, anchor="center", width=widths[4])
            sni_label.grid(
                row=i + 1, column=4, padx=2, pady=3
            )

            self.cf_quota_rows.append({
                "name": name_var,
                "requests": requests_var,
                "remain": remain_var,
                "limit": limit_var,
                "uuid": uuid_var,
                "sni": sni_var,
                "sni_label": sni_label,
            })

        bottom = ttk.Frame(frame)
        bottom.pack(fill="x", pady=(10, 0))

        total_var = tk.StringVar(value="")
        ttk.Label(bottom, textvariable=total_var, width=34).pack(side="left")

        schedule_mode_var = tk.BooleanVar(value=self.cf_schedule_mode == "drain")
        schedule_mode_text = tk.StringVar(value="放干模式" if schedule_mode_var.get() else "平衡模式")
        def sync_schedule_settings():
            threading.Thread(
                target=self._sync_cf_schedule_to_worker,
                args=(
                    backend_var.get().strip(),
                    password_var.get(),
                    self.cf_schedule_mode,
                    5,
                    self.cf_reserve_accounts2_6,
                    self.cf_balance_rotation_percent,
                ),
                daemon=True
            ).start()

        def on_schedule_mode_change():
            self.cf_schedule_mode = "drain" if schedule_mode_var.get() else "balance"
            schedule_mode_text.set("放干模式" if schedule_mode_var.get() else "平衡模式")
            self.cf_quota_accounts["schedule_mode"] = self.cf_schedule_mode
            self.cf_quota_accounts["balance_rotation_percent"] = self.cf_balance_rotation_percent
            self.save_cf_quota_config(self.cf_quota_accounts)
            sync_schedule_settings()

        def on_rotation_change(event=None):
            try:
                value = int(rotation_var.get().replace("%", "").strip())
            except Exception:
                value = 5
            if value not in (3, 5, 10, 15, 20):
                value = 5
            self.cf_balance_rotation_percent = value
            rotation_var.set(f"{value}%")
            self.cf_quota_accounts["balance_rotation_percent"] = value
            self.save_cf_quota_config(self.cf_quota_accounts)
            sync_schedule_settings()
        mode_box = ttk.Frame(bottom)
        mode_box.pack(side="left", padx=(18, 0))
        ttk.Checkbutton(
            mode_box,
            textvariable=schedule_mode_text,
            variable=schedule_mode_var,
            command=on_schedule_mode_change
        ).pack(side="left")

        rotation_box = ttk.Frame(bottom)
        rotation_box.pack(side="left", padx=(12, 0))
        ttk.Label(rotation_box, text="轮换").pack(side="left")
        rotation_values = ("3%", "5%", "10%", "15%", "20%")
        rotation_var = tk.StringVar(value=f"{self.cf_balance_rotation_percent}%")
        rotation_combo = ttk.Combobox(
            rotation_box,
            textvariable=rotation_var,
            values=rotation_values,
            state="readonly",
            width=5
        )
        rotation_combo.pack(side="left", padx=(3, 0))
        rotation_combo.bind("<<ComboboxSelected>>", on_rotation_change)

        reserve_box = ttk.Frame(bottom)
        reserve_box.pack(side="left", padx=(12, 0))
        ttk.Label(reserve_box, text="账户1：5000-10000").pack(side="left")
        ttk.Label(reserve_box, text="  账户2-6保留").pack(side="left", padx=(8, 0))
        reserve26_var = tk.StringVar(value=str(self.cf_reserve_accounts2_6))
        ttk.Entry(reserve_box, textvariable=reserve26_var, width=4).pack(side="left", padx=(3, 0))
        ttk.Label(reserve_box, text="%").pack(side="left")

        def on_close():
            # 先把入口恢复，再清理当前页面。这样连续“CF配置→返回”时，
            # 即使后台刷新线程刚好回调，也不会把按钮重新绑定到旧页面。
            self.quota_button.config(text="CF配置", command=self.open_cf_quota_manager)

            # 先失效当前页面引用，所有旧刷新回调都会被身份检查拦截。
            if self.cf_quota_dialog is dialog:
                self.cf_quota_dialog = None
            self.cf_quota_refreshing = False

            try:
                if self.cf_quota_refresh_after_id is not None:
                    dialog.after_cancel(self.cf_quota_refresh_after_id)
            except Exception:
                pass
            self.cf_quota_refresh_after_id = None

            # 立即隐藏 CF 页面，保证马上回到 IP 主窗口。
            try:
                dialog.place_forget()
            except Exception:
                pass
            try:
                self.config_overlay.place_forget()
                self.config_mode = False
                self.config_readonly = False
                self.tree.lift()
                # CF 配置页覆盖 Treeview 时会把右侧滚动条压到下面；
                # 返回主界面后重新提升滚动条，确保它立即可见。
                try:
                    self.tree_scrollbar.lift()
                except Exception:
                    pass
            except Exception:
                pass

            # 延后一拍销毁旧页面，避免当前 Tk 回调链中途销毁自身造成
            # 连续点击时出现“返回失效”。
            try:
                dialog.after_idle(lambda: dialog.destroy() if dialog.winfo_exists() else None)
            except Exception:
                pass
        self.quota_button.config(text="返回", command=on_close)

        save_button = ttk.Button(bottom, text="保存配置", width=11)
        save_button.pack(side="right", padx=(6, 0))


        def save_config():
            config = {
                "backend_url": backend_var.get().strip().rstrip("/"),
                "username": username_var.get().strip(),
                "password": password_var.get(),
                "remember": bool(remember_var.get()),
                "schedule_mode": self.cf_schedule_mode,
                "reserve_account1": 5000,
                "reserve_accounts2_6": max(0, min(100, int(reserve26_var.get().strip() or 3))),
                "balance_rotation_percent": self.cf_balance_rotation_percent,
            }
            if not config["backend_url"]:
                messagebox.showwarning("提示", "请填写额度后台地址。", parent=dialog)
                return
            if self.save_cf_quota_config(config):
                self.cf_quota_accounts = config
                self.cf_reserve_accounts2_6 = config["reserve_accounts2_6"]
                self.cf_balance_rotation_percent = config["balance_rotation_percent"]
                threading.Thread(
                    target=self._sync_cf_schedule_to_worker,
                    args=(
                        config["backend_url"],
                        config["password"],
                        config["schedule_mode"],
                        5,
                        config["reserve_accounts2_6"],
                        config["balance_rotation_percent"],
                    ),
                    daemon=True
                ).start()
                if not config["remember"]:
                    password_var.set("")
                messagebox.showinfo("提示", "额度后台配置已保存，调度设置正在同步。", parent=dialog)
            else:
                messagebox.showerror("错误", "额度后台配置保存失败。", parent=dialog)

        def refresh():
            if self.cf_quota_dialog is not dialog:
                return
            self.cf_quota_refresh_after_id = None
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

            # 刷新时保留当前表格内容，不清空、不显示“读取中…”。
            # 新数据返回后直接覆盖对应数值。
            def progress_callback(message):
                if dialog.winfo_exists():
                    try:
                        dialog.after(0, lambda m=message: login_status_var.set("登录状态：" + m))
                    except Exception:
                        pass

            threading.Thread(
                target=self._refresh_cf_quota_worker,
                args=(dialog, total_var, backend_url, username, password, progress_callback, login_status_var, login_status_label, refresh),
                daemon=True
            ).start()

        save_button.config(command=save_config)

        # 打开后立即尝试读取一次；之后每 30 秒自动刷新。
        refresh()

    def _refresh_cf_quota_worker(
        self, dialog, total_var,
        backend_url, username, password, progress_callback=None, login_status_var=None, login_status_label=None, refresh_callback=None
    ):
        try:
            data = self._cf_quota_login_and_query(
                backend_url, username, password, progress_callback=progress_callback
            )
            self._last_cf_quota_data = data
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

        def set_login_status(text, logged_in=False):
            if login_status_var is not None:
                login_status_var.set("登录状态：" + text)
            if login_status_label is not None:
                try:
                    login_status_label.configure(foreground="#000000" if logged_in else "#d00000")
                except Exception:
                    pass

        def apply_results():
            if self.closing:
                return

            for i, used, remain, limit, error in results:
                if i >= len(self.cf_quota_rows):
                    continue
                row = self.cf_quota_rows[i]

                if error:
                    # 读取失败时保留原来的数值，只更新状态。
                    row["sni"].set(row["sni"].get() or "—")
                    continue

                row["name"].set(f"账户{i + 1}")
                row["requests"].set(f"{used:,}")
                row["remain"].set(f"{remain:,}")
                row["limit"].set(f"{limit:,}")
                row["sni"].set(row["sni"].get() or "—")

            if total_requests is not None:
                self._set_cf_schedule(getattr(self, "_last_cf_quota_data", {}))
                # 直接给 SNI 列着色：
                # 绿色 = 当前正在使用；黄色 = 到达保留/限制点；红色 = 已放干。
                with self.cf_schedule_lock:
                    active_account = int(getattr(self, "cf_current_account", 6) or 6)
                for i, row in enumerate(self.cf_quota_rows):
                    if results[i][4] is None:
                        remain_value = results[i][2]
                        account_no = i + 1
                        limit_value = results[i][3]
                        if account_no == 1:
                            reserve_value = self.cf_account1_min_remaining
                        else:
                            reserve_value = (
                                int(limit_value * self.cf_reserve_accounts2_6 / 100)
                                if limit_value is not None
                                else 0
                            )

                        try:
                            if remain_value is not None and remain_value <= 0:
                                row["sni_label"].configure(foreground="#d00000")
                            elif remain_value is not None and remain_value <= reserve_value:
                                row["sni_label"].configure(foreground="#d4a000")
                            elif account_no == active_account and remain_value is not None and remain_value > 0:
                                row["sni_label"].configure(foreground="#008000")
                            else:
                                row["sni_label"].configure(foreground="#333333")
                        except Exception:
                            pass

            if total_requests is None:
                error_text = next((x[4] for x in results if x[4]), "未知错误")
                error_lower = str(error_text).lower()
                if "登录失败" in str(error_text) or "http 401" in error_lower or "http 403" in error_lower:
                    self.cf_quota_logged_in = False
                    self.cf_quota_login_key = None
                    set_login_status("未登录", False)
                total_var.set("")
            else:
                set_login_status("已登录", True)
                total_var.set("")

            self.cf_quota_refreshing = False

            # 当前正在使用的 SNI 单独快速刷新：每 1 秒更新该账户的今日请求/今日剩余。
            # 六账户完整刷新仍保持原来的 5 秒周期。
            try:
                if dialog.winfo_exists() and not self.closing and self.cf_quota_dialog is dialog:
                    self.cf_quota_active_refresh_after_id = dialog.after(
                        1000,
                        lambda: self._refresh_cf_active_row(dialog, backend_url, password)
                        if dialog.winfo_exists() and not self.closing and self.cf_quota_dialog is dialog
                        else None
                    )
            except Exception:
                self.cf_quota_active_refresh_after_id = None

            # 自动刷新：记录 after ID；关闭窗口时会明确取消，避免返回后又触发一次登录。
            if dialog.winfo_exists() and not self.closing and self.cf_quota_dialog is dialog:
                try:
                    self.cf_quota_refresh_after_id = dialog.after(
                        CF_QUOTA_REFRESH_SECONDS * 1000,
                        lambda: refresh_callback()
                        if dialog.winfo_exists() and not self.cf_quota_refreshing and self.cf_quota_dialog is dialog and refresh_callback is not None
                        else None
                    )
                except Exception:
                    self.cf_quota_refresh_after_id = None

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
        self.update_status()

        # 上传成功属于正常提示，不占用 Xray 错误状态区域。
        self.lbl_progress.config(
            text=f"上传成功：已上传 {count} 个 Xray 可用节点到 CF"
        )

    def _upload_failed(self, error):
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
        else:
            # 关闭软件也保存最后一次累计计时；只有“清空列表”才会删除断点并清零。
            self.save_scan_checkpoint(force=True)
        self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = NirSoftCFScanner(root)
    root.mainloop()
