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
import urllib.request
import urllib.parse
import http.cookiejar

# ============================================================
# Cloudflare & 第三方节点 IP 优选工具
# 扫描停止与 Xray 停止彻底分离版
# 新增：上传 Xray 成功节点到 CF /admin/ADD.txt
# 新增：表头「下载速度」列，双击测速（与延迟测试分离）
# ============================================================

CF_ADMIN_BASE_URL = "https://cvx.x83870.workers.dev"
CF_LOGIN_URL = CF_ADMIN_BASE_URL + "/login"
CF_ADD_URL = CF_ADMIN_BASE_URL + "/admin/ADD.txt"
CF_USAGE_URL = CF_ADMIN_BASE_URL + "/admin/get6AccountUsage"
CF_PASSWORD_FILE = "cf_upload_config.json"


class NirSoftCFScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("IP 节点优选工具 - TCP + Xray + 下载测速")
        self.root.geometry("960x520")
        self.root.minsize(780, 400)

        self.running = False
        self.closing = False

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

        # 扫描计时
        self.scan_start_time = None
        self.last_scan_elapsed = 0.0

        self.workers = []
        self.xray_workers = []
        self.xray_task_queue = queue.Queue(maxsize=300)
        self.index_lock = threading.Lock()
        self.xray_lock = threading.Lock()
        self.xray_processes = set()
        self.xray_process_lock = threading.Lock()

        self.xray_process = None
        self.xray_port = 10819

        # 六账户 CF 免费额度状态
        self.cf_usage_data = None
        self.cf_usage_refreshing = False

        # 表头排序状态：当前排序列 & 是否升序
        self.sort_column = None
        self.sort_reverse = False

        self.setup_styles()
        self.build_ui()

        self.root.after(80, self.update_results)
        self.root.after(500, self._tick_scan_timer)
        self.root.after(3000, self.refresh_cf_usage)
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

        ttk.Label(top, text="目标/网段:").pack(side="left", padx=(2, 2))

        self.subnet_entry = ttk.Entry(top, width=22)
        self.subnet_entry.insert(0, "38.147.171.110")
        self.subnet_entry.pack(side="left", padx=(0, 8))

        ttk.Label(top, text="端口:").pack(side="left", padx=(2, 2))

        self.port_entry = ttk.Entry(top, width=24)
        self.port_entry.insert(0, "443,8443,2053,2083,2087,2096")
        self.port_entry.pack(side="left", padx=(0, 8))

        ttk.Label(top, text="线程:").pack(side="left", padx=(2, 2))

        self.worker_entry = ttk.Entry(top, width=5)
        self.worker_entry.insert(0, "30")
        self.worker_entry.pack(side="left", padx=(0, 8))

        self.start_button = ttk.Button(
            top,
            text="开始打野",
            width=9,
            command=self.toggle_scan
        )
        self.start_button.pack(side="left", padx=(0, 5))

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

        self.tree.heading(
            "ip",
            text="IP 地址",
            command=lambda: self.sort_by_column("ip")
        )
        self.tree.heading(
            "ports",
            text="可用端口",
            command=lambda: self.sort_by_column("ports")
        )
        self.tree.heading(
            "tcp",
            text="TCP延迟",
            command=lambda: self.sort_by_column("tcp")
        )
        self.tree.heading(
            "xray",
            text="Xray真延迟",
            command=lambda: self.sort_by_column("xray")
        )
        self.tree.heading(
            "speed",
            text="下载速度",
            command=lambda: self.sort_by_column("speed")
        )

        self.tree.column("ip", width=180, anchor="center")
        self.tree.column("ports", width=180, anchor="center")
        self.tree.column("tcp", width=140, anchor="center")
        self.tree.column("xray", width=140, anchor="center")
        self.tree.column("speed", width=140, anchor="center")

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

        self.tree.tag_configure("good", foreground="#008000")
        self.tree.tag_configure("normal", foreground="#333333")
        self.tree.tag_configure("testing", foreground="#0000FF")
        self.tree.tag_configure("fail", foreground="#999999")

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
            text="就绪（双击延迟列=刷新延迟 | 双击下载速度列=测速）",
            font=("Microsoft YaHei UI", 9)
        )
        self.lbl_progress.pack(side="left", padx=(2, 15))

        self.lbl_xray_status = ttk.Label(
            self.statusbar,
            text="Xray:已停止",
            font=("Microsoft YaHei UI", 9)
        )
        self.lbl_xray_status.pack(side="left")

        self.lbl_cf_usage = ttk.Label(
            self.statusbar,
            text="CF免费额度: 未读取",
            font=("Microsoft YaHei UI", 9)
        )
        self.lbl_cf_usage.pack(side="right", padx=(8, 2))

        # ====================================================
        # 右键菜单
        # ====================================================
        self.context_menu = tk.Menu(self.root, tearoff=0)

        self.context_menu.add_command(
            label="重新测试此IP（延迟）",
            command=self.retest_selected_ip
        )

        self.context_menu.add_command(
            label="测试下载速度",
            command=self.speed_test_selected_ip
        )

        self.context_menu.add_separator()

        self.context_menu.add_command(
            label="复制选中IP",
            command=self.copy_selected_ip
        )

        self.context_menu.add_command(
            label="复制选中IP:端口",
            command=self.copy_selected_ip_port
        )

        self.context_menu.add_separator()

        self.context_menu.add_command(
            label="复制所有可用IP",
            command=self.copy_all_valid_ips
        )

        self.context_menu.add_command(
            label="复制所有可用IP:端口",
            command=self.copy_all_valid_ip_ports
        )

    def fast_scroll(self, event):
        self.tree.yview_scroll(int(-event.delta / 24), "units")
        return "break"

    def toggle_scan(self):
        if self.running:
            self.stop_scan()
        else:
            self.start_scan()

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

        raw = self.subnet_entry.get().strip()

        parts = [
            x.strip()
            for x in raw.split(",")
            if x.strip()
        ]

        gathered_ips = []

        try:
            for part in parts:
                network = ipaddress.ip_network(part, strict=False)

                hosts = [
                    str(ip)
                    for ip in network.hosts()
                ]

                if not hosts and network.num_addresses == 1:
                    hosts = [str(network.network_address)]

                gathered_ips.extend(hosts)

            if not gathered_ips:
                raise ValueError

        except Exception:
            messagebox.showerror(
                "错误",
                "IP 或网段格式不正确。"
            )
            return

        random.shuffle(gathered_ips)
        self.ip_list = gathered_ips

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
        self.tested = 0
        self.success = 0
        self.next_index = 0

        self.results.clear()
        self.scan_ports = ports
        self.ip_scan_states = {}

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

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.running = True
        self.scan_start_time = time.perf_counter()
        self.last_scan_elapsed = 0.0

        self.start_button.config(text="停止打野")
        self.set_inputs_state(False)

        self.upload_button.config(state="disabled")

        self.lbl_xray_status.config(
            text="Xray: 10 路并发"
        )

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
        self.scan_stop_event.set()

        self.running = False
        if self.scan_start_time is not None:
            self.last_scan_elapsed = time.perf_counter() - self.scan_start_time
            self.scan_start_time = None

        self.start_button.config(text="开始打野")
        self.set_inputs_state(True)

        self.xray_stop_event.set()
        self.force_stop_all_xray()
        self.force_stop_xray()

        self.upload_button.config(state="normal")

        self.update_status()

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
                lambda: self.lbl_xray_status.config(
                    text="Xray: 已停止"
                )
            )
        except Exception:
            pass

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
                    try:
                        self.root.after(
                            0,
                            lambda: self.lbl_xray_status.config(
                                text="Xray: 运行中"
                            )
                        )
                    except Exception:
                        pass

                    return True

            except Exception:
                pass

            time.sleep(0.04)

        self.force_stop_xray()
        return False

    def worker(self):
        """低资源流水线 TCP worker。
        一个 IP 仍由一个 worker 按端口顺序测试，避免 IP×端口全面爆发。
        但 TCP 一旦发现可用端口，就立即投递给 Xray，不再等该 IP 的所有端口测完。
        """
        while not self.scan_stop_event.is_set():
            ip = None
            try:
                with self.index_lock:
                    if self.next_index >= self.total:
                        break
                    index = self.next_index
                    self.next_index += 1

                ip = self.ip_list[index]
                state = {
                    "pending": 0,
                    "tcp_finished": False,
                    "ports": [],
                    "best_delay": None,
                    "best_tcp": None,
                }
                with self.index_lock:
                    self.ip_scan_states[ip] = state

                for target_port in self.scan_ports:
                    if self.scan_stop_event.is_set():
                        break

                    tcp_delay, tcp_ok = self.test_tcp(ip, target_port)
                    if not tcp_ok:
                        continue

                    with self.index_lock:
                        state["pending"] += 1

                    # TCP 成功立即进入 Xray 队列，让 TCP 与 Xray 形成真正流水线。
                    task = (ip, target_port, tcp_delay)
                    while not self.scan_stop_event.is_set():
                        try:
                            self.xray_task_queue.put(task, timeout=0.2)
                            break
                        except queue.Full:
                            # Xray 忙时只短暂让出，不让大量 TCP 线程空转。
                            continue

                with self.index_lock:
                    state["tcp_finished"] = True
                    pending = state["pending"]

                if pending == 0:
                    self.result_queue.put(("ip_done", ip, [], None, None))

            except Exception as e:
                print("TCP 扫描线程异常:", e)
                if ip is not None and not self.scan_stop_event.is_set():
                    with self.index_lock:
                        state = self.ip_scan_states.get(ip)
                        if state is not None:
                            state["tcp_finished"] = True
                            if state["pending"] == 0:
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
        """启动一个独立 Xray 实例测试指定 IP:端口，测试完成立即释放。"""
        base = os.path.dirname(os.path.abspath(__file__))
        xray_path = os.path.join(base, "xray.exe")
        template_path = os.path.join(base, "test.json")

        try:
            with open(template_path, "r", encoding="utf-8") as f:
                config = json.load(f)

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
                stream.setdefault("wsSettings", {}).setdefault("path", "/")

            config_path = os.path.join(
                base, f"_xray_test_{socks_port}_{threading.get_ident()}.json"
            )
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4, ensure_ascii=False)

            creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            startupinfo = None
            if os.name == "nt":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE
            p = subprocess.Popen(
                [xray_path, "run", "-c", config_path],
                cwd=base, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=creationflags,
                startupinfo=startupinfo
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
                    if 'config_path' in locals() and os.path.isfile(config_path):
                        os.remove(config_path)
                except Exception:
                    pass

    def run_isolated_xray_speed_test(self, target_ip, target_port):
        """启动独立 Xray 实例，通过 SOCKS 下载测速文件，测完立即释放。
        返回 (speed_MBps, ok, reason)。与延迟测试完全分离。
        """
        base = os.path.dirname(os.path.abspath(__file__))
        xray_path = os.path.join(base, "xray.exe")
        template_path = os.path.join(base, "test.json")

        if not os.path.isfile(xray_path):
            return None, False, "无xray.exe"
        if not os.path.isfile(template_path):
            return None, False, "无test.json"

        try:
            with open(template_path, "r", encoding="utf-8") as f:
                config = json.load(f)

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                socks_port = s.getsockname()[1]

            inbounds = config.get("inbounds", [])
            if not inbounds:
                return None, False, "无inbounds"
            inbounds[0]["listen"] = "127.0.0.1"
            inbounds[0]["port"] = socks_port

            outbounds = config.get("outbounds", [])
            if not outbounds:
                return None, False, "无outbounds"

            vnext = outbounds[0].get("settings", {}).get("vnext", [])
            if not vnext:
                return None, False, "无vnext"

            vnext[0]["address"] = target_ip
            vnext[0]["port"] = int(target_port)

            stream = outbounds[0].setdefault("streamSettings", {})
            tls = stream.get("tlsSettings")
            if isinstance(tls, dict):
                tls.pop("allowInsecure", None)
            if stream.get("network") == "ws":