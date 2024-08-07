import json
import os.path
import re
import socket
import subprocess
import threading
import time
from tkinter import simpledialog

import paramiko

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class MySsh:
    def __init__(self):
        # 实例化 ，ssh服务器的会话高级表现形式，把通道/传输类/sftp进行了封装
        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.path = "~"
        # 所有服务器的列表
        self.servers = []
        # 当前正在使用的服务器信息
        self.server = {}
        self.load_server()
        self.connected = []

    def load_server(self):
        with open('server.json', "r", encoding='utf-8') as fp:
            self.servers = json.load(fp)
        print(f"获取到的服务器信息：{self.servers}")

    def save_server(self):
        with open('server.json', "w", encoding='utf-8') as fp:
            fp.write(json.dumps(self.servers))

    def add_server(self, ip, port, username, password, description):
        self.servers.append({
            "description": description,
            "ip": ip,
            "port": port,
            "username": username,
            "password": password
        })
        self.save_server()

    # def find_server(self,ip):

    def connecting(self):
        self.connected = None
        # 将信任的主机自动添加到know_hosts文件（~/.ssh/）中
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
        try:
            # 连接到服务器
            self.ssh.connect(hostname=self.server["ip"], port=self.server["port"], username=self.server["username"],
                             password=self.server["password"])
            # messagebox.showinfo("成功", f"连接到服务器【{self.server['ip']}】成功！")
            print(f"连接到服务器【{self.server['ip']}】成功！")
            self.connected = True
            self.get_pwd()
            return True
        except Exception as e:
            messagebox.showerror("错误", f"连接到服务器【{self.server['ip']}】失败！")
            self.connected = False
            return False

    def exec(self, command):
        if command.startswith("cd"):
            tmp_path = command.split(" ")[-1]
            if tmp_path.startswith("/"):
                # 绝对路径处理
                self.path = tmp_path
            else:
                # todo 如果用户输入的是一个相对路径呢？
                print("用户输入的是相对路径")
                if tmp_path.startswith(".."):
                    self.path = self.path + "/" + tmp_path
                else:
                    self.path = self.path + tmp_path
        else:
            # 根据当前的路径去执行指令
            command = f"cd {self.path} && {command}"
        print(f"->输入指令({self.path})：{command}")
        stdin, stdout, stderr = self.ssh.exec_command(command)
        result = stdout.read().decode("utf-8")
        print(f"<-返回：{result}")
        # 用户输入的路径里包含.. ，通过pwd刷新当前路径
        if command.find("..") > 0:
            self.get_pwd()
        return result

    def _read_channel(self, channel, output_callback):
        """在独立线程中读取通道输出，并调用回调函数处理"""
        while True:
            if channel.recv_ready():
                data = channel.recv(1024)
                output_callback(data)

    def download_file(self):
        remote_file = tk.simpledialog.askstring("输入文件名", "请输入要下载的文件名:")
        if remote_file is None:  # 用户点击“取消”或关闭对话框
            return
        elif not remote_file:  # 用户输入了空字符串
            
            messagebox.showerror("错误", "请输入文件名！")
            return
        local_path = filedialog.askdirectory(title="选择下载到的本地目录")
        if local_path:
            try:
                sftp = self.ssh.open_sftp()
                local_file_path = os.path.join(local_path, remote_file)
                sftp.get(remote_file, local_file_path)
                sftp.close()
                messagebox.showinfo("下载成功", f"文件下载成功: {remote_file} -> {local_path}")
            except Exception as e:
                messagebox.showerror("下载失败", f"文件下载失败: {e}")

    def watch_and_upload(self, local_file_path, remote_full_path):
        class FileModifiedHandler(FileSystemEventHandler):
            #ssh_handler是一个SSH处理程序的实例，remote_full_path是远程文件的完整路径。
            def __init__(self, ssh_handler, remote_full_path):
                self.ssh_handler = ssh_handler
                self.remote_full_path = remote_full_path

            def on_modified(self, event):
                if event.is_directory or not event.src_path == local_file_path:
                    return
                # messagebox.showinfo("文件被修改", f"文件被修改：{event.src_path}")
                try:
                    # self.ssh_handler.connecting()  # 重新连接SSH（如果需要）
                    sftp = self.ssh_handler.ssh.open_sftp()
                    sftp.put(local_file_path, self.remote_full_path)
                    sftp.close()
                    messagebox.showinfo("文件上传成功", f"vim修改成功: {local_file_path} -> {self.remote_full_path}")
                except Exception as e:
                    messagebox.showerror("文件上传失败", f"文件上传失败: {e}")

        event_handler = FileModifiedHandler(self, remote_full_path)
        observer = Observer()
        observer.schedule(event_handler, path=os.path.dirname(local_file_path), recursive=False)
        observer.start()

        try:
            # 等待用户操作或其他信号来停止监视
            # 这里使用time.sleep作为示例，但建议使用更好的机制，如事件或信号
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()

        observer.join()

    def vim_edit(self):
        remote_file = simpledialog.askstring("vim", "请输入要编辑的完整远程文件路径:")
        if remote_file is None:  # 用户点击“取消”或关闭对话框
            return
        elif not remote_file:  # 用户输入了空字符串
            messagebox.showerror("错误", "请输入文件路径！")
            return

            # 检查用户是否输入了以'/'开头的绝对路径
        if not remote_file.startswith('/'):
            messagebox.showerror("错误", "请输入绝对路径，例如：/home/user/file.txt")
            return

            # 临时文件目录
        tmp = filedialog.askdirectory(title="选择下载到的本地目录")
        if not tmp:  # 用户取消了选择目录
            return

        local_file_path = os.path.join(tmp, os.path.basename(remote_file))

        try:
            self.connecting()
            sftp = self.ssh.open_sftp()
            # 检查远程文件是否存在
            try:
                sftp.stat(remote_file)
            except FileNotFoundError:
                # 如果不存在，则在远程服务器上创建空文件
                with sftp.open(remote_file, 'wb') as f:
                    pass  # 写入空内容或者模板内容
            # 下载文件到本地
            sftp.get(remote_file, local_file_path)
            sftp.close()

            # 启动文件监视线程
            watch_thread = threading.Thread(target=self.watch_and_upload, args=(local_file_path, remote_file))
            watch_thread.start()

            # 打开文件编辑器
            subprocess.run(['Code', local_file_path], shell=True)

        except Exception as e:
            messagebox.showerror("文件下载失败", f"文件下载失败：{e}")
            print(f"文件下载失败：{e}")

    # 使用pwd更新当前路径
    def get_pwd(self):
        stdin, stdout, stderr = self.ssh.exec_command(f"cd {self.path} && pwd")
        result = stdout.read().decode("utf-8")
        self.path = result.strip()


import tkinter as tk
from tkinter import ttk, filedialog
from tkinter import messagebox


class MyUI:
    def __init__(self, ssh):
        print("初始化")
        self.is_connected = False
        self.mssh = ssh
        self.mssh_channel = None

        # 主应用程序窗口
        self.root = tk.Tk()
        frame = ttk.Frame(self.root)
        self.root.geometry("800x550")

        # 设置窗口标题（可选）
        self.root.title("暗影坤手")

        # 使用 grid 布局
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        # 布局，网格布局
        # 创建一个框架容器
        frame = ttk.Frame(self.root)
        frame.grid(sticky="nsew")

        # 添加菜单项   连接：新建连接  打开连接 操作：-- 帮助：--
        menu_top = tk.Menu(self.root)

        # 连接菜单
        menu_link = tk.Menu(menu_top)
        menu_top.add_cascade(label="连接", menu=menu_link)
        menu_link.add_command(label="新建连接", command=self.new_connect_ui)
        menu_link.add_command(label="打开连接", command=self.open_connect_ui)

        # 操作菜单
        menu_func = tk.Menu(menu_top)
        menu_top.add_cascade(label="操作", menu=menu_func)
        menu_func.add_command(label="上传文件", command=self.upload_file)
        menu_func.add_command(label="下载文件", command=self.downloader)
        menu_func.add_command(label="vim编辑文件", command=self.vim_edit)

        # 帮助菜单
        menu_help = tk.Menu(menu_top)
        menu_top.add_cascade(label="帮助", menu=menu_help)
        menu_help.add_command(label="查看进程", command=self.get_process)
        # menu_help.add_command(label="查看磁盘使用情况", command=self.view_disk_usage)

        # 扩展菜单
        menu_ext = tk.Menu(menu_top)
        menu_top.add_cascade(label="扩展", menu=menu_ext)
        menu_ext.add_command(label="批量下载日志文件", command=self.download_logs)
        menu_ext.add_command(label="查看日志文件", command=self.view_log)

        # 展示信息的label
        self.label_server = ttk.Label(frame, text="服务器信息：")
        self.label_server.grid(row=0, column=0, sticky="w", padx=10, pady=5)

        # 输入指令框
        self.command = tk.StringVar()
        entry_command = ttk.Entry(frame, width=60, textvariable=self.command)
        entry_command.grid(row=1, column=0, sticky="ew", padx=10, pady=5)

        # 执行指令的按钮
        entry_command.bind("<Return>", self.ok)  # 当按下Enter键时执行命令
        entry_command.bind("<Control-c>", self.okk)

        # 展示结果
        self.txt_result = tk.Text(frame)
        self.txt_result.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)
        self.root.config(menu=menu_top)

        # 文本框背景/前景颜色
        self.txt_result.config(bg="#262626", fg="#D9D9D9")
        self.root.config(menu=menu_top)

        # 导入 ttk 后
        style = ttk.Style()

        # 设置 ttk 主题
        style.theme_use("clam")

        # 定制按钮样式
        style.configure("TButton", foreground="white", background="#404040")
        style.map("TButton",
                  foreground=[("active", " #CCCCCC"), ("disabled", "#666666")],
                  background=[("active", "#404040"), ("disabled", "#262626")])

        # 让文本框自动扩展以填充剩余空间
        frame.grid_rowconfigure(2, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=0)  # 信息监控面板不需要扩展

        # thread_info=threading.Thread(target=self.update_info)
        thread_info = threading.Thread(target=self.update_info, args=(frame,))
        thread_info.start()

        # 将主应用程序挂起
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing_main)
        self.root.mainloop()

    def okk(self, event):
        self.command.set('q')
        self.ok(self)

#用于处理从SSH通道中接收到的输出数据
    def handle_output(self, data):
        # 先解码数据
        decoded_data = data.decode("utf-8")
        # 去除颜色转义序列
        cleaned_data = re.sub(r'\x1B\[([0-?]*[ -/]*[@-~])', '', decoded_data)
        # 插入到文本框的末尾
        self.txt_result.insert(tk.END, cleaned_data)
        # 确保滚动条跟随到最后
        self.txt_result.see(tk.END)

    # ------------------------------------------帮助---------------------------------------------------
    def get_process(self):
        if not self.mssh.connected:
            messagebox.showerror("错误", "请先连接到服务器!")
            return

        self.pop_win = tk.Toplevel(self.root)
        self.pop_win.title("进程")
        self.pop_win.geometry("800x600+600+250")

        table_frame = ttk.Frame(self.pop_win)
        table_frame.pack(padx=10, pady=10, fill="both", expand=True)

        server = self.mssh.server
        ip = server['ip']
        username = server['username']
        password = server['password']

        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, 22, username, password)
            stdin, stdout, stderr = client.exec_command("ps -ef")
            result = stdout.read().decode("utf-8").strip().split("\n")

            # 创建表格
            table = ttk.Treeview(table_frame, columns=(
                "user", "pid", "cpu", "mem", "vsz", "rss", "tty", "stat", "start", "time", "command"), show="headings")
            table.heading("user", text="用户")
            table.heading("pid", text="进程ID")
            table.heading("cpu", text="CPU%")
            table.heading("mem", text="内存%")
            table.heading("vsz", text="虚拟内存")
            table.heading("rss", text="常驻内存")
            table.heading("tty", text="终端")
            table.heading("stat", text="状态")
            table.heading("start", text="启动时间")
            table.heading("time", text="CPU时间")
            table.heading("command", text="命令")
            table.pack(side="left", fill="both", expand=True)

            # 添加滚动条
            scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=table.yview)
            scrollbar.pack(side="right", fill="y")
            table.configure(yscrollcommand=scrollbar.set)

            # 填充表格数据
            for line in result[1:]:
                parts = line.split()
                if len(parts) >= 10:
                    user, pid, cpu, mem, vsz, rss, tty, stat, start, time, *command = parts
                    command = " ".join(command)
                    table.insert("", "end", values=(user, pid, cpu, mem, vsz, rss, tty, stat, start, time, command))

            # 调整列宽度
            table.column("#0", width=0, stretch="no")  # 隐藏第一列
            table.column("user", width=80, anchor="w")
            table.column("pid", width=60, anchor="e")
            table.column("cpu", width=60, anchor="e")
            table.column("mem", width=60, anchor="e")
            table.column("vsz", width=100, anchor="e")
            table.column("rss", width=100, anchor="e")
            table.column("tty", width=60, anchor="w")
            table.column("stat", width=60, anchor="w")
            table.column("start", width=120, anchor="w")
            table.column("time", width=80, anchor="e")
            table.column("command", width=300, anchor="w")

            # 自动调整行高
            def fixed_map(option):
                return [elm for elm in style.map("Treeview", query_opt=option) if elm[:2] != ("!disabled", "!selected")]

            style = ttk.Style()
            style.map("Treeview", foreground=fixed_map("foreground"), background=fixed_map("background"))

        except paramiko.AuthenticationException:
            messagebox.showerror("错误", "认证失败,请验证您的凭据")
        except paramiko.SSHException as sshException:
            messagebox.showerror("错误", f"无法建立SSH连接: {sshException}")
        except paramiko.BadHostKeyException as badHostKeyException:
            messagebox.showerror("错误", f"无法验证服务器的主机密钥: {badHostKeyException}")
        except Exception as e:
            messagebox.showerror("错误", f"发生错误: {e}")
        finally:
            if 'client' in locals() and client:
                client.close()  # 确保连接被关闭

        # 当窗口关闭时,确保没有遗留的引用或连接
        self.pop_win.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_widgets(self, frame):
        self.cpu_label = ttk.Label(frame, text="CPU信息：")
        self.cpu_label.grid()

        self.cpu_progress = ttk.Progressbar(frame, orient='horizontal', length=200, mode='determinate')
        self.cpu_progress.grid(pady=(0, 10))

        self.mem_label = ttk.Label(frame, text="Memory Usage: 0 MB / 0 MB")
        self.mem_label.grid()

        self.mem_progress = ttk.Progressbar(frame, orient='horizontal', length=200, mode='determinate')
        self.mem_progress.grid(pady=(0, 5))

        self.net_label = ttk.Label(frame, text="网络信息：")
        self.net_label.grid(pady=5)

        self.disk_button = tk.Button(frame, text="查看磁盘使用情况", command=self.show_disk_usage)
        self.disk_button.grid(pady=(5, 5))

    def update_info(self, frame):
        self.create_widgets(frame)  # 创建标签
        # 定义进度条样式
        style = ttk.Style()
        style.theme_use("default")
        style.configure("green.Horizontal.TProgressbar", foreground='green', background='green')
        style.configure("yellow.Horizontal.TProgressbar", foreground='yellow', background='yellow')
        style.configure("red.Horizontal.TProgressbar", foreground='red', background='red')
        prev_connected = self.mssh.connected  # 记录上一次的连接状态
        while True:
            if "ip" in self.mssh.server:
                if self.mssh.connected == None:
                    result_connect = (f"服务器{self.mssh.server['ip']}连接中", "red")
                    self.reset_system_monitoring()  # 重置系统监控状态

                elif self.mssh.connected:
                    result_connect = (f"服务器{self.mssh.server['ip']}连接成功", "green")
                    # -----------------------------系统信息------------------------------------------------
                    server = self.mssh.server
                    ip = server['ip']
                    username = server['username']
                    password = server['password']
                    self.client = paramiko.SSHClient()
                    self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    self.client.connect(ip, 22, username, password)

                    # 执行远程命令获取内存信息
                    stdin, stdout, stderr = self.client.exec_command("free -m")
                    result = stdout.read().decode('utf-8')
                    # 获取系统内存信息
                    lines = result.split('\n')
                    mem_info = lines[1].split()
                    total_mem = int(mem_info[1])
                    used_mem = int(mem_info[2])
                    mem_usage = used_mem / total_mem * 100

                    # 获取网络速率
                    stdin1, stdout1, stderr1 = self.client.exec_command("ifconfig")
                    result = stdout1.read().decode("utf-8")
                    # 使用正则表达式提取数据包和字节数信息
                    matches = re.findall(r'ens160.*?RX packets (\d+)  bytes (\d+).*?TX packets (\d+)  bytes (\d+)',
                                         result, re.DOTALL)
                    if matches:
                        rx_packets, rx_bytes, tx_packets, tx_bytes = matches[0]
                    else:
                        rx_packets, rx_bytes, tx_packets, tx_bytes = 0, 0, 0, 0
                    time.sleep(1)
                    stdin2, stdout2, stderr3 = self.client.exec_command("ifconfig")
                    result = stdout2.read().decode("utf-8")
                    matches = re.findall(r'ens160.*?RX packets (\d+)  bytes (\d+).*?TX packets (\d+)  bytes (\d+)',
                                         result, re.DOTALL)
                    if matches:
                        rx_packets, new_rx_bytes, tx_packets, new_tx_bytes = matches[0]
                    else:
                        rx_packets, new_rx_bytes, tx_packets, new_tx_bytes = 0, 0, 0, 0

                    # 计算速率
                    upload_speed = ((int(new_tx_bytes) - int(tx_bytes)) / 1024)  # MB/s，
                    download_speed = ((int(new_rx_bytes) - int(rx_bytes)) / 1024)

                    # 获取cpu利用率
                    stdin4, stdout4, stderr4 = self.client.exec_command("top -bn 1")
                    result = stdout4.read().decode("utf-8")
                    cpu = 0
                    for line in result.split("\n"):
                        if line.startswith("%Cpu(s)"):
                            cpu_us = re.findall(r'\d+\.\d+', line.split(":")[1].split(",")[0])[0]
                            cpu_sy = re.findall(r'\d+\.\d+', line.split(":")[1].split(",")[1])[0]
                            cpu_ni = re.findall(r'\d+\.\d+', line.split(":")[1].split(",")[2])[0]
                            cpu_id = re.findall(r'\d+\.\d+', line.split(":")[1].split(",")[3])[0]
                            cpu_wa = re.findall(r'\d+\.\d+', line.split(":")[1].split(",")[4])[0]
                            cpu_hi = re.findall(r'\d+\.\d+', line.split(":")[1].split(",")[5])[0]
                            cpu_si = re.findall(r'\d+\.\d+', line.split(":")[1].split(",")[6])[0]
                            cpu_st = re.findall(r'\d+\.\d+', line.split(":")[1].split(",")[7])[0]
                            sum = float(cpu_st) + float(cpu_si) + float(cpu_hi) + float(cpu_wa) + float(cpu_id) + float(
                                cpu_ni) + float(cpu_sy) + float(cpu_us)
                            cpu = sum - float(cpu_id)

                            # 设置进度条样式
                    if cpu > 80:
                        cpu_style = "red.Horizontal.TProgressbar"
                    elif cpu > 50:
                        cpu_style = "yellow.Horizontal.TProgressbar"
                    else:
                        cpu_style = "green.Horizontal.TProgressbar"

                    if mem_usage > 80:
                        mem_style = "red.Horizontal.TProgressbar"
                    elif mem_usage > 50:
                        mem_style = "yellow.Horizontal.TProgressbar"
                    else:
                        mem_style = "green.Horizontal.TProgressbar"

                    # 更新标签
                    self.cpu_label.config(text=f"CPU信息：{cpu:.2f}%")
                    self.cpu_progress.config(style=cpu_style, value=cpu)
                    self.mem_label.config(text=f"Memory Usage: {used_mem} MB / {total_mem} MB ({mem_usage:.2f}%)")
                    self.mem_progress.config(style=mem_style, value=mem_usage)
                    self.net_label.config(text=f"网络信息：↑{upload_speed:.2f}MB/s \t ↓{download_speed:.2f}MB/s")

                else:
                    result_connect = (f"服务器{self.mssh.server['ip']}连接失败", "red")
                    self.reset_system_monitoring()  # 重置系统监控状态
            else:
                result_connect = (f"服务器未选择", "black")
                self.reset_system_monitoring()  # 重置系统监控状态

                # 检查连接状态是否发生变化
                if self.mssh.connected != prev_connected:
                    self.reset_system_monitoring()  # 重置系统监控状态
                    prev_connected = self.mssh.connected
            self.label_server.config(text=f"{result_connect[0]}", foreground=result_connect[1])
            time.sleep(1)

    def reset_system_monitoring(self):
        # 重置系统监控状态
        self.cpu_label.config(text="CPU信息：")
        self.cpu_progress.config(style="", value=0)
        self.mem_label.config(text="Memory Usage: 0 MB / 0 MB")
        self.mem_progress.config(style="", value=0)
        self.net_label.config(text="网络信息：")

    def show_disk_usage(self):
        if not self.mssh.connected:
            messagebox.showerror("错误", "请先连接到服务器!")
            return

        try:
            self.mssh.connecting()
            stdin, stdout, stderr = self.mssh.ssh.exec_command("df -h")
            disk_info = stdout.read().decode("utf-8").strip().split("\n")

            # 创建新窗口
            disk_window = tk.Toplevel(self.root)
            disk_window.title("磁盘使用情况")

            # 创建表格
            table_frame = ttk.Frame(disk_window)
            table_frame.pack(padx=10, pady=10, fill="both", expand=True)

            # 创建表格标题
            table = ttk.Treeview(table_frame, columns=("filesystem", "size", "used", "avail", "use%", "mounted_on"),
                                 show="headings")
            table.heading("filesystem", text="文件系统")
            table.heading("size", text="总大小")
            table.heading("used", text="已用空间")
            table.heading("avail", text="可用空间")
            table.heading("use%", text="已用百分比")
            table.heading("mounted_on", text="挂载点")
            table.pack(side="left", fill="both", expand=True)

            # 添加滚动条
            scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=table.yview)
            scrollbar.pack(side="right", fill="y")
            table.configure(yscrollcommand=scrollbar.set)

            # 填充表格数据
            for line in disk_info[1:]:
                parts = line.split()
                if len(parts) >= 6:
                    filesystem, size, used, avail, use_percent, mounted_on = parts
                    table.insert("", "end", values=(filesystem, size, used, avail, use_percent, mounted_on))

            # 调整列宽度
            table.column("#0", width=0, stretch="no")  # 隐藏第一列
            table.column("filesystem", width=100, anchor="w")
            table.column("size", width=80, anchor="e")
            table.column("used", width=80, anchor="e")
            table.column("avail", width=80, anchor="e")
            table.column("use%", width=80, anchor="e")
            table.column("mounted_on", width=200, anchor="w")

            # 自动调整行高
            def fixed_map(option):
                return [elm for elm in style.map("Treeview", query_opt=option) if elm[:2] != ("!disabled", "!selected")]

            style = ttk.Style()
            style.map("Treeview", foreground=fixed_map("foreground"), background=fixed_map("background"))

        except Exception as e:
            messagebox.showerror("错误", f"无法获取磁盘使用情况: {e}")

    def ok(self, event):
        command = self.command.get()
        if not self.mssh.connected:
            self.txt_result.insert(tk.END, "未连接到服务器！\n")
            return
        # 如果ssh_channel尚未创建，创建一个新的ssh通道
        if self.mssh_channel is None:
            self.mssh_channel = self.mssh.ssh.invoke_shell()
            self.mssh_channel.set_combine_stderr(True)
        try:
            # 使用ssh_channel发送命令
            self.mssh_channel.send(f"{command}\n")
            # 创建线程监听输出并调用UI提供的回调函数
            t = threading.Thread(target=self.mssh._read_channel, args=(self.mssh_channel, self.handle_output))
            t.daemon = True
            t.start()
            # 设置延时清空输入框
            self.root.after(2000, lambda: self.command.set(""))
        except Exception as e:
            self.txt_result.insert(tk.END, f"执行错误: {str(e)}\n")

        # 清空输入框
        self.command.set("")

    # --------------------------------------------连接-----------------------------------------------

    # 新建连接
    def new_connect_ui(self):
        self.pop_win = tk.Toplevel(self.root)
        # 设置标题和大小
        self.pop_win.title("新建连接")
        self.pop_win.geometry("300x200+600+250")
        frame = tk.Frame(self.pop_win)
        frame.grid()

        # IP
        ip_label = tk.Label(frame, text="服务器IP地址:")
        ip_label.grid(row=0, column=0)
        self.ip_entry = tk.Entry(frame)
        self.ip_entry.grid(row=0, column=1)

        # Port
        port_label = tk.Label(frame, text="服务器端口号:")
        port_label.grid(row=1, column=0)
        self.port_entry = tk.Entry(frame)
        self.port_entry.grid(row=1, column=1)

        # Username
        username_label = tk.Label(frame, text="用户名:")
        username_label.grid(row=2, column=0)
        self.username_entry = tk.Entry(frame)
        self.username_entry.grid(row=2, column=1)

        # Password
        password_label = tk.Label(frame, text="密码:")
        password_label.grid(row=3, column=0)
        self.password_entry = tk.Entry(frame, show="*")
        self.password_entry.grid(row=3, column=1)

        # Description
        description_label = tk.Label(frame, text="备注信息:")
        description_label.grid(row=4, column=0)
        self.description_entry = tk.Entry(frame)
        self.description_entry.grid(row=4, column=1)

        # Button
        submit_button = tk.Button(frame, text="保存", command=self.save_server_info)
        submit_button.grid(row=5, columnspan=2)

    # 保存新建连接的服务器信息
    def save_server_info(self):
        if self.ip_entry.get() == "" or self.port_entry.get() == "" or self.username_entry.get() == "" or self.password_entry.get() == "":
            messagebox.showerror("错误", "请填写完整的服务器信息！")
            return
        else:
            ip = self.ip_entry.get()
            port = self.port_entry.get()
            username = self.username_entry.get()
            password = self.password_entry.get()
            description = self.description_entry.get()
            # 这里应该调用你的 add_server 函数，将获取到的信息添加到服务器列表中
            ssh.add_server(ip=ip, port=int(port), username=username, password=password, description=description)
            messagebox.showinfo('成功', "服务器信息已保存")

    #  打开连接
    def open_connect_ui(self):
        print("打开连接！")
        self.pop_win = tk.Toplevel(self.root)
        # 设置标题和大小
        self.pop_win.title("打开连接")
        self.pop_win.geometry("+480+230")
        frame = tk.Frame(self.pop_win)
        frame.grid()
        index = 0
        for item in self.mssh.servers:
            # 删除列表信息中的password（这里假设item是一个字典）
            item_without_password = {k: v for k, v in item.items() if k != 'password'}

            # 显示不包含密码的服务器信息
            tk.Label(self.pop_win, text=str(item_without_password)).grid(row=index, column=0, padx=5, pady=5)

            # 添加连接、删除、修改按钮...
            tk.Button(self.pop_win, text="连接", command=lambda item=item: self.connect(item)).grid(row=index, column=2)
            tk.Button(self.pop_win, text='删除', command=lambda item=item: self.del_connect(item)).grid(row=index,
                                                                                                        column=4)
            tk.Button(self.pop_win, text='修改', command=lambda item=item: self.modify_server(item)).grid(row=index,
                                                                                                          column=6)

            index = index + 1

            # 连接到指定的服务器

    def connect(self, server):
        print("连接到指定的服务器")
        self.mssh.server = server
        print(f"服务器信息：{self.mssh.server}")

        socket.setdefaulttimeout(5)

        # 在单独的线程中执行连接操作
        thread_connect = threading.Thread(target=self.connect_thread, args=(server,))
        thread_connect.start()

        self.pop_win.destroy()

    def connect_thread(self, server):
        result = self.mssh.connecting()
        if result:
            self.is_connected = True
            self.update_connection_status(server, True)
        else:
            self.is_connected = False
            self.update_connection_status(server, False)

    def update_connection_status(self, server, connected):
        if connected:
            self.label_server.config(text=f"服务器{server['ip']}连接成功", foreground="green")
        else:
            self.label_server.config(text=f"服务器{server['ip']}连接失败", foreground="red")

    def del_connect(self, server):
        print("删除指定的服务器")
        # 输出服务器信息
        print(f"服务器信息：{server}")
        # 确认是否删除服务器
        confirm = messagebox.askyesno("确认删除", f"确认删除服务器 {server['ip']} 吗？")
        if confirm:
            # 从服务器列表中删除指定的服务器
            if server in self.mssh.servers:
                self.mssh.servers.remove(server)
                self.pop_win.destroy()
                self.open_connect_ui()
                messagebox.showinfo("删除成功", f"服务器 {server['ip']} 已成功删除！")
            else:
                messagebox.showerror("错误", "服务器不存在，无法删除")
        # 保存更新后的服务器列表到配置文件中
        self.mssh.save_server()

    def modify_server(self, server):
        self.pop_win.destroy()
        print("修改服务器信息")
        self.mssh.server = server.copy()  # 添加这一行来复制服务器信息
        self.pop_win_modify = tk.Toplevel(self.root)
        frame = tk.Frame(self.pop_win_modify)
        frame.grid()

        # IP
        ip_label = tk.Label(frame, text="服务器IP地址:")
        ip_label.grid(row=0, column=0)
        self.ip_entry = tk.Entry(frame, textvariable=tk.StringVar(value=server['ip']))
        self.ip_entry.grid(row=0, column=1)

        # Port
        port_label = tk.Label(frame, text="服务器端口号:")
        port_label.grid(row=1, column=0)
        self.port_entry = tk.Entry(frame, textvariable=tk.StringVar(value=str(server['port'])))
        self.port_entry.grid(row=1, column=1)

        # Username
        username_label = tk.Label(frame, text="用户名:")
        username_label.grid(row=2, column=0)
        self.username_entry = tk.Entry(frame, textvariable=tk.StringVar(value=server['username']))
        self.username_entry.grid(row=2, column=1)

        # Password
        password_label = tk.Label(frame, text="密码:")
        password_label.grid(row=3, column=0)
        self.password_entry = tk.Entry(frame, show="*", textvariable=tk.StringVar(value=server['password']))
        self.password_entry.grid(row=3, column=1)

        # Description
        description_label = tk.Label(frame, text="备注信息:")
        description_label.grid(row=4, column=0)
        self.description_entry = tk.Entry(frame, textvariable=tk.StringVar(value=server['description']))
        self.description_entry.grid(row=4, column=1)

        # Button
        submit_button = tk.Button(frame, text="保存", command=self.save_modified_server)
        submit_button.grid(row=5, columnspan=2)

    # 保存修改后的服务器信息
    def save_modified_server(self):
        if self.ip_entry.get() == "" or self.port_entry.get() == "" or self.username_entry.get() == "" or self.password_entry.get() == "":
            messagebox.showerror("错误", "请填写完整的服务器信息！")
            return
        else:
            modified_server = {
                "ip": self.ip_entry.get(),
                "port": int(self.port_entry.get()),
                "username": self.username_entry.get(),
                "password": self.password_entry.get(),  # 假设密码不变，保持原值
                "description": self.description_entry.get(),
            }
            index = self.mssh.servers.index(self.mssh.server)
            self.mssh.servers[index] = modified_server
            messagebox.showinfo("成功", "服务器信息已成功修改！")
            self.pop_win_modify.destroy()
            self.open_connect_ui()
            self.mssh.save_server()

    ##################################  操作  #################################################

    # 上传文件
    def upload_file(self):
        if not self.mssh.connected:
            messagebox.showerror("错误", "请先连接到服务器!")
            return
        else:
            self.file_path = filedialog.askopenfilename()
            try:
                if self.file_path:
                    # 获取文件名
                    file_name = self.file_path.split("/")[-1]

                    # 创建 SFTP 客户端
                    sftp_client = self.mssh.ssh.open_sftp()
                    remote_path = f"{self.mssh.path}/{file_name}"
                    print(f"文件：{self.file_path},上传到：{remote_path}")
                    # 上传文件
                    sftp_client.put(self.file_path, remote_path)
                    messagebox.showinfo("成功", "上传成功")
                    sftp_client.close()
                else:
                    print("请选择要上传的文件")
            except Exception as e:
                messagebox.showerror("错误", f"文件上传失败: {e}")

    # #下载文件
    def downloader(self):
        if not self.mssh.connected:
            messagebox.showerror("错误", "请先连接到服务器!")
            return
        self.mssh.download_file()

    def vim_edit(self):
        if not self.mssh.connected:
            messagebox.showerror("错误", "请先连接到服务器!")
            return
        self.mssh.vim_edit()

    def download_logs(self):
        if not self.mssh.connected:
            messagebox.showerror("错误", "请先连接到服务器!")
            return

        # 将远程目录设置为 /var/log
        remote_dir = "/var/log"

        try:
            self.mssh.connecting()
            sftp = self.mssh.ssh.open_sftp()

            # 检查远程目录是否存在
            try:
                sftp.stat(remote_dir)
            except IOError as e:
                messagebox.showerror("错误", f"远程目录 {remote_dir} 不存在")
                return

            remote_files = sftp.listdir(remote_dir)

            local_dir = filedialog.askdirectory(title="选择下载到的本地目录")
            if local_dir:
                self.local_log_dir = local_dir
            else:
                return

            downloaded_count = 0
            for filename in remote_files:
                # 检查文件是否以 ".log" 结尾
                if filename.endswith(".log"):
                    remote_path = f"{remote_dir}/{filename}"
                    local_path = f"{local_dir}/{filename}"
                    sftp.get(remote_path, local_path)
                    downloaded_count += 1
                    print(f"下载成功: {remote_path} -> {local_path}")

            sftp.close()
            print(f"共下载了 {downloaded_count} 个文件")
            if downloaded_count > 0:
                messagebox.showinfo("成功", f"成功下载了 {downloaded_count} 个日志文件")
        except Exception as e:
            print(f"下载失败: {e}")
            messagebox.showerror("错误", f"下载日志文件失败: {e}")

    def view_log(self):
        if not self.mssh.connected:
            messagebox.showerror("错误", "请先连接服务器并下载日志文件!")
            return

            # 从 download_logs 函数中获取之前选择的本地目录
        try:
            local_dir = self.local_log_dir
        except AttributeError:
            local_dir = filedialog.askdirectory(title="选择下载日志文件所在的目录")
            if not local_dir:
                return

        log_file = filedialog.askopenfilename(initialdir=local_dir, title="选择要查看的日志文件",
                                              filetypes=(("Log Files", "*.log"),))
        if log_file:
            try:
                # 使用 VSCode 打开日志文件
                subprocess.run(['Code', log_file], shell=True)
            except Exception as e:
                messagebox.showerror("错误", f"无法打开文件: {e}")

    def on_closing_main(self):
        if messagebox.askokcancel("Quit", "确认退出吗?"):
            self.root.destroy()

    def on_closing(self):
        if messagebox.askokcancel("Quit", "确认退出吗?"):
            self.pop_win.destroy()


if __name__ == '__main__':
    ssh = MySsh()
    ui = MyUI(ssh)
