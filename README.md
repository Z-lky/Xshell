简易版ssh远程服务器管理工具 
开发环境：python3.11
技术栈：paramiko+tkinter+Watchdog
项目描述：
该项目是一款自主研发的远程服务器管理工具，旨在通过图形化界面简化虚拟机（VM）的远程管理操作。该项目集成了SSH协
议，实现了远程登录、命令执行、文件传输、服务器监控及日志管理等核心功能，为用户提供了高效、便捷且安全的服务器管理体
验。
技术要点：
1、使用集成Paramiko模块，实现了对SSH服务器的安全连接与远程操作功能。用户可通过平台界面快速建立SSH连接，执行远程
命令并实时查看输出结果，包括标准输出与错误信息。同时，支持多服务器配置管理，满足用户多样化的管理需求。。
2、引入Watchdog库对指定目录进行实时监控，能够准确捕捉文件的修改、增加、删除等事件。
3、利用Python的threading模块创建了独立线程用于执行SSH连接操作，避免了连接操作对其他GUI操作的干扰，确保了系统的
流畅运行与用户体验，提高了系统的整体性能与稳定性。
