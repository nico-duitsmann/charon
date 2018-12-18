class AutostartManager:
    class Windows:
        def __init__(self):
            import _winreg
            self._registry = _winreg.ConnectRegistry(None, _winreg.HKEY_CURRENT_USER)

        def get_runonce(self) -> str:
            return _winreg.OpenKey(self._registry,
                    r"Software\Microsoft\Windows\CurrentVersion\Run", 0,
            _winreg.KEY_ALL_ACCESS)

        def add(self, name: str, application: str):
            key = get_runonce()
            _winreg.SetValueEx(key, name, 0, _winreg.REG_SZ, application)
            _winreg.CloseKey(key)

        def exists(self, name: str) -> bool:
            key = get_runonce()
            exists = True
            try:
                _winreg.QueryValueEx(key, name)
            except WindowsError:
                exists = False
            _winreg.CloseKey(key)
            return exists

        def remove(self, name: str):
            key = get_runonce()
            _winreg.DeleteValue(key, name)
            _winreg.CloseKey(key)

    class Linux:
        def __init__(self):
            self._xdg_config_home = os.environ.get("XDG_CONFIG_HOME", "~/.config")
            self._xdg_user_autostart = os.path.join(os.path.expanduser(_xdg_config_home),
                    "autostart")

        def getfilename(self, name: str) -> str:
            return os.path.join(_xdg_user_autostart, name + ".desktop")

        def add(self, name: str, application: str):
            desktop_entry = "[Desktop Entry]\n"\
                "Name=%s\n"\
                "Exec=%s\n"\
                "Type=Application\n"\
                "Terminal=false\n" % (name, application)
            with open(getfilename(name), "w") as f:
                f.write(desktop_entry)

        def exists(self, name: str) -> bool:
            return os.path.exists(getfilename(name))

        def remove(self, name: str):
            os.unlink(getfilename(name))
