import sys
import dns._features
if sys.platform == 'win32':
    from typing import Any
    import dns.name
    _prefer_wmi = True
    import winreg
    try:
        WindowsError is None
    except KeyError:
        WindowsError = Exception
    if dns._features.have('wmi'):
        import threading
        import pythoncom
        import wmi
        _have_wmi = True
    else:
        _have_wmi = False

    class DnsInfo:

        def __init__(self):
            self.domain = None
            self.nameservers = []
            self.search = []
    if _have_wmi:

        class _WMIGetter(threading.Thread):

            def __init__(self):
                super().__init__()
                self.info = DnsInfo()
                self.wmi = None
    else:

        class _WMIGetter:
            pass

    class _RegistryGetter:

        def __init__(self):
            self.info = DnsInfo()

        def get(self):
            """Extract resolver configuration from the Windows registry."""
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters') as key:
                    self.info.domain = winreg.QueryValueEx(key, 'Domain')[0]
            except WindowsError:
                pass

            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters') as key:
                    self.info.search = winreg.QueryValueEx(key, 'SearchList')[0].split(',')
            except WindowsError:
                pass

            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                    r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces') as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            interface_key = winreg.OpenKey(key, winreg.EnumKey(key, i))
                            nameservers = winreg.QueryValueEx(interface_key, 'NameServer')[0].split(',')
                            self.info.nameservers.extend(nameservers)
                        except WindowsError:
                            pass
            except WindowsError:
                pass

            return self.info
    _getter_class: Any
    if _have_wmi and _prefer_wmi:
        _getter_class = _WMIGetter
    else:
        _getter_class = _RegistryGetter

    def get_dns_info():
        """Extract resolver configuration."""
        getter = _getter_class()
        if isinstance(getter, _WMIGetter):
            getter.start()
            getter.join()
        return getter.get()
