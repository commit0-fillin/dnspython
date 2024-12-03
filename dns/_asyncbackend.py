class NullContext:

    def __init__(self, enter_result=None):
        self.enter_result = enter_result

    def __enter__(self):
        return self.enter_result

    def __exit__(self, exc_type, exc_value, traceback):
        return None

    async def __aenter__(self):
        return self.enter_result

    async def __aexit__(self, exc_type, exc_value, traceback):
        return None

class Socket:

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.close()

class DatagramSocket(Socket):

    def __init__(self, family: int):
        self.family = family
        self._socket = None

class StreamSocket(Socket):
    pass

class NullTransport:
    pass

class Backend:
    pass
