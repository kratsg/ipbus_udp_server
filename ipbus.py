class IPBus(socket):
  # IPBus() will generate a socket that binds to a port
  def __init__(self, *args, **kwargs):
    self._ip = kwargs.get('ip', '0.0.0.0')
    self._port = kwargs.get('port', 8888)
    self._buffer_size = kwargs.get('buffer_size',1024)
    # Instantiate socket
    self._socket = socket.socket(socket.AF_INET,  # Internet
                                socket.SOCK_DGRAM)  # UDP
    self._socket.bind((self.ip, self.port))

  @property
  def socket(self):
    return self._socket

  @property
  def recvfrom(self):
    return self.socket.recvfrom(self.buffer_size)

  @property
  def ip(self):
    return self._ip

  @property
  def port(self):
    return self._port

  @property
  def buffer_size(self):
    return self._buffer_size

  def run():
    while True:
      data, addr = self.recvfrom

class IPBusHandler(object):
  def __init__(self, data, addr, verbosity='high'):
    self.data = data
    self.addr = addr
    self.FLAG_LITTLE_ENDIAN = False
    # unicode for fancy outputting
    self.UNICODE = {'error': "\xE2\x9D\x8C ",
                    'warning': "\xE2\x9A\xA0\xEF\xB8\x8F "}

    # for ease of formatting
    self.PRINT_LENGTH = 60  # number of columns


