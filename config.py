UDP_IP = "0.0.0.0"
UDP_PORT = 8888

FLAG_LITTLE_ENDIAN = False
REQUIRE_PROTOCOL_VERSION = '2'  # hex value of protocol version, in string
WORD_LENGTH = 4  # in bytes

TRANSACTION_TYPE_VALUES = {'0': 'read',
                           '1': 'write',
                           '2': 'read (non-incrementing)',
                           '3': 'write (non-incrementing)',
                           '4': 'read/modify/write bits (RMWbits)',
                           '5': 'read/modify/write sum (RMWsum)',
                           '6': 'configuration space, read (0x0)',
                           '7': 'configuration space, write (0x1)'}
PACKET_TYPE_VALUES = {'0': 'control (r/w)',
                      '1': 'status',
                      '2': 're-send'}
TRANSACTION_INFO_CODE_VALUES = {'0': 'request success',
                                '1': 'bad header',
                                '4': 'bus error on read',
                                '5': 'bus error on write',
                                '6': 'bus timeout on read',
                                '7': 'bus timeout on write',
                                'f': 'outbound request'}

# packet header format comes in "keyName":(startIndex [from left], lengthOfValue)
PACKET_HEADER_FORMAT = {"protocol_version": (0,1),
                        "reserved": (1,2),
                        "packet_id": (2,6),
                        "byte-order_qualifier": (6,7),
                        "packet_type": (7,8)}

TRANSACTION_HEADER_FORMAT = {"protocol_version": (0,1),
                             "transaction_id": (1,4),
                             "words": (4,6),
                             "type_id": (6,7),
                             "info_code": (7,8)}
 
# unicode for fancy outputting
UNICODE = {'error': "\xE2\x9D\x8C ",
           'warning': "\xE2\x9A\xA0\xEF\xB8\x8F ",
           'leftrightarrow': "\xE2\x86\x94\xEF\xB8\x8F "}

# for ease of formatting
PRINT_LENGTH = 60  # number of columns


class COLORS:
  END = '\033[0m'

  PURPLE = '\033[95m'
  CYAN = '\033[96m'
  DARKCYAN = '\033[36m'
  BLUE = '\033[94m'
  GREEN = '\033[92m'
  YELLOW = '\033[93m'
  RED = '\033[91m'

  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'

  HEADER = '\033[95m'
  OKBLUE = BLUE
  OKGREEN = GREEN
  WARNING = YELLOW
  FAIL = RED
 
  @classmethod
  def PRINT(cls):
    for i, v in vars(cls).items():
      if '__' in i:
        continue
      try:
        print v+i+cls.ENDC
      except:
        continue

