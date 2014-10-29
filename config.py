import socket
UDP_IP = "0.0.0.0"
UDP_PORT = 8888

FLAG_BIGENDIAN = None
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
                        "reserved": (1,1),
                        "packet_id": (2,4),
                        "byte-order_qualifier": (6,1),
                        "packet_type": (7,1)}

TRANSACTION_HEADER_FORMAT = {"protocol_version": (0,1),
                             "transaction_id": (1,3),
                             "words": (4,2),
                             "type_id": (6,1),
                             "info_code": (7,1)}
 
# unicode for fancy outputting
UNICODE = {'error': "\xE2\x9D\x8C ",
           'warning': "\xE2\x9A\xA0\xEF\xB8\x8F "}
