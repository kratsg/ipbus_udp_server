import socket
UDP_IP = "0.0.0.0"
UDP_PORT = 8888

FLAG_BIGENDIAN = 0

def checkFalsey(booly):
  if booly:
    return ""
  else:
    return "\xE2\x9D\x8C"

def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

def flipEndian(word):
  global FLAG_BIGENDIAN
  if FLAG_BIGENDIAN:
    return ''.join(list(chunks(word, 2))[::-1])
  else:
    # do nothing, no flip needed
    return word

def parsePacketType(hex_val):
  packetTypeValue = {'0': 'control (r/w)', '1': 'status', '2': 're-send'}
  return packetTypeValue.get(hex_val, 'reserved')

def parseTransactionType(hex_val):
  transactionTypeValue = {'0': 'read',
                          '1': 'write',
                          '2': 'read (non-incrementing)',
                          '3': 'write (non-incrementing)',
                          '4': 'read/modify/write bits (RMWbits)',
                          '5': 'read/modify/write sum (RMWsum)',
                          '6': 'configuration space, read (0x0)',
                          '7': 'configuration space, write (0x1)'}
  return transactionTypeValue.get(hex_val, '?')

def parseTransactionInfoCode(hex_val):
  transactionInfoCodeValue = {'0': 'request success',
                              '1': 'bad header',
                              '4': 'bus error on read',
                              '5': 'bus error on write',
                              '6': 'bus timeout on read',
                              '7': 'bus timeout on write',
                              'f': 'outbound request'}
  return transactionInfoCodeValue.get(hex_val, 'reserved')

def printPacketDetails(packet, indentLevel=0):
  print ("\t"*indentLevel)+("\n"+"\t"*indentLevel).join(packet['str'])
  return True

def checkEndian(packet_header):
  global FLAG_BIGENDIAN
  if packet_header[6:7] not in ['0','f']:
    FLAG_BIGENDIAN = 1
 

def parsePacketHeader(word):
    checkEndian(word)
    word = flipEndian(word)
    data = {"protocol_version": word[0:1],
            "reserved": word[1:2],
            "packet_id": word[2:6],
            "byte-order_qualifier": word[6:7],
            "packet_type": word[7:8]}
    outStr = []
    outStr.append("Protocol Version (0x2)")
    outStr.append("{}\t{}".format(checkFalsey(data['protocol_version']=='2'),data['protocol_version']))
    outStr.append("Reserved (0)")
    outStr.append("{}\t{}".format(checkFalsey(data['reserved'] == '0'), data['reserved']))
    outStr.append("Packet ID (16b, 0x0 - 0xffff)")
    outStr.append("\t{}".format(data['packet_id']))
    outStr.append("Byte-order qualifier (0xf = big endian-ness)")
    outStr.append("\t{}".format(data['byte-order_qualifier']))
    outStr.append("Packet Type (0x0 - 0x2)")
    outStr.append("\t{} = {}".format(data['packet_type'], parsePacketType(data['packet_type'])))
    data['str'] = outStr
    return data


def parseTransactionHeader(word):
    word = flipEndian(word)
    data = {"protocol_version": word[0:1],
            "transaction_id": word[1:4],
            "words": word[4:6],
            "type_id": word[6:7],
            "info_code": word[7:8]}
    outStr = []
    outStr.append("Protocol Version (4b)")
    outStr.append("{}\t{}".format(checkFalsey(data['protocol_version'] == '2'), data['protocol_version']))
    outStr.append("Transaction ID (12b)")
    outStr.append("\t{}".format(data['transaction_id']))
    outStr.append("Words (8b)")
    outStr.append("\t{} 32-bit words in addressable memory space".format(int(data['words'], 16)))
    outStr.append("Type ID (4b)")
    outStr.append("\t{} = {}".format(data['type_id'], parseTransactionType(data['type_id'])))
    outStr.append("Info Code (4b)")
    outStr.append("{}\t{} = {}".format(checkFalsey(data['info_code'] == 'f'), data['info_code'], parseTransactionInfoCode(data['info_code'])))
    data['str'] = outStr
    return data

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    data = data.encode("hex")
    print "received message:", data, addr
    words = list(chunks(data,8))

    packet_data = parsePacketHeader(words[0])
    print "Packet Details"
    printPacketDetails(packet_data, indentLevel=1)

    transaction_data = parseTransactionHeader(words[1])
    print "Transaction Details"
    printPacketDetails(transaction_data, indentLevel=1)

    print "="*40
    print "| Breakdown"
    for i,v in enumerate(words):
      binNumber = bin(int(v, 16))[2:].zfill(32)
      print "| \tWord {:d} = {:s}\n\t\t{:s}".format(i, flipEndian(v), binNumber)
    print "="*40

