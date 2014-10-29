import socket
from config import *

# unicode for fancy outputting
UNICODE = {'error': "\xE2\x9D\x8C",
           'warning': "\xE2\x9A\xA0\xEF\xB8\x8F"}

def checkFalsey(booly):
  global UNICODE
  if booly:
    return ""
  else:
    return UNICODE['error']

def raiseEndianWarning():
  global FLAG_BIGENDIAN, UNICODE
  if FLAG_BIGENDIAN is True:
    print "{} Warning: Big endian-ness detected!".format(UNICODE['warning'])

def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in xrange(0, len(l), n):
        yield l[i:i+n]

# flip the word if globally required, can be overrided with `flip`
def flipEndian(word, flipOverride=False):
  global FLAG_BIGENDIAN, UNICODE

  if flipOverride:
    print "{} Overriden: Flipping endian-ness of word".format(UNICODE['warning'])

  if FLAG_BIGENDIAN is None and not flipOverride:
    ValueError('FLAG_BIGENDIAN is unset. Run checkEndian() on the packet header')
    return word
  elif FLAG_BIGENDIAN is True or flipOverride:
    return ''.join(list(chunks(word, 2))[::-1])
  else:
    # do nothing, no flip needed
    return word

def decodePacketType(hex_val):
  global PACKET_TYPE_VALUES
  return PACKET_TYPE_VALUES.get(hex_val, 'reserved')

def decodeTransactionType(hex_val):
  global TRANSACTION_TYPE_VALUES
  return TRANSACTION_TYPE_VALUES.get(hex_val, '?')

def decodeTransactionInfoCode(hex_val):
  global TRANSACTION_INFO_CODE_VALUES
  return TRANSACTION_INFO_CODE_VALUES.get(hex_val, 'reserved')

def printPacketDetails(packet, indentLevel=0):
  print ("\t"*indentLevel)+("\n"+"\t"*indentLevel).join(packet['str'])
  return True

def printPacketsBreakdown(packets, indentLevel=0):
  outStr = []
  for i,v in enumerate(packets):
    v = flipEndian(v)
    binNumber = ' '.join(chunks(bin(int(v, 16))[2:].zfill(32), 8))
    outStr.append("Word {:d} = {:s}".format(i, v))
    outStr.append("\t{:s}".format(binNumber))
  print ("\t"*indentLevel)+("\n"+"\t"*indentLevel).join(outStr)
  return True

def checkEndian(packet_header):
  global FLAG_BIGENDIAN
  FLAG_BIGENDIAN = bool(packet_header[6:7] not in ['0','f'])
  raiseEndianWarning()

def hexToBin(hex_val, numBits=8):
  return ' '.join(chunks(bin(int(hex_val, 16))[2:].zfill(numBits), 8))
 
# used by decodePacketHeader and decodeTransactionHeader 
def reportHexVal(hex_val, flagError=True, parseFunction=None, numBits=8):
  if parseFunction is None:
    parseFunction_out = ''
  else:
    parseFunction_out = parseFunction(hex_val)
  return "{}\t{}\t{}\t{}".format(checkFalsey(flagError), hex_val, hexToBin(hex_val, numBits=numBits), parseFunction_out)

def decodePacketHeader(word):
    global REQUIRE_PROTOCOL_VERSION, PACKET_HEADER_FORMAT
    checkEndian(word)
    word = flipEndian(word)
    parsedWord = {}
    for k,v in PACKET_HEADER_FORMAT.iteritems():
      parsedWord[k] = word[v[0]:v[0]+v[1]]

    outStr = []
    outStr.append("(4b)  Protocol Version")
    outStr.append(reportHexVal(parsedWord['protocol_version'], flagError=(parsedWord['protocol_version']==REQUIRE_PROTOCOL_VERSION), numBits=4))
    outStr.append("(4b)  Reserved")
    outStr.append(reportHexVal(parsedWord['reserved'], flagError=(parsedWord['reserved']=='0'), numBits=4))
    outStr.append("(16b) Packet ID")
    outStr.append(reportHexVal(parsedWord['packet_id'], numBits=16))
    outStr.append("(4b)  Byte-order qualifier")
    outStr.append(reportHexVal(parsedWord['byte-order_qualifier'], parseFunction=(lambda x: 'big endian-ness' if x == 'f' else 'little endian-ness'), numBits=4))
    outStr.append("(4b)  Packet Type")
    outStr.append(reportHexVal(parsedWord['packet_type'], flagError=(parsedWord['packet_type']!='3'), parseFunction=decodePacketType, numBits=4))
    parsedWord['str'] = outStr
    return parsedWord

def decodeTransactionHeader(word, checkOutboundRequest=True):
    global REQUIRE_PROTOCOL_VERSION, TRANSACTION_HEADER_FORMAT
    word = flipEndian(word)
    parsedWord = {}
    for k,v in TRANSACTION_HEADER_FORMAT.iteritems():
      parsedWord[k] = word[v[0]:v[0]+v[1]]

    outStr = []
    outStr.append("(4b)  Protocol Version")
    outStr.append(reportHexVal(parsedWord['protocol_version'], flagError=(parsedWord['protocol_version']==REQUIRE_PROTOCOL_VERSION), numBits=4))
    outStr.append("(12b) Transaction ID")
    outStr.append(reportHexVal(parsedWord['transaction_id'], numBits=12))
    outStr.append("(8b)  Words")
    outStr.append(reportHexVal(parsedWord['words'], parseFunction=(lambda x: "N={} 32-bit words in addressable memory space".format(int(x, 16))), numBits=8))
    outStr.append("(4b)  Type ID")
    outStr.append(reportHexVal(parsedWord['type_id'], parseFunction=decodeTransactionType, numBits=4))
    outStr.append("(4b)  Info Code")
    outStr.append(reportHexVal(parsedWord['info_code'], flagError=(parsedWord['info_code']=='f' or not checkOutboundRequest), parseFunction=decodeTransactionInfoCode, numBits=4))
    parsedWord['str'] = outStr
    return parsedWord

def encodePacket(PACKET_FORMAT, packet, **kwargs):
  global WORD_LENGTH
  outbound_packet = ['']*WORD_LENGTH*2  # put in hex
  for k,v in PACKET_FORMAT.iteritems():
    outbound_packet[v[0]:v[0]+v[1]] = kwargs.get(k, packet[k])
  return flipEndian(''.join(outbound_packet), flipOverride=True)

sock = socket.socket(socket.AF_INET, # Internet
                     socket.SOCK_DGRAM) # UDP
sock.bind((UDP_IP, UDP_PORT))

while True:
    data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
    data = data.encode("hex")
    print "received message:", data, addr
    words = list(chunks(data,8))

    parsed_packetData = decodePacketHeader(words[0])
    print "Packet Details"
    printPacketDetails(parsed_packetData, indentLevel=1)

    parsed_transactionData = decodeTransactionHeader(words[1])
    print "Transaction Details"
    printPacketDetails(parsed_transactionData, indentLevel=1)

    print "Packets Breakdown"
    printPacketsBreakdown(words, indentLevel=1)

    print "Responding with Transaction Header"
    responsePackets = []
    responsePackets.append(encodePacket(PACKET_HEADER_FORMAT, parsed_packetData))
    responsePackets.append(encodePacket(TRANSACTION_HEADER_FORMAT, parsed_transactionData, info_code='0'))
    print "Checking"
    printPacketDetails(decodePacketHeader(responsePackets[0]))
    printPacketDetails(decodeTransactionHeader(responsePackets[1], checkOutboundRequest=False))
    printPacketsBreakdown(responsePackets, indentLevel=1)

    print "Sending"
    sock.sendto((''.join(responsePackets)).decode("hex"), addr)

    print "ENDING"
    print "="*60

