import struct


def dns_packet() -> bytes:
    """
    Создает DNS-запрос в виде байтового объекта.

    Возвращает:
    -----------
    bytes
        Байтовый объект, представляющий DNS-запрос.
    """
    pack_id = struct.pack('!H', 20)
    flags = struct.pack('!H', 256)
    qd_count = struct.pack('!H', 1)
    an_count = struct.pack('!H', 0)
    ns_count = struct.pack('!H', 0)
    ar_count = struct.pack('!H', 0)
    header = pack_id + flags + qd_count + an_count + ns_count + ar_count
    domain = 'example.ru'
    sec_dom, first_dom = domain.split('.')
    mark_first = struct.pack('!H', len(sec_dom))
    byte_sec = struct.pack(f'!{len(sec_dom)}s', sec_dom.encode())
    mark_second = struct.pack('!H', 2)
    byte_first = struct.pack(f'!{len(first_dom)}s', first_dom.encode())
    q_type = struct.pack('!H', 1)
    q_class = struct.pack('!H', 1)
    packet = header + mark_first + byte_sec + mark_second + byte_first \
             + struct.pack('!H', 0) + q_type + q_class
    return packet


def ntp_packet() -> bytes:
    """
    Создает NTP-запрос в виде байтового массива.

    Возвращает:
    -----------
    bytearray
        Байтовый массив, представляющий NTP-запрос.
    """
    ntp_request = bytearray(48)
    ntp_request[0] = 0x1B
    return ntp_request


def http_packet() -> bytes:
    return b"GET / HTTP/1.1\r\n\r\n"


DNS_PACKET = dns_packet()
NTP_PACKET = ntp_packet()
HTTP_PACKET = http_packet()
EMPTY_PACKET = b""
