import socket
import prepare_args
import packets
from multiprocessing.pool import ThreadPool

CHUNK_SIZE = 1024
PACKETS = [packets.DNS_PACKET, packets.EMPTY_PACKET, packets.ntp_packet()]


class PortChecker:
    """
    Класс для сканирования портов на указанном хосте и портовом диапазоне с
    использованием многопоточности.

    Атрибуты:
    -----------
    hostname : str
        IP-адрес хоста для сканирования.
    udp_checked : bool
        Флаг, указывающий, нужно ли сканировать порты с протоколом UDP.
    tcp_checked : bool
        Флаг, указывающий, нужно ли сканировать порты с протоколом TCP.
    ports : list of int
        Список номеров портов для сканирования.
    thread_pool : multiprocessing.pool.ThreadPool
        Пул потоков для обработки задач сканирования портов.

    Методы:
    --------
    __init__(self, host: str, is_udp: bool, is_tcp: bool, ports: tuple):
        Инициализирует объект класса PortChecker.

    start_scanning(self):
        Запускает сканирование портов.

    check_port(self, port: int, port_proto: str):
        Проверяет, доступен ли указанный порт на хосте, используя указанный протокол.

    recognize_protocol(self, data):
        Распознает протокол, используемый на указанном порту.

    """
    def __init__(self, host: str, is_udp: bool, is_tcp: bool, ports: tuple):
        """
        Инициализирует объект класса PortChecker.

        Параметры:
        ----------
        host : str
            Имя хоста для сканирования.
        is_udp : bool
            Флаг, указывающий, нужно ли сканировать порты с протоколом UDP.
        is_tcp : bool
            Флаг, указывающий, нужно ли сканировать порты с протоколом TCP.
        ports : tuple
            Кортеж из двух целых чисел, представляющих начальный и конечный номера портов для сканирования.
        """
        self.hostname = socket.gethostbyname(host)
        self.udp_checked = is_udp
        self.tcp_checked = is_tcp
        self.ports = [int(p) for p in ports]
        self.thread_pool = ThreadPool(processes=10)

    def start_scanning(self) -> None:
        """
        Запускает сканирование портов в диапазоне, используя многопоточность.
        """
        try:
            tasks = []
            for port in range(self.ports[0], self.ports[1] + 1):
                if self.tcp_checked:
                    tcp_task = self.thread_pool.apply_async(self.check_port,
                                                            args=(port, "TCP"))
                    tasks.append(tcp_task)
                if self.udp_checked:
                    udp_task = self.thread_pool.apply_async(self.check_port,
                                                            args=(port, "UDP"))
                    tasks.append(udp_task)
            for task in tasks:
                task.wait()
        finally:
            self.thread_pool.terminate()
            self.thread_pool.join()

    def check_port(self, port: int, port_proto: str) -> None:
        """
        Проверяет, доступен ли указанный порт на хосте, используя указанный
        протокол.

        Параметры:
        ----------
        port : int
            Номер проверяемого порта.
        port_proto : str
            Протокол для проверки (TCP или UDP).
        """
        is_connection = False
        if port_proto == "UDP":
            with (socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
                sock.settimeout(0.5)
                for packet in PACKETS:
                    try:
                        sock.sendto(packet, (self.hostname, port))
                        data, _ = sock.recvfrom(2048)
                        protocol = self.recognize_protocol(data)
                        print(f"{port_proto}: {port} {protocol}")
                        break
                    except socket.error:
                        pass

        else:
            with (socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(1)
                try:
                    sock.connect((self.hostname, port))
                    is_connection = True
                    data, _ = sock.recvfrom(1024)
                    protocol = self.recognize_protocol(data)
                    print(f"{port_proto}: {port} {protocol}")
                except socket.error:
                    if is_connection and port == 80:
                        print(f"{port_proto}: {port} HTTP")
                    elif is_connection and port == 43:
                        print(f"{port_proto}: {port} WHOIS")
                    elif is_connection:
                        print(f"{port_proto}: {port}")

    @staticmethod
    def recognize_protocol(data: bytes) -> str:
        """
        Распознает протокол, используемый на указанном порту.

        Параметры:
        ----------
        data : bytes
            Байтовый объект, полученный после установления соединения с портом.

        Возвращает:
        -----------
        str
            Строковое представление протокола, используемого на указанном порту.
        """
        ntp_signature = b"\x1c"
        dns_signature = b"\x00\x07exa"
        smtp_signature = b"220"
        pop3_signature = b"+OK\r\n"
        imap_signature = b"\x2A\x20\x4F\x4B\x20\x49\x4D\x41\x50"
        ssh_signature = b"SSH"

        if data.startswith(ntp_signature):
            return "NTP"
        elif data.endswith(dns_signature):
            return "DNS"
        elif data.startswith(smtp_signature):
            return "SMTP"
        elif data.startswith(pop3_signature):
            return "POP3"
        elif data.startswith(imap_signature):
            return "IMAP"
        elif data.startswith(ssh_signature):
            return "SSH"
        else:
            return ""


if __name__ == "__main__":
    args = prepare_args.prepare_args()
    checker = PortChecker(args.host, args.udp, args.tcp, args.ports)
    checker.start_scanning()
