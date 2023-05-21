import argparse


def prepare_args() -> argparse.Namespace:
    """
    Подготавливает и парсит аргументы командной строки.

    Возвращает:
    --------
    argparse.Namespace
        Объект, содержащий значения аргументов командной строки.
    """
    arg_parser = argparse.ArgumentParser(
        prog='portscan',
        description='A tool for checking open ports'
    )
    arg_parser.add_argument('host', default='127.0.0.1', type=str,
                            help='the host to scan for open ports')
    arg_parser.add_argument('-u', action='store_true', dest='udp',
                            help='use UDP protocol')
    arg_parser.add_argument('-t', action='store_true', dest='tcp',
                            help='use TCP protocol')
    arg_parser.add_argument('-p', '--ports', nargs='+', dest='ports',
                            help='a list of ports to scan')

    return arg_parser.parse_args()
