import argparse


def get_parser():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument("-t", dest="timeout",
                            type=float,
                            default=2,
                            help="Таймаут ожидания ответа. "
                                 "По умолчанию 2 секунды.")
    arg_parser.add_argument("-p", dest="port",
                            type=int,
                            help="Порт (для tcp или udp).")
    arg_parser.add_argument("-n", dest="max_ttl",
                            type=int,
                            default=30,
                            help="Максимальное количество запросов. "
                                 "По умолчанию 30.")
    arg_parser.add_argument("-v", dest="verbose",
                            action="store_true",
                            help="Вывод номера автономной системы "
                            "для каждого ip-адреса.")

    arg_parser.add_argument("IP_ADDRESS")

    arg_parser.add_argument("PROTOCOL",
                            choices=["icmp", "tcp", "udp"],
                            help="Протокол (icmp, tcp или udp).")

    return arg_parser
