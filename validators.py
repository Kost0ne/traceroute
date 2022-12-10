from ipaddress import ip_address


def is_ip_address(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False

    return True


def is_port(value: int) -> bool:
    return 0 <= value <= 65535
