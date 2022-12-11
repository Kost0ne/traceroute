from ipaddress import ip_address
from enums import Error


def validate_ip_address(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False

    return True


def validate_port(value: int) -> bool:
    if value is None:
        return True
    return 0 <= value <= 65535


def validate_timeout(value: float) -> bool:
    return value > 0


def validate_args(ip_address: str, port: int, timeout: float) -> Error | None:
    if not validate_ip_address(ip_address):
        print("Invalid IP address")
        return Error.INVALID_IP
    elif not validate_port(port):
        print("Invalid port")
        return Error.INVALID_PORT
    elif not validate_timeout(timeout):
        print("Invalid timeout")
        return Error.NEGATIVE_ARGUMENT
