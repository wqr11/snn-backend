class LogColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def log(level: str = 'INFO', *data):
    level = level.upper()

    match level:
        case "INFO":
            color = LogColors.OKBLUE
        case "WARN":
            color = LogColors.WARNING
        case "ERR":
            color = LogColors.FAIL
        case "DEBUG":
            color = LogColors.OKGREEN
        case _:
            color = LogColors.OKCYAN

    print(f"{color}{level}:     {LogColors.ENDC}", end="")
    print(*data)
