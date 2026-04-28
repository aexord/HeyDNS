import subprocess
import ipaddress
import argparse
import socket
import re


GLOBAL_HOSTS = {}


class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[00m'


def banner(only_brute: bool = False):
    banner_info = f"""
    {Colors.YELLOW}╔═══════════════════════════════════════╗
    {Colors.YELLOW}║                                       ║
    {Colors.YELLOW}║{Colors.BLUE}  HeyDNS by @Aexord, @Machine_Prophet  {Colors.YELLOW}║
    {Colors.YELLOW}║                             ver. 1.1  ║
    {Colors.YELLOW}╚═══════════════════════════════════════╝{Colors.RESET}
    {Colors.YELLOW} Режим работы: {Colors.RESET}
    {Colors.YELLOW} DNS-сервер - {Colors.BLUE} {"Перенос зоны + брут по подсети" if not only_brute else "Только брут по подсети"} {Colors.RESET}
    {Colors.YELLOW} DC DNS-сервер - {Colors.BLUE} Только брут по подсети {Colors.RESET}
    """
    print(banner_info)


def print_message(text: str, level: str, ender: str = "\n", flusher: bool = False):
    """
    Вывод красочных сообщений
    """

    match level:
        case "text":
            print(f"{text}", end=ender, flush=flusher)
        case "success":
            print(f"{Colors.BLUE}[+] {text} {Colors.RESET}", end=ender, flush=flusher)
        case "fail":
            print(f"{Colors.RED}[-] {text} {Colors.RESET}", end=ender, flush=flusher)
        case "alert":
            print(f"{Colors.YELLOW}[?] {text} {Colors.RESET}", end=ender, flush=flusher)


def nmap_parse(nmap_output: str) -> list:
    """
    Парсинг вывода nmap
    """
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ips = re.findall(ip_pattern, nmap_output)
    return ips


def check_alive_hosts(subnet: str) -> list:
    """
    Быстрая проверка живых хостов по подсети
    """
    if not bool(re.fullmatch(r'[0-9./]*', subnet)):
        print_message("Некорректный формат целей для nmap!", "fail")
        exit(1)
    try:
        checker = subprocess.run("nmap -sn -n -PE -PP -PS --min-rate 1000 {subnet}".format(subnet=subnet),
                                 shell=True, capture_output=True, text=True, check=True)
        print_message("Залутали список живых хостов:", "success")
        iplist = nmap_parse(checker.stdout)
        print_message(", ".join(iplist), "text")
        # print_message(checker.stderr, "fail") # debug fail
        return iplist
    except subprocess.CalledProcessError as e:
        print_message(f"Что-то пошло не так: {e.stderr}", "fail")
        exit(1)


def check_port(ip: str, port: int = 53):
    """
    Проверка порта на хосте, по умолчанию, проверяем DNS
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        return True if result == 0 else False
    except:
        return False


def find_dns_servers(ips: list) -> list:
    """
    Функция определения DNS-серверов
    """
    dns_servers = []
    for ip in ips:
        if check_port(ip):
            dns_servers.append(ip)
            print_message(ip, "success")

    if not dns_servers:
        print_message("Не нашли DNS-серверов", "fail")
        exit(1)

    return dns_servers


def check_dc_dns_server(ip: str) -> bool:
    """
    Функция определения DC DNS-серверов
    """

    try:
        if check_port(ip, 88):
            print_message(f"Нашли DC DNS-сервер: {ip}", "success")
            return True
        else:
            print_message(f"Не DC DNS-сервер: {ip}", "alert")
            return False

    except Exception as e:
        print_message(f"Что-то пошло не так: {str(e)}", "fail")
        exit(1)


def transfer_zone(dns_server: str, domain: str) -> list:
    """
    Функция переноса зоны для DNS-серверов
    """

    def find_ip_for_hostname(hname, list_records):
        for address, hostnames in list_records.items():
            if hname in hostnames:
                return address
        return None

    try:
        checker = subprocess.run("dig axfr {domain} @{dns}".format(domain=domain, dns=dns_server),
                                 shell=True, capture_output=True, text=True, check=True)
        if "Transfer failed" in checker.stdout:
            print_message(f"Перенос зоны для {domain} на {dns_server} не сработал :(", "alert")
            return []

        pattern_A_record = r'^(\S+)\s+\d+\s+IN\s+A\s+(\d+\.\d+\.\d+\.\d+)$'
        pattern_CNAME_record = r'^(\S+)\s+\d+\s+IN\s+CNAME\s+(\S+)$'
        records = {}

        for line in checker.stdout.split('\n'):
            match = re.match(pattern_A_record, line.strip())
            if match:
                hostname = match.group(1).rstrip('.')
                if "*" in hostname:
                    continue
                ip = match.group(2)
                if ip in records:
                    records[ip].append(hostname)
                else:
                    records[ip] = [hostname]
            else:
                match = re.match(pattern_CNAME_record, line.strip())
                if match:
                    first_hostname = match.group(1).rstrip('.')
                    if "*" in first_hostname:
                        continue
                    second_hostname = match.group(2).rstrip('.')
                    if ip := find_ip_for_hostname(second_hostname, records):
                        records[ip].append(first_hostname)

        print_message(f"Перенос зоны для {domain} сработал, держи hosts:", "success")
        print_message("\n".join(f"{ip} {" ".join(records[ip])}" for ip in records.keys()), "text", ender="\n\n")
        # print_message(checker.stderr, "fail") # debug fail
    except subprocess.CalledProcessError as e:
        print_message(f"Что-то пошло не так: {e.stderr}", "fail", ender="\n\n")
        exit(1)


def req_dc_dns_server(dns_server: str, subnet: str) -> (dict, list):
    """
    Функция опроса DNS-серверов по подсети
    """

    hosts = {}

    try:
        # Узнаем имя DC и домен
        checker = subprocess.run("timeout 2 nslookup {ip} {dns}".format(ip=dns_server, dns=dns_server),
                                 shell=True, capture_output=True, text=True)

        if "communications error" in checker.stdout:
            print_message(f"Словил таймаут от DNS-сервера {dns_server} - это ненормально", "fail")
            return {}

        if "server can't find" in checker.stdout:
            print_message(f"Так, этот {dns_server} сервер даже себя опознать не может, пропустим его", "fail")
            return {}

        pattern = r'(\d+)\.(\d+)\.(\d+)\.(\d+)\.in-addr\.arpa\s+name\s+=\s+([^\s]+)\.?$'
        match = re.match(pattern, checker.stdout.strip())
        if not hasattr(match, 'group'):
            print_message(f"Так, проблема с парсингом: {match}", "fail")
            return {}
        dc_name = match.group(5).rstrip('.')
        domain = dc_name.split('.', maxsplit=1)
        domain = f"{domain[1]}"

        # Начинаем допрос DC DNS
        network = ipaddress.ip_network(subnet, strict=False)
        iplist = [str(ip) for ip in network.hosts()]

        for ip in iplist:
            checker = subprocess.run("timeout 2 nslookup {ip} {dns}".format(ip=ip, dns=dns_server),
                                     shell=True, capture_output=True, text=True)
            if "server can't find" in checker.stdout or not checker.stdout or checker.returncode != 0:
                continue
            else:
                match = re.match(pattern, checker.stdout.strip())
                if not hasattr(match, 'group'):
                    print_message(f"Так, проблема с парсингом: {match}", "fail")
                    continue
                hostname = match.group(5).rstrip('.')
                if domain in hostname:
                    if hostname in hosts:
                        hosts[hostname].append(ip)
                    else:
                        hosts[hostname] = [ip]
                    print_message(f"Нашли хост:", "success", ender=" ")
                    print_message(hostname, "text")
                else:
                    if hostname in hosts:
                        hosts[f"{hostname}.{domain}"].append(ip)
                    else:
                        hosts[f"{hostname}.{domain}"] = [ip]
                    print_message(f"Нашли хост и добавили предположительный домен: ", "success", ender=" ")
                    print_message(f"{hostname}.{domain}", "text")

        return hosts

    except Exception as e:
        print_message(f"Что-то пошло не так: {str(e)}", "fail")
        exit(1)


def interrogation_dns_servers(subnet: str, dns_servers: list, domains: str = None, only_brute: bool = False):
    """
    Массивная функция работы с DNS-серверами (перенос зоны + опрос)
    """
    if domains is None or domains == "":
        list_domains = []
    else:
        list_domains = domains.split(',')

    for dns_server in dns_servers:
        print_message(f" ", "text")
        # Для не-DC DNS-серверов пытаемся и перенос зоны сделать, и опросить их по всей подсети
        if not check_dc_dns_server(dns_server):

            if not only_brute:
                if not list_domains:
                    print_message('Нет домена - нет возможного переноса зоны ._.', 'fail')
                else:
                    for domain in list_domains:
                        transfer_zone(dns_server, domain)

            print_message(f"Начинаем злостный опрос {dns_server} v_v", "alert", ender="\n\n")

            # Все хосты, для которых определили имя
            hosts = req_dc_dns_server(dns_server, subnet)

            # Массив для хостов, у которых есть пересечение по ip/имя
            buffer = {}

            # Если нашли хосты
            if hosts:
                print_message(f"Залутали хостов для hosts с {dns_server}:", "success")
            else:
                continue

            for hostname in hosts.keys():
                if hostname not in GLOBAL_HOSTS:
                    GLOBAL_HOSTS[hostname] = hosts[hostname]
                else:
                    GLOBAL_HOSTS[hostname] = list(set(GLOBAL_HOSTS[hostname] + hosts[hostname]))

                # Определяем проблемные хосты
                if len(hosts[hostname]) == 1:
                    print_message(f"{hosts[hostname][0]} {hostname}", 'text')
                else:
                    buffer[hostname] = hosts[hostname]
            if buffer:
                print_message("Также есть пересечение по именами и ip:", "alert")
                for hostname in buffer.keys():
                    print_message(f"{hostname} {" ".join(buffer[hostname])}", "text")
        # Для DC-DNS серверов как правило перенос зоны не работает, поэтому просто начнём их злостно опрашивать
        else:
            print_message(f"Начинаем злостный опрос {dns_server} v_v", "alert")

            # Все хосты, для которых определили имя
            hosts = req_dc_dns_server(dns_server, subnet)

            # Массив для хостов, у которых есть пересечение по ip/имя
            buffer = {}

            if hosts:
                print_message(f"Залутали хостов для hosts с {dns_server}:", "success")
            else:
                continue

            # Если нашли хосты
            for hostname in hosts.keys():
                if hostname not in GLOBAL_HOSTS:
                    GLOBAL_HOSTS[hostname] = hosts[hostname]
                else:
                    GLOBAL_HOSTS[hostname] = list(set(GLOBAL_HOSTS[hostname] + hosts[hostname]))

                # Определяем проблемные хосты
                if len(hosts[hostname]) == 1:
                    print_message(f"{hosts[hostname][0]} {hostname}", 'text')
                else:
                    buffer[hostname] = hosts[hostname]
            if buffer:
                print_message("Также есть пересечение по именами и ip:", "alert")
                for hostname in buffer.keys():
                    print_message(f"{hostname} {" ".join(buffer[hostname])}", "text")


def save_result(filename: str):
    """
    Сохранение финального результата перебора
    """
    try:
        with open(filename, "w") as file:
            file.writelines(GLOBAL_HOSTS)
            file.close()
    except Exception as err:
        print_message(f"Ошибка сохранения результата! Файл не бы создан.", "fail")
        exit(1)


def run_recon(target: str, flags: dict, domains: str = None):
    """
    Основная функция запуска разведки и финального вывода по её результатам
    """
    only_brute = flags["brute"]
    input_servers = flags["servers"].split(',') if flags["servers"] else None
    outfile = flags["outfile"]
    skip_search = flags["skip"]
    if skip_search and not input_servers:
        print_message(f"Если не ищем DNS-сервера их нужно указать!", "fail")
        exit(1)

    banner(only_brute)
    if not skip_search:
        print_message("Ищем живые хосты", "alert", ender="\n\n")
        iplist = check_alive_hosts(target)
        print_message(f" ", "text")
        print_message("Ищем DNS-сервера", "alert", ender="\n\n")
        dns_servers = find_dns_servers(iplist)
    else:
        print_message("Пропускаем поиск", "info", ender="\n\n")
        dns_servers = []
    if input_servers:
        for server in input_servers:
            if server not in input_servers:
                dns_servers.append(server)
    print_message(f" ", "text")
    print_message("Начинаем работать с каждым сервером", "alert")
    interrogation_dns_servers(target, dns_servers, domains, only_brute)

    if GLOBAL_HOSTS:
        print_message(f"-------------------------------", "text")
        print_message(f"Финализированный результат для hosts:", "success")
        buffer = {}
        for hostname in GLOBAL_HOSTS.keys():
            if len(GLOBAL_HOSTS[hostname]) == 1:
                print_message(f"{GLOBAL_HOSTS[hostname][0]}    {hostname}", "text")
            else:
                buffer[hostname] = GLOBAL_HOSTS[hostname]
        if buffer:
            print_message(f"-------------------------------", "text")
            print_message("Оставшиеся не распределенные хосты:", "alert")
            for hostname in buffer.keys():
                print_message(f"{hostname} {" ".join(buffer[hostname])}", "text")
    if outfile:
        print_message(f"-------------------------------", "text")
        save_result(outfile)
        print_message(f"Сохранили результат {outfile}", "success")


if __name__ == "__main__":
    usage = "Самое главное убедитесь, что имеется возможность с атакующей машины увидеть DNS-сервер, иначе фиаско :)"
    parser = argparse.ArgumentParser(description="Тулза для допроса DNS-серверов в подсети", usage=usage)
    parser.add_argument('target', type=str, help='подсетка')
    parser.add_argument('--domains', type=str, help='список доменов (при наличии)')
    parser.add_argument('-b', '--brute', action='store_true', help='Только брут подсетей')
    parser.add_argument('--skip', action='store_true', help='пропустить поиск DNS-серверов')
    parser.add_argument('-s', '--servers', type=str, help='список DNS-серверов, eg. 10.0.0.1,10.0.0.2')
    parser.add_argument('-o', '--outfile', type=str, help='сохранить финальный результат в указанный файл')
    args = parser.parse_args()

    run_recon(target=args.target, domains=args.domains,
              flags={"brute": args.brute, "servers": args.servers, "skip": args.skip, "outfile": args.outfile})
