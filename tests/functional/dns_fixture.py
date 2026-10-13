"""A local authoritative-style UDP fixture; never forwards questions to the internet."""

from collections import Counter
import ipaddress
import socketserver
import struct
import threading


def wire_name(name):
    if name == ".":
        return b"\0"
    return b"".join(bytes([len(label)]) + label.encode("ascii")
                    for label in name.rstrip(".").split(".")) + b"\0"


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        offset, labels = 12, []
        while data[offset]:
            length = data[offset]
            labels.append(data[offset + 1:offset + 1 + length].decode("ascii"))
            offset += length + 1
        offset += 1
        record_type, query_class = struct.unpack("!HH", data[offset:offset + 4])
        question = data[12:offset + 4]
        domain = ".".join(labels).lower()
        with self.server.lock:
            self.server.questions[(domain, record_type)] += 1
        if domain == "timeout.test" or (domain == "partial.test" and record_type == 15):
            return  # Simulate one record type timing out.
        status = 3 if domain == "missing.test" else 0
        payload = None
        if not status:
            if record_type == 1:
                payload = ipaddress.ip_address("192.0.2.10").packed
            elif record_type == 28:
                payload = ipaddress.ip_address("2001:db8::10").packed
            elif record_type == 2:
                payload = wire_name("ns1.fixture.test")
            elif record_type == 15:
                payload = struct.pack("!H", 0 if domain == "null-mail.test" else 10)
                payload += wire_name("." if domain == "null-mail.test" else "mail.fixture.test")
        answer = b""
        if payload is not None:
            answer = b"\xc0\x0c" + struct.pack("!HHIH", record_type, query_class, 60, len(payload)) + payload
        header = struct.pack("!HHHHHH", struct.unpack("!H", data[:2])[0],
                             0x8180 | status, 1, int(bool(answer)), 0, 0)
        sock.sendto(header + question + answer, self.client_address)


class DNSFixture:
    def __init__(self):
        self.server = socketserver.UDPServer(("127.0.0.1", 0), DNSHandler)
        self.server.questions = Counter()
        self.server.lock = threading.Lock()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def address(self):
        host, port = self.server.server_address
        return f"{host}:{port}"

    def count(self, domain):
        with self.server.lock:
            return sum(count for (name, _), count in self.server.questions.items() if name == domain)

    def start(self):
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
