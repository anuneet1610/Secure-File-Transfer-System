# Secure File Transfer System

A secure and reliable file transfer system built using Python sockets and modern cryptography.

## Features

- TCP-based file transfer
- ECDH key exchange (P-256)
- AES-256 encryption (CFB mode)
- RSA-PSS authentication
- SHA-256 integrity verification
- Chunk-based transfer with ACKs
- Automatic retransmission on corruption/loss
- Multi-client support using threads
- Live terminal dashboard using `rich`

---

## Technologies Used

- Python
- Socket Programming
- Cryptography Library
- Rich Terminal UI

---

## Security Architecture

| Component | Purpose |
|---|---|
| ECDH | Shared secret generation |
| HKDF | AES key + IV derivation |
| AES-256-CFB | File encryption |
| RSA-PSS | Server authentication |
| SHA-256 | Integrity verification |

---

## How It Works

1. Client connects to server over TCP
2. ECDH public keys are exchanged
3. Server signs its public key using RSA
4. Client verifies RSA signature
5. AES key and IV are derived using HKDF
6. File is encrypted and sent in chunks
7. Server verifies SHA-256 integrity
8. Retransmission occurs if corruption is detected

---

## Installation

Install dependencies:

```bash
pip install cryptography rich
```

---

## Run the Server

```bash
python server_updated.py
```

---

## Run the Client

```bash
python client_updated.py
```

Enter the filename when prompted.

---

## Project Structure

```text
.
├── client_updated.py
├── server_updated.py
├── public.pem
├── partial_*
├── recv_*
└── README.md
```

---

## Features Demonstrated

- TCP socket programming
- Secure key exchange
- Digital signatures
- Symmetric encryption
- Integrity verification
- Fault-tolerant transfer
- Multi-threaded server handling

---

## Future Improvements

- Resume interrupted transfers
- GUI interface
- AES-GCM support
- Compression
- Parallel chunk transfer
- TLS-style certificates

---

## Author

**Anuneet Gupta**  
IIT Goa
