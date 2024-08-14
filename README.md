# PySlidingWindow

Custom GBN file transfer implementation with two key features:
 1. Sel. Rep. buffering  :   reciever buffers out-of-order packets
 2. RFC 2001 fast retrans:   immediately retrans on Nth duplicate ack

Fix-len header (8 byte check# + 2 byte seq#), sent in hex
Seq# are sent serialized (i.e. can wrap around without side-effects), allowing for unlimited total size & # of msgs

Should be decently fast with ~40% chance of packet corruption and ~40% packet loss.

# Usage

## Sender

```bash
python Sender.py <SendingPort>
```
Read from `stdin` and send through port `<SendingPort>`.

```bash
python Sender.py <SendingPort> < input.txt
```
Read from file `input.txt` and send through port `<SendingPort>`.

## Reciever

```bash
python Reciever.py <ListeningPort>
```
Listen on port `<ListeningPort>` and print to `<stdout>` (non-blocking).

```bash
python Reciever.py <ListeningPort> > output.txt
```
Listen on port `<ListeningPort>` and print to file `output.txt`.

# Config

Each file has the following configurable hardcoded constants. Feel free to experiment:

`MAX_PKT_BYTES`   - Packet size in bytes
`CSUM_BYTES`      - No. of bytes allocated to checksum
`SNUM_BYTES`      - No. of bytes allocated to sequence number. Does not affect max size of data sendable.
`WINDOW_SIZE`     - Size of GBN sliding window
`MAX_DUPLICATES`  - Maximum number of consecutive lost bytes tolerable, before mass retransmission.

---

https://en.wikipedia.org/wiki/Serial_number_arithmetic

https://en.wikipedia.org/wiki/Sliding_window_protocol#Sequence_number_range_required
