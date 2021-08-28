#!/usr/bin/env python3

import sys
import ctypes
from bcc import BPF, USDT

""" Example script to log details about add/spend/uncache coin events.
utilizing USDT probes and the utxocache:add, utxocache:spent,
utxocache:uncache tracepoint."""

program = """
# include <uapi/linux/ptrace.h>

#define MAX_HASH_SIZE 64

struct coin_data
{
  char hash[MAX_HASH_SIZE];
  u32 index;
  u32 height;
  long value;
  u64 usage;
  u64 cachedCoinsCount;
  bool isCoinBase;
};

BPF_PERF_OUTPUT(add);
BPF_PERF_OUTPUT(spent);
BPF_PERF_OUTPUT(uncache);

int trace_add_coin(struct pt_regs *ctx) {
    struct coin_data data = {};
    bpf_usdt_readarg_p(1, ctx, &data.hash, MAX_HASH_SIZE);
    bpf_usdt_readarg(2, ctx, &data.index);
    bpf_usdt_readarg(3, ctx, &data.height);
    bpf_usdt_readarg(4, ctx, &data.value);
    bpf_usdt_readarg(5, ctx, &data.isCoinBase);
    bpf_usdt_readarg(6, ctx, &data.usage);
    bpf_usdt_readarg(7, ctx, &data.cachedCoinsCount);
    add.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_spend_coin(struct pt_regs *ctx) {
    struct coin_data data = {};
    bpf_usdt_readarg_p(1, ctx, &data.hash, MAX_HASH_SIZE);
    bpf_usdt_readarg(2, ctx, &data.index);
    bpf_usdt_readarg(3, ctx, &data.height);
    bpf_usdt_readarg(4, ctx, &data.value);
    bpf_usdt_readarg(5, ctx, &data.isCoinBase);
    bpf_usdt_readarg(6, ctx, &data.usage);
    bpf_usdt_readarg(7, ctx, &data.cachedCoinsCount);
    spent.perf_submit(ctx, &data, sizeof(data));
    return 0;
}

int trace_uncached_coin(struct pt_regs *ctx) {
    struct coin_data data = {};
    bpf_usdt_readarg_p(1, ctx, &data.hash, MAX_HASH_SIZE);
    bpf_usdt_readarg(2, ctx, &data.index);
    bpf_usdt_readarg(3, ctx, &data.height);
    bpf_usdt_readarg(4, ctx, &data.value);
    bpf_usdt_readarg(5, ctx, &data.isCoinBase);
    bpf_usdt_readarg(6, ctx, &data.usage);
    bpf_usdt_readarg(7, ctx, &data.cachedCoinsCount);
    uncache.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""


class Data(ctypes.Structure):
    _fields_ = [
        ("hash", ctypes.c_char * 64),
        ("index", ctypes.c_uint32),
        ("height", ctypes.c_uint32),
        ("value", ctypes.c_uint64),
        ("usage", ctypes.c_uint64),
        ("cachedCoinsCount", ctypes.c_uint64),
        ("isCoinBase", ctypes.c_bool),
    ]


def print_event(event, action):
    print("%-70s %-10s %-10d %-15d %-10s %-15d %d" %
          (f"{event.hash.decode('ASCII')}:{str(event.index)}",
           action, event.height,
           event.value,
           "YES" if event.isCoinBase else "NO",
           event.usage,
           event.cachedCoinsCount))


def main(bitcoind_path):
    bitcoind_with_usdts = USDT(path=str(bitcoind_path))
    bitcoind_with_usdts.enable_probe(
        probe="add", fn_name="trace_add_coin")
    bitcoind_with_usdts.enable_probe(
        probe="spent", fn_name="trace_spend_coin")
    bitcoind_with_usdts.enable_probe(
        probe="uncache", fn_name="trace_uncached_coin")

    b = BPF(text=program, usdt_contexts=[bitcoind_with_usdts])

    def handle_coins_added(_, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Data)).contents
        print_event(event, "Add")

    def handle_coins_spent(_, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Data)).contents
        print_event(event, "Spent")

    def handle_coins_uncached(_, data, size):
        event = ctypes.cast(data, ctypes.POINTER(Data)).contents
        print_event(event, "Uncache")

    b["add"].open_perf_buffer(handle_coins_added)
    b["spent"].open_perf_buffer(handle_coins_spent)
    b["uncache"].open_perf_buffer(handle_coins_uncached)

    print("Logging Add, Spend and Uncache in the UTXO set. Ctrl-C to end...")
    print("%-70s %-10s %-10s %-15s %-10s %-15s %s" %
          ("Outpoint",
           "Action",
           "Height",
           "Value",
           "Coinbase",
           "Memory Usage",
           "Cached Coins"))

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit(0)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("USAGE: ", sys.argv[0], "path/to/bitcoind")
        exit(1)

    path = sys.argv[1]
    main(path)
