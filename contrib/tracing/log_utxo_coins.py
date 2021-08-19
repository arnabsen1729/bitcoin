#!/usr/bin/env python3

import sys
from bcc import BPF, USDT

""" Example script to log details about add/spend/uncache coin events.
utilizing USDT probes and the utxo:coins_added, utxo:coins_spent,
utxo:coins_uncached  tracepoint. """

program = """
# include <uapi/linux/ptrace.h>

#define MAX_HASH_SIZE 64

struct coin_data
{
  u32 height;
  char hash[MAX_HASH_SIZE];
  long value;
  u32 isCoinBase;
  u64 usage;
};

BPF_PERF_OUTPUT(coins_added);
BPF_PERF_OUTPUT(coins_spent);
BPF_PERF_OUTPUT(coins_uncached);

int trace_add_coin(struct pt_regs *ctx) {
  struct coin_data data = {};
  bpf_usdt_readarg_p(1, ctx, &data.hash, MAX_HASH_SIZE);
  bpf_usdt_readarg(2, ctx, &data.height);
  bpf_usdt_readarg(3, ctx, &data.value);
  bpf_usdt_readarg(4, ctx, &data.isCoinBase);
  bpf_usdt_readarg(5, ctx, &data.usage);
  coins_added.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_spend_coin(struct pt_regs *ctx) {
  struct coin_data data = {};
  bpf_usdt_readarg_p(1, ctx, &data.hash, MAX_HASH_SIZE);
  bpf_usdt_readarg(2, ctx, &data.height);
  bpf_usdt_readarg(3, ctx, &data.value);
  bpf_usdt_readarg(4, ctx, &data.isCoinBase);
  bpf_usdt_readarg(5, ctx, &data.usage);
  coins_spent.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

int trace_uncached_coin(struct pt_regs *ctx) {
    struct coin_data data = {};
    bpf_usdt_readarg_p(1, ctx, &data.hash, MAX_HASH_SIZE);
    bpf_usdt_readarg(2, ctx, &data.height);
    bpf_usdt_readarg(3, ctx, &data.value);
    bpf_usdt_readarg(4, ctx, &data.isCoinBase);
    bpf_usdt_readarg(5, ctx, &data.usage);
    coins_uncached.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""


def print_event(event, action):
    print("%-68s %-10s %-10d %-15d %-10s %-10d" %
          (event.hash.decode('ASCII'), action, event.height, event.value, "YES" if event.isCoinBase else "NO", event.usage))


def main(bitcoind_path):
    bitcoind_with_usdts = USDT(path=str(bitcoind_path))
    bitcoind_with_usdts.enable_probe(
        probe="coins_added", fn_name="trace_add_coin")
    bitcoind_with_usdts.enable_probe(
        probe="coins_spent", fn_name="trace_spend_coin")
    bitcoind_with_usdts.enable_probe(
        probe="coins_uncached", fn_name="trace_uncached_coin")

    b = BPF(text=program, usdt_contexts=[bitcoind_with_usdts])

    def handle_coins_added(_, data, size):
        event = b["coins_added"].event(data)
        print_event(event, "Add")

    def handle_coins_spent(_, data, size):
        event = b["coins_spent"].event(data)
        print_event(event, "Spent")

    def handle_coins_uncached(_, data, size):
        event = b["coins_uncached"].event(data)
        print_event(event, "Uncache")

    b["coins_added"].open_perf_buffer(handle_coins_added)
    b["coins_spent"].open_perf_buffer(handle_coins_spent)
    b["coins_uncached"].open_perf_buffer(handle_coins_uncached)

    print("Logging Add, Spend and Uncache in the UTXO set. Ctrl-C to end...")
    print("%-68s %-10s %-10s %-15s %-10s %s"%("txHash","Action", "Height", "Satoshis", "Coin Base", "Usage" ))
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
