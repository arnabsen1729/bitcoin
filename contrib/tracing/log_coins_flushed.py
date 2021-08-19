#!/usr/bin/env python3

import sys
from bcc import BPF, USDT

""" Example script to log details about coins flushed by the Bitcoin client
utilizing USDT probes and the flush:coins_flushed tracepoint. """

# USAGE:  ./contrib/tracing/log_coins_flushed.py path/to/bitcoind

# BCC: The C program to be compiled to an eBPF program (by BCC) and loaded into
# a sandboxed Linux kernel VM.
program = """
# include <uapi/linux/ptrace.h>

struct data_t
{
  long ts;
  u32 mode;
  u64 coins;
  u64 coins_mem_usage;
};

// BPF perf buffer to push the data to user space.
BPF_PERF_OUTPUT(coins_flushed);

int trace_coins_flushed(struct pt_regs *ctx) {
  struct data_t data = {};

  bpf_usdt_readarg(1, ctx, &data.ts);
  bpf_usdt_readarg(2, ctx, &data.mode);
  bpf_usdt_readarg(3, ctx, &data.coins);
  bpf_usdt_readarg(4, ctx, &data.coins_mem_usage);

  coins_flushed.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
"""


FLUSH_MODES = [
    'NONE',
    'IF_NEEDED',
    'PERIODIC',
    'ALWAYS'
]


def print_event(event):
    print("%-10s %-10d %-20s" % (
        FLUSH_MODES[event.mode],
        event.coins,
        "%.2f kB" % (event.coins_mem_usage/1000),
    ))


def main(bitcoind_path):
    bitcoind_with_usdts = USDT(path=str(bitcoind_path))

    # attaching the trace functions defined in the BPF program
    # to the tracepoints
    bitcoind_with_usdts.enable_probe(
        probe="coins_flushed", fn_name="trace_coins_flushed")
    b = BPF(text=program, usdt_contexts=[bitcoind_with_usdts])

    def handle_coins_flushed(_, data, size):
        """ Coins Flush handler.

          Called each time coin caches and indexes are flushed."""
        event = b["coins_flushed"].event(data)
        print_event(event)

    b["coins_flushed"].open_perf_buffer(handle_coins_flushed)
    print("Logging Coin flushes. Ctrl-C to end...")
    print("%-10s %-10s %-20s" % ("Mode",
                                 "Coins", "Coin Memory Usage"))
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
