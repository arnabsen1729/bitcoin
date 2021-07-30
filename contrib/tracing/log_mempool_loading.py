#!/usr/bin/env python3

import sys
from bcc import BPF, USDT
from bcc.utils import printb

program = """
# include <uapi/linux/ptrace.h>

struct data_t
{
  u64 count;
  u64 failed;
  u64 expired;
  u64 already;
  u64 unbroadcast;
};

BPF_PERF_OUTPUT(mempool_loaded);

int trace_mempool_loaded(struct pt_regs *ctx) {
  struct data_t data = {};
  data.count=123;

  bpf_usdt_readarg(1, ctx, &data.count);
  bpf_usdt_readarg(2, ctx, &data.failed);
  bpf_usdt_readarg(3, ctx, &data.expired);
  bpf_usdt_readarg(4, ctx, &data.already);
  bpf_usdt_readarg(5, ctx, &data.unbroadcast);

  mempool_loaded.perf_submit(ctx, &data, sizeof(data));
  return 0;
}
"""


def print_event(event):
    print("%-15d %-10d %-10d %-17d %-15d" % (
        event.count,
        event.failed,
        event.expired,
        event.already,
        event.unbroadcast,
    ))


def main(bitcoind_path):
    bitcoind_with_usdts = USDT(path=str(bitcoind_path))
    bitcoind_with_usdts.enable_probe("mempool_loaded", "trace_mempool_loaded")
    b = BPF(text=program, usdt_contexts=[bitcoind_with_usdts])

    def handle_mempool_loaded(_, data, size):
        event = b["mempool_loaded"].event(data)
        print_event(event)

    b["mempool_loaded"].open_perf_buffer(handle_mempool_loaded)
    print("Loaded mempool...")
    print("%-15s %-10s %-10s %-17s %-15s" % ("Succeeded", "Failed",
                                             "Expired", "Already there", "Waiting for broadcast"))
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
