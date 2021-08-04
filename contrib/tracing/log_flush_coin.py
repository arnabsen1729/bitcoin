#!/usr/bin/env python3

import sys
from bcc import BPF, USDT
from bcc.utils import printb

program = """
# include <uapi/linux/ptrace.h>

struct data_t
{
  long ts;
  u32 mode;
  u64 coins;
  u64 coins_mem_usage;
  u64 available_disk_space;
};

BPF_ARRAY(data_arr, struct data_t, 1);

BPF_PERF_OUTPUT(flush_coins);

int trace_flush_coins(struct pt_regs *ctx) {
  int idx = 0;
  struct data_t *data = data_arr.lookup(&idx);

  if (data == NULL) return 1;

  bpf_usdt_readarg(1, ctx, &data->ts);
  bpf_usdt_readarg(2, ctx, &data->mode);
  bpf_usdt_readarg(3, ctx, &data->coins);
  bpf_usdt_readarg(4, ctx, &data->coins_mem_usage);
  bpf_usdt_readarg(5, ctx, &data->available_disk_space);
  flush_coins.perf_submit(ctx, data, sizeof(*data));
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
    print("%-10s %-10d %-20s %s" % (
        FLUSH_MODES[event.mode],
        event.coins,
        "%.2f kB"%(event.coins_mem_usage/1000),
        "%.2f kB"%(event.available_disk_space/1000),
    ))


def main(bitcoind_path):
    bitcoind_with_usdts = USDT(path=str(bitcoind_path))
    bitcoind_with_usdts.enable_probe(probe="flush_coins", fn_name="trace_flush_coins")
    b = BPF(text=program, usdt_contexts=[bitcoind_with_usdts])

    def handle_flush_coins(_, data, size):
        event = b["flush_coins"].event(data)
        print_event(event)

    b["flush_coins"].open_perf_buffer(handle_flush_coins)
    print("Logging Disk State (during flush). Ctrl-C to end...")
    print("%-10s %-10s %-20s %-15s" % ("Mode",
                                       "Coins", "Coin Memory Usage", "Available Disk Space"))
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
