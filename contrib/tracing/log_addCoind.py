#!/usr/bin/env python3

import sys
from bcc import BPF, USDT
from bcc.utils import printb

program = """
# include <uapi/linux/ptrace.h>

struct coin_data
{
  u32 height;
  long value;
  u32 isCoinBase;
  u64 usage;
};

BPF_ARRAY(data_arr, struct coin_data, 1);

BPF_PERF_OUTPUT(addCoin);
BPF_PERF_OUTPUT(spendCoin);

int trace_add_coin(struct pt_regs *ctx) {
  int idx = 0;
  struct coin_data *data = data_arr.lookup(&idx);

  if (data == NULL) return 1;

  bpf_usdt_readarg(1, ctx, &data->height);
  bpf_usdt_readarg(2, ctx, &data->value);
  bpf_usdt_readarg(3, ctx, &data->isCoinBase);
  bpf_usdt_readarg(4, ctx, &data->usage);
  addCoin.perf_submit(ctx, data, sizeof(*data));
  return 0;
}

int trace_spend_coin(struct pt_regs *ctx) {
  int idx = 0;
  struct coin_data *data = data_arr.lookup(&idx);
  if (data == NULL) return 1;
  bpf_usdt_readarg(1, ctx, &data->height);
  bpf_usdt_readarg(2, ctx, &data->value);
  bpf_usdt_readarg(3, ctx, &data->isCoinBase);
  bpf_usdt_readarg(4, ctx, &data->usage);
  addCoin.perf_submit(ctx, data, sizeof(*data));
  return 0;
}
"""


def print_event(event, addCoin):
    print("%-7s %-10d %-15d %-20d" % ("ADD" if addCoin else "SPEND", event.height, event.value, event.isCoinBase))

coins_added = 0
coins_spend = 0

def main(bitcoind_path):
    bitcoind_with_usdts = USDT(path=str(bitcoind_path))
    bitcoind_with_usdts.enable_probe(probe="addCoin", fn_name="trace_add_coin")
    bitcoind_with_usdts.enable_probe(probe="spendCoin", fn_name="trace_spend_coin")
    b = BPF(text=program, usdt_contexts=[bitcoind_with_usdts])


    def handle_addCoin(_, data, size):
        global coins_added
        event = b["addCoin"].event(data)
        coins_added += 1
        print_event(event, True)

    def handle_spendCoin(_, data, size):
        global coins_spend
        event = b["spendCoin"].event(data)
        coins_spend += 1
        print_event(event, False)

    b["addCoin"].open_perf_buffer(handle_addCoin)
    b["spendCoin"].open_perf_buffer(handle_spendCoin)

    print("Logging Add Coin. Ctrl-C to end...")
    print("%-7s %-10s %-15s %-20s" % ("Event", "Height",
                                       "Satoshis", "Coin Base"))
    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\n%d coins added, %d coins spend\n" % (coins_added, coins_spend))
            exit(0)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("USAGE: ", sys.argv[0], "path/to/bitcoind")
        exit(1)

    path = sys.argv[1]
    main(path)
