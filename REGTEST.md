# Local regtest bring-up + trustless LiftV2 deposit (validated)

This documents a from-scratch local regtest run that validates the **trustless
LiftV2 deposit** path end to end across two binaries (engine + node) over real
TCP sockets — the cooperative MuSig2 Lift Path. Validated June 2026.

## What it proves

A node discovers an on-chain `LiftV2` deposit (taproot `MuSig2(account,engine)`
key path + account-only CSV sweep) and lifts it into the rollup *without custody*:
the engine cannot spend the deposit alone — the two-round cosign
(register+nonce-commit, then fetch-engine-material + submit-partial-sig) runs over
the socket transport, the engine aggregates the **64-byte key-path signature**, and
the batch tx spends the deposit into the engine payload. Both sides then sync the
batch from chain and the node's rollup balance reflects the lifted deposit.

## Prerequisites

`bitcoind`/`bitcoin-cli` on PATH; the `cube` binary built (`cargo build --bin cube`).

## 1. Regtest bitcoind

```bash
mkdir -p ~/cube-regtest-data
cat > ~/cube-regtest-data/bitcoin.conf <<'EOF'
regtest=1
server=1
txindex=1
fallbackfee=0.0002
[regtest]
rpcuser=user
rpcpassword=password
rpcport=18443
EOF
bitcoind -datadir=$HOME/cube-regtest-data -daemon
B="bitcoin-cli -datadir=$HOME/cube-regtest-data"
$B -named createwallet wallet_name=main
MINE=$($B getnewaddress); echo "$MINE" > ~/cube-regtest-data/mine_addr.txt
$B generatetoaddress 110 "$MINE"     # clear IBD, get spendable coins
```

## 2. Engine identity + genesis payload

```bash
./target/debug/cube genesis regtest   # prints engine secret/nsec, engine pubkey, genesis_payload_address
```

Fund the printed `genesis_payload_address` with the baked genesis amount
(`REGTEST_GENESIS_PAYLOAD_AMOUNT`, default 1_000_000 sats = 0.01 BTC), mine it, and
note the txid/vout:

```bash
$B -named sendtoaddress address=<genesis_payload_address> amount=0.01 fee_rate=2
$B generatetoaddress 1 "$MINE"        # genesis tx now at some height H
```

## 3. Bake the regtest constants (`src/inscriptive/baked.rs`)

For a **fresh** regtest chain, regenerate these (they are chain-specific):

- `REGTEST_ENGINE_PUBLIC_KEY` — the engine pubkey hex from step 2 (32-byte x-only).
- `REGTEST_GENESIS_PAYLOAD_TX_ID` — the funding txid, **reversed to internal byte
  order** (rust-bitcoin `Txid::from_byte_array`); i.e. `bytes.fromhex(displayed)[::-1]`.
- `REGTEST_GENESIS_PAYLOAD_VOUT` — the vout paying the genesis address.
- `REGTEST_GENESIS_PAYLOAD_AMOUNT` — the sats sent (1_000_000).
- `REGTEST_SYNC_START_HEIGHT` — the genesis tx height `H`.

Then `cargo build --bin cube`.

> Sync note: the syncer targets `tip - BLOCK_DEPTH_FOR_FINALITY` (=1) and only
> marks "synced" (opening the port) once caught up with no newer block. Mine the
> chain a dozen+ blocks past `H` before starting the engine so it converges.

## 4. Run the engine (archival — the batch builder requires it)

```bash
cd ~/cube
./target/debug/cube archival regtest engine http://127.0.0.1:18443 user password false
# paste the engine nsec from step 2 at "Enter nsec:"
# -> "Syncing complete." / "Opened port '6272'." / "BATCH BUILDER SESSION BEGINNING: height #1"
```

## 5. Run the node (separate working dir — sled locks `storage/regtest`)

```bash
mkdir -p ~/cube-rgnode && cd ~/cube-rgnode
export CUBE_ENGINE_ADDR=127.0.0.1        # bypass NNS/nostr; connect to local engine:6272
~/cube/target/debug/cube gensec          # generate a node nsec
~/cube/target/debug/cube pruned regtest node http://127.0.0.1:18443 user password false
# paste the node nsec
```

## 6. Deposit + lift

```bash
# in the node CLI:
liftaddr        # prints the liftv2 address
# fund it on regtest, then mine past finality depth:
$B -named sendtoaddress address=<liftv2_address> amount=0.005 fee_rate=2
$B generatetoaddress 3 "$MINE"
# in the node CLI:
lifts           # shows the v2_interactive deposit
liftup          # runs register -> fetch material -> partial-sign -> submit
# -> "Cosign submitted for deposit <txid>:<vout>."
```

The engine builds + broadcasts the batch (advances height). Mine it, then a couple
more blocks; the node logs "Executed batch during on-chain sync" and `coins`
reflects the lifted balance.

## Observed result (this run)

- Engine + node as separate processes; `ping` = 0 ms over the real socket.
- V2 deposit `e3afd7f4…:1` (500_000 sats) to the node's liftv2 address.
- `liftup` → node: `Cosign submitted for deposit e3afd7f4…:1.`
- Batch tx `68adc680…` mined: `in[0]` = genesis payload (script-path, 4 witness
  items), **`in[1]` = the V2 deposit with a single 64-byte key-path witness** (the
  account+engine MuSig2 cosignature), `out[0]` = 1_499_462 sats new payload
  (1_000_000 genesis + 500_000 deposit − 538 fee).
- Node after sync: `coins` = **499_940** sats; log: `Executed batch during on-chain
  sync. Batch height: #1`.

This is the trustless Lift Path proven live; the account-only CSV Exit Path is
proven on a real regtest broadcast in `tests/liftv2_regtest_sweep.rs`.
