# taggr-ethereum-contracts

Solidity contracts for the TAGGR migration to Ethereum L1. Phase 1 is the
immutable ERC20 plus the one-way IC → L1 bridge; the full design lives in the
taggr repository under `docs/ETHEREUM.md`.

Not deployed yet. The token has no proxy, pause, fees, burn or admin escape
hatch — every change is a token migration.

## Pinned toolchain

| Component    | Version                                                 |
| ------------ | ------------------------------------------------------- |
| solc         | 0.8.37                                                   |
| OpenZeppelin | v5.7.0 (`cab19933c33c2ad1d4c7a84864a3601dddfd16f3`)      |
| forge-std    | v1.17.0 (`f3dae6e6ee381f25eb6a246f7da9b85c91a68219`)     |
| forge        | 1.8.5 (built and tested with)                            |
| optimizer    | on, 200 runs                                             |
| EVM version  | cancun                                                   |
| metadata     | ipfs bytecode hash                                       |

All of these are pinned in `foundry.toml`. Changing any of them changes the
deployed bytecode — do not do it after deployment, or the Etherscan source
will no longer match.

## Setup

Install Foundry: `curl -L https://foundry.paradigm.xyz | bash && foundryup`.

Dependencies are git submodules pinned to the versions above (and recorded in
`foundry.lock`):

```bash
git clone --recurse-submodules git@github.com:TaggrNetwork/contracts.git

# or, in an existing clone:
git submodule update --init --recursive
```

## Build and test

```bash
forge build
forge test -vvv
forge lint
forge fmt --check
```

## Deploy and verify on mainnet

```bash
export MAINNET_RPC_URL=...
export ETHERSCAN_API_KEY=...
export TAGGR_MINTER=0x...      # canister EOA: key_1, derivation path b"ethereum"
export TAGGR_CONTROLLER=0x...  # same as minter in phase 1
forge script script/Deploy.s.sol --rpc-url mainnet --broadcast --verify
```

Re-verify later (source plus constructor args):

```bash
forge verify-contract <TOKEN_ADDRESS> src/TaggrToken.sol:TaggrToken \
  --chain 1 \
  --constructor-args "$(cast abi-encode 'constructor(address,address)' 0xMINTER 0xCONTROLLER)"
```

Manual standard-JSON fallback for the Etherscan UI:

```bash
ETHERSCAN_API_KEY=dummy \
  forge verify-contract <TOKEN_ADDRESS> src/TaggrToken.sol:TaggrToken --chain 1 \
  --constructor-args "..." --show-standard-json-input > standard-json-input.json
```

Paste the JSON into Etherscan's "Solidity (Standard-Json-Input)" form; it
contains the token and every OpenZeppelin source plus `settings.remappings`,
and has been checked to compile standalone with solc 0.8.37. Any verify
command needs `ETHERSCAN_API_KEY` set (a dummy value is fine when only
producing the JSON), because `foundry.toml` interpolates it.

### Deployment record

| Item     | Value |
| -------- | ----- |
| Address  | TBD   |
| Tx       | TBD   |
| Deployer | TBD   |
| forge    | TBD   |

## EIP-712 spec (must match the canister implementation)

- Domain: `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)`
  with name `"TAGGR"`, version `"1"`, chainId `1`, verifyingContract = token address.
  The contract uses `block.chainid`, which is `1` on mainnet.
- Mint struct: `Mint(address to,uint256 amount,uint256 index)`.
- Nomination struct: `NominateController(address candidate,uint256 index)`.
- Digest: `keccak256(0x1901 || domainSeparator || keccak256(abi.encode(typehash, ...fields)))`.
  Read it on-chain via `mintDigest(to, amount, index)` /
  `nominateControllerDigest(candidate, index)`.
- Signatures: 65 bytes `r || s || v`, low-s (EIP-2), `v ∈ {27, 28}`. High-s
  and malformed signatures are rejected by OpenZeppelin `ECDSA.recover`.
- Amounts: 1 IC base unit = `1e16` wei (18 decimals); `MAX_SUPPLY = 1e24` wei.
- Recipe indices are one global, monotonically increasing sequence assigned by
  the canister; failed signings consume an index, so gaps are legal and reuse
  is rejected. Mint and nomination recipes share the index space and bitmask.
- Role holders are read at execution time: rotating the minter invalidates all
  pending mint recipes (same for the controller).

## Interface notes

- `controller` is the root role: `setMinter`, `nominateController`. Handover is
  two-step (`acceptController` must come from the nominee; a contract nominee
  calls through its own code, like the phase-2 stake contract will).
- `minter` signs mint recipes. In phase 1 the minter and controller are the
  canister EOA, which cannot send transactions, so every action flows through
  relayed, EIP-712-signed recipes.
- `nominateControllerWithAuthorization` is reserved for handing the controller
  role to L1 in phase 2; no other role-change signing exists in phase 1.
- Invalid signatures never consume a recipe index: the index is marked used
  only after signature, role and supply-cap checks pass.
- A pending controller nomination is harmless: the current controller can
  always replace it.

## License

GPL-3.0-only (see `LICENSE`); the OpenZeppelin sources under `lib/` are MIT.
