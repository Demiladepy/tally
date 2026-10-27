# Joining a Tally clearing committee

Thank you for helping. A Tally committee is 3 people. Any 2 of them together can open the few aggregate totals that clearing needs, and no single person can open anything. You hold one of the 3 key shares on **your own machine**. Your share never leaves it.

You'll spend about 15 minutes at setup and a few minutes when the auction closes. Everything you exchange with the coordinator is a small file. You never send a secret.

## 0. Install (once)

You need Rust 1.85 or newer ([rustup.rs](https://rustup.rs)).

```bash
cargo install --git https://github.com/Demiladepy/tally tally-committee
```

Keep everything in one folder, for example `tally-member/`, and run every command from there.

## 1. Your transport key (once)

```bash
tally-committee keygen --identity me.age
```

This prints a line starting with `age1…`. **Send that line to the coordinator.** It's public: other members use it to encrypt your share to you. `me.age` is private; keep it.

## 2. Key ceremony (once)

The coordinator sends back the 3 `age1…` lines in order, and tells you your member number `J` (1, 2 or 3).

```bash
tally-committee deal --j J --n 3 --t 2 --recipients age1AAA,age1BBB,age1CCC --out dealing-J.json
```

**Send `dealing-J.json` to the coordinator.** It contains only encrypted shares and public commitments. When you've received all three dealings:

```bash
tally-committee finish --j J --identity me.age --dealings dealing-1.json,dealing-2.json,dealing-3.json \
  --names "Your name or handle,Member 2,Member 3" --secret me.secret --public committee.json
```

This checks every dealing. If someone cheated, it names them and stops. `me.secret` is your key share: **never send it anywhere.** `committee.json` is public, and all three members end up with the identical file. Compare its hash with the others over a channel you trust:

```bash
sha256sum committee.json
```

## 3. Co-sign an offering (each auction)

The seller sends a `draft.json`. Check it against **your own** `committee.json`, then endorse it:

```bash
tally-committee endorse --j J --secret me.secret --committee committee.json --manifest draft.json --out endorse-J.json
```

It refuses if the draft names a different committee or fails any check, and it prints the offering's ID, size and escrow. Only endorse terms you've read. **Send `endorse-J.json` to the seller.**

## 4. At close (each auction)

The coordinator gives you the desk URL `URL/v1/auctions/ID` and the escrow's `bonds.json`. That file holds only order hashes and amounts. If it ever contains addresses, the tool refuses it.

```bash
tally-committee attest --j J --secret me.secret --log URL/v1/auctions/ID --bonds bonds.json --out sig-J.json
```

Send `sig-J.json`. Then, for each aggregate the clearing asks for (the coordinator tells you the target, for example `T_9`):

```bash
tally-committee share --j J --secret me.secret --log URL/v1/auctions/ID --target T_9 --out share-J-T_9.json
```

The desk refuses any target the binary search doesn't need, so you can't be tricked into opening an individual order. Anyone can check the result:

```bash
tally-committee verify --log URL/v1/auctions/ID
```

## What you can and can't see

- You **can't** see any bid, alone or with one other member. Only aggregate yes-counts at a few price levels are ever opened.
- You **never** receive anyone's address or payment details.
- Keep `me.secret` and `me.age` private, and back them up. If 2 members lose their shares, the auction can't clear, and every deposit is refunded by the escrow.
