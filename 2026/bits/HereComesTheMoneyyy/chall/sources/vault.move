module challenge::vault {
    use sui::object::{Self, UID, ID};
    use sui::tx_context::{TxContext};
    use sui::coin::{Self, Coin};
    use sui::balance::{Self, Balance};
    use sui::sui::SUI;
    use sui::event;
    use sui::clock::{Self, Clock};

    const E_INSUFFICIENT_BALANCE: u64 = 1;
    const E_INVALID_REQUEST: u64 = 2;
    const E_NOT_OWNER: u64 = 4;
    const E_VAULT_LOCKED: u64 = 5;
    const E_INVALID_AMOUNT: u64 = 6;
    const E_REQUEST_EXPIRED: u64 = 8;
    const E_MERGE_LIMIT: u64 = 10;

    const INITIAL_VAULT_BALANCE: u64 = 10_000_000_000;
    const WIN_THRESHOLD: u64 = 9_000_000_000;
    const REQUEST_VALIDITY_MS: u64 = 600000;
    const FLASH_FEE_BPS: u64 = 9;

    public struct Vault has key {
        id: UID,
        reserves: Balance<SUI>,
        total_shares: u64,
        is_paused: bool
    }

    public struct UserAccount has key, store {
        id: UID,
        owner: address,
        shares: u64,
        cumulative_deposited: u64,
        active_ticket_value: u64
    }

    public struct WithdrawTicket has store, drop {
        amount: u64,
        owner: address,
        vault_id: ID,
        timestamp_ms: u64,
        merge_count: u8
    }

    public struct FlashLoanReceipt has store, drop {
        amount: u64,
        fee: u64,
        vault_id: ID
    }

    public struct Exploited has copy, drop {
        attacker: address,
        amount: u64
    }

    fun init(ctx: &mut TxContext) {
        let vault = Vault {
            id: object::new(ctx),
            reserves: balance::zero(),
            total_shares: 0,
            is_paused: false
        };
        transfer::share_object(vault);
    }

    #[test_only]
    public fun init_for_testing(ctx: &mut TxContext) {
        init(ctx);
    }

    public fun seed(vault: &mut Vault, coins: Coin<SUI>) {
        let amt = coin::value(&coins);
        balance::join(&mut vault.reserves, coin::into_balance(coins));
        vault.total_shares = vault.total_shares + amt;
    }

    public fun create_account(ctx: &mut TxContext): UserAccount {
        UserAccount {
            id: object::new(ctx),
            owner: tx_context::sender(ctx),
            shares: 0,
            cumulative_deposited: 0,
            active_ticket_value: 0
        }
    }

    public fun deposit(
        vault: &mut Vault,
        account: &mut UserAccount,
        coins: Coin<SUI>,
        ctx: &mut TxContext
    ) {
        assert!(!vault.is_paused, E_VAULT_LOCKED);
        assert!(tx_context::sender(ctx) == account.owner, E_NOT_OWNER);
        
        let amount = coin::value(&coins);
        let reserves = balance::value(&vault.reserves);
        
        let new_shares = if (vault.total_shares == 0 || reserves == 0) {
            amount
        } else {
            (((amount as u128) * (vault.total_shares as u128)) / (reserves as u128)) as u64
        };
        
        balance::join(&mut vault.reserves, coin::into_balance(coins));
        vault.total_shares = vault.total_shares + new_shares;
        account.shares = account.shares + new_shares;
        account.cumulative_deposited = account.cumulative_deposited + amount;
    }

    public fun create_ticket(
        vault: &Vault,
        account: &mut UserAccount,
        amount: u64,
        clock: &Clock,
        ctx: &mut TxContext
    ): WithdrawTicket {
        assert!(!vault.is_paused, E_VAULT_LOCKED);
        assert!(tx_context::sender(ctx) == account.owner, E_NOT_OWNER);
        assert!(amount <= account.shares, E_INSUFFICIENT_BALANCE);
        
        account.shares = account.shares - amount;
        account.active_ticket_value = account.active_ticket_value + amount;
        
        WithdrawTicket {
            amount,
            owner: account.owner,
            vault_id: object::id(vault),
            timestamp_ms: clock::timestamp_ms(clock),
            merge_count: 0
        }
    }

    public fun cancel_ticket(
        account: &mut UserAccount,
        ticket: WithdrawTicket,
        ctx: &mut TxContext
    ) {
        assert!(tx_context::sender(ctx) == ticket.owner, E_NOT_OWNER);
        
        let WithdrawTicket { amount, owner: _, vault_id: _, timestamp_ms: _, merge_count: _ } = ticket;
        
        account.shares = account.shares + amount;
        account.active_ticket_value = account.active_ticket_value - amount;
    }

    public fun split_ticket(
        ticket: WithdrawTicket,
        split_amount: u64,
        clock: &Clock
    ): (WithdrawTicket, WithdrawTicket) {
        let WithdrawTicket { amount, owner, vault_id, timestamp_ms, merge_count } = ticket;
        
        assert!(split_amount > 0 && split_amount < amount, E_INVALID_AMOUNT);
        
        let current = clock::timestamp_ms(clock);
        assert!(current - timestamp_ms <= REQUEST_VALIDITY_MS, E_REQUEST_EXPIRED);
        
        (
            WithdrawTicket {
                amount: split_amount,
                owner,
                vault_id,
                timestamp_ms,
                merge_count
            },
            WithdrawTicket {
                amount: amount - split_amount,
                owner,
                vault_id,
                timestamp_ms,
                merge_count
            }
        )
    }

    public fun merge_tickets(
        t1: WithdrawTicket,
        t2: WithdrawTicket
    ): WithdrawTicket {
        let WithdrawTicket { 
            amount: a1, 
            owner: o1, 
            vault_id: v1, 
            timestamp_ms: ts1, 
            merge_count: m1 
        } = t1;
        
        let WithdrawTicket { 
            amount: a2, 
            owner: o2, 
            vault_id: v2, 
            timestamp_ms: ts2, 
            merge_count: m2 
        } = t2;
        
        assert!(o1 == o2, E_NOT_OWNER);
        assert!(v1 == v2, E_INVALID_REQUEST);
        
        let new_merge = if (m1 > m2) { m1 + 1 } else { m2 + 1 };
        assert!(new_merge <= 10, E_MERGE_LIMIT);
        
        WithdrawTicket {
            amount: a1 + a2,
            owner: o1,
            vault_id: v1,
            timestamp_ms: if (ts1 < ts2) { ts1 } else { ts2 },
            merge_count: new_merge
        }
    }

    public fun boost_ticket(
        vault: &Vault,
        account: &mut UserAccount,
        ticket: WithdrawTicket,
        boost_shares: u64,
        ctx: &mut TxContext
    ): WithdrawTicket {
        assert!(!vault.is_paused, E_VAULT_LOCKED);
        assert!(tx_context::sender(ctx) == ticket.owner, E_NOT_OWNER);
        assert!(tx_context::sender(ctx) == account.owner, E_NOT_OWNER);
        assert!(boost_shares <= account.shares, E_INSUFFICIENT_BALANCE);
        
        let WithdrawTicket { amount, owner, vault_id, timestamp_ms, merge_count } = ticket;
        
        WithdrawTicket {
            amount: amount + boost_shares,
            owner,
            vault_id,
            timestamp_ms,
            merge_count
        }
    }

    public fun finalize_withdraw(
        vault: &mut Vault,
        account: &mut UserAccount,
        ticket: WithdrawTicket,
        clock: &Clock,
        ctx: &mut TxContext
    ): Coin<SUI> {
        assert!(!vault.is_paused, E_VAULT_LOCKED);
        assert!(tx_context::sender(ctx) == ticket.owner, E_NOT_OWNER);
        
        let WithdrawTicket { amount, owner, vault_id, timestamp_ms, merge_count: _ } = ticket;
        
        assert!(vault_id == object::id(vault), E_INVALID_REQUEST);
        assert!(owner == account.owner, E_NOT_OWNER);
        
        let current = clock::timestamp_ms(clock);
        assert!(current - timestamp_ms <= REQUEST_VALIDITY_MS, E_REQUEST_EXPIRED);
        
        let reserves = balance::value(&vault.reserves);
        let payout = if (vault.total_shares == 0) {
            0
        } else {
            (((amount as u128) * (reserves as u128)) / (vault.total_shares as u128)) as u64
        };
        
        assert!(payout <= reserves, E_INSUFFICIENT_BALANCE);
        
        vault.total_shares = vault.total_shares - amount;
        account.active_ticket_value = 0;
        
        coin::from_balance(balance::split(&mut vault.reserves, payout), ctx)
    }

    public fun flash_loan(
        vault: &mut Vault,
        amount: u64,
        ctx: &mut TxContext
    ): (Coin<SUI>, FlashLoanReceipt) {
        assert!(!vault.is_paused, E_VAULT_LOCKED);
        
        let reserves = balance::value(&vault.reserves);
        assert!(amount <= reserves, E_INSUFFICIENT_BALANCE);
        
        let mut fee = (amount * FLASH_FEE_BPS) / 10000;
        if (fee == 0 && amount > 0) { fee = 1; };
        
        let coins = coin::from_balance(balance::split(&mut vault.reserves, amount), ctx);
        
        (coins, FlashLoanReceipt {
            amount,
            fee,
            vault_id: object::id(vault)
        })
    }

    public fun repay_loan(
        vault: &mut Vault,
        coins: Coin<SUI>,
        receipt: FlashLoanReceipt
    ) {
        let FlashLoanReceipt { amount, fee, vault_id } = receipt;
        assert!(vault_id == object::id(vault), E_INVALID_REQUEST);
        assert!(coin::value(&coins) >= amount + fee, E_INSUFFICIENT_BALANCE);
        
        balance::join(&mut vault.reserves, coin::into_balance(coins));
    }

    public fun check_exploit(
        vault: &Vault,
        ctx: &mut TxContext
    ): bool {
        let reserves = balance::value(&vault.reserves);
        let stolen = if (INITIAL_VAULT_BALANCE > reserves) {
            INITIAL_VAULT_BALANCE - reserves
        } else {
            0
        };
        
        if (stolen >= WIN_THRESHOLD) {
            event::emit(Exploited {
                attacker: tx_context::sender(ctx),
                amount: stolen
            });
            true
        } else {
            false
        }
    }

    public fun reserves(vault: &Vault): u64 {
        balance::value(&vault.reserves)
    }

    public fun total_shares(vault: &Vault): u64 {
        vault.total_shares
    }

    public fun user_shares(account: &UserAccount): u64 {
        account.shares
    }
    
    public fun ticket_amount(ticket: &WithdrawTicket): u64 {
        ticket.amount
    }

    public fun destroy_account(account: UserAccount) {
        let UserAccount { id, owner: _, shares: _, cumulative_deposited: _, active_ticket_value: _ } = account;
        object::delete(id);
    }

    public fun destroy_empty_ticket(ticket: WithdrawTicket) {
        let WithdrawTicket { amount, owner: _, vault_id: _, timestamp_ms: _, merge_count: _ } = ticket;
        assert!(amount == 0, E_INVALID_AMOUNT);
    }
}
