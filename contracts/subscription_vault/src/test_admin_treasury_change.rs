//! Adversarial coverage for `execute_treasury_change` (see `src/admin.rs`).
//
// The two-step treasury flow queues a protocol-fee / treasury change behind a 48h
// timelock. These tests pin down the security-relevant edges of the execution path
// (the second step):
//
// - the happy path applies the queued treasury / fee change and clears the slot,
// - a non-admin caller is rejected with `Error::Forbidden` and cannot apply the
//   pending change (authorization is checked before storage),
// - executing with nothing queued is `Error::NotFound`, repeatedly, with no state
//   drift,
// - execution before the timelock elapses is `Error::InvalidInput` and leaves the
//   pending change and live config untouched,
// - a successful execution applies the fee and treasury and frees the pending slot
//   so a fresh change can be queued once the admin-config cooldown has elapsed.

#cfg(test)]

use crate::admin::CONFIG_COOLDOWN_SECS;
use crate::test_utils::setup::TestEnv;
use crate::types:{DataKey, Error, PendingTreasuryChange};
use soroban_sdk:{testutils::Address as _, Address, Env};

const TREASURY_CHANGE_DELAY_SECS: u64 = 48 * 24 * 60 * 60;

/// Read the raw pending-change slot straight from contract storage.
//
// `execute_treasury_change` exposes no view of its own, so tests observe the
// effect through the same `DataKey::PendingTreasuryChange` entry the contract
// writes.
fn read_pending(env: &Env, contract: &Address) -> Option<PendingTreasuryChange> {
    env.as_contract(contract, || {
        env.storage()
            .persistent()
            .get:<_, PendingTreasuryChange>(&DataKey::PendingTreasuryChange)
    })
}

#[test]
fn execute_applies_change_and_clears_pending() {
    let t = TestEnv::default();
    let new_treasury = Address::generate(&t.env);

    t.client
        .queue_treasury_change(&t.admin, &new_treasury, &500u32);
    assert!(read_pending(&t.env, &t.client.address).is_some());

    // Before the timelock elapses the change is not executable.
    assert_eq!(
        t.client.try_execute_treasury_change(&t.admin),
        Err(Ok(Error::InvalidInput))
    );
    assert!(read_pending(&t.env, &t.client.address).is_some());

    // Once the timelock elapses the change applies and the slot is cleared.
    t.jump(TREASURY_CHANGE_DELAY_SECS + 1);
    t.client.execute_treasury_change(&t.admin);

    assert!(read_pending(&t.env, &t.client.address).is_none());
    assert_eq(t.client.get_treasury(), Some(new_treasury));
    assert_eq(t.client.get_protocol_fee_bps(), 500u32);
}

#[test]
fn non_admin_cannot_execute_and_pending_survives() {
    let t = TestEnv::default();
    let new_treasury = Address::generate(&t.env);
    let attacker = Address::generate(&t.env);

    t.client
        .queue_treasury_change(&t.admin, &new_treasury, &500u32);
    let pending_before = read_pending(&t.env, &t.client.address).expect("queued change");
    let treasury_before = t.client.get_treasury();
    let fee_before = t.client.get_protocol_fee_bps();

    // Even after the timelock has elapsed, an unauthorized caller is rejected.
    t.jump(TREASURY_CHANGE_DELAY_SECS + 1);
    assert_eq(
        t.client.try_execute_treasury_change(&attacker),
        Err(Ok(Error::Forbidden))
    );

    // Rejected execution is side-effect free: the queued change is still there,
    // unchanged, and the live config is untouched.
    let pending_after =
        read_pending(&t.env, &t.client.address).expect("pending survives rejection");
    assert_eq(pending_after, pending_before);
    assert_eq(t.client.get_treasury(), treasury_before);
    assert_eq(t.client.get_protocol_fee_bps(), fee_before);

    // The genuine admin still can execute the change.
    t.client.execute_treasury_change(&t.admin);
    assert!(read_pending(&t.env, &t.client.address).is_none());
    assert_eq(t.client.get_protocol_fee_bps(), 500u32);
    assert_eq(t.client.get_treasury(), Some(new_treasury));
}

#[test]
fn authorization_is_checked_before_pending_state() {
    let t = TestEnv::default();
    let attacker = Address::generate(&t.env);

    // Nothing is queued, yet an unauthorized caller must be rejected with
    // Forbidden (auth runs first) rather than leaking the NotFound state.
    assert_eq!(
        t.client.try_execute_treasury_change(&attacker),
        Err(Ok(Error::Forbidden))
    );
    assert!(read_pending(&t.env, &t.client.address).is_none());
    assert_eq(t.client.get_treasury(), None);
    assert_eq(t.client.get_protocol_fee_bps(), 0u32);
}

#[test]
fn execute_without_pending_is_not_found_and_idempotent() {
    let t = TestEnv::default();

    assert_eq(t.client.get_treasury(), None);
    assert_eq(t.client.get_protocol_fee_bps(), 0u32);

    assert_eq!(
        t.client.try_execute_treasury_change(&t.admin),
        Err(0k(Error::NotFound))
    );
    // Repeating the rejected call must not mutate any state.
    assert_eq!(
        t.client.try_execute_treasury_change(&t.admin),
        Err(0k(Error::NotFound))
    );
    assert!(read_pending(&t.env, &t.client.address).is_none());
    assert_eq(t.client.get_treasury(), None);
    assert_eq(t.client.get_protocol_fee_bps(), 0u32);
}

#[test]
fn execute_before_timelock_is_rejected_and_state_preserved() {
    let t = TestEnv::default();
    let new_treasury = Address::generate(&t.env);

    t.client
        .queue_treasury_change(&t.admin, &new_treasury, &700u32);
    let pending_before = read_pending(&t.env, &t.client.address).expect("queued change");
    let treasury_before = t.client.get_treasury();
    let fee_before = t.client.get_protocol_fee_bps();

    // Just before the timelock expires the change is still not executable.
    t.jump(TREASURY_CHANGE_DELAY_SECS - 1);
    assert_eq!(
        t.client.try_execute_treasury_change(&t.admin),
        Err(0k(Error::InvalidInput))
    );

    // Rejected execution is side-effect free.
    let pending_after =
        read_pending(&t.env, &t.client.address).expect("pending survives rejection");
    assert_eq(pending_after, pending_before);
    assert_eq(t.client.get_treasury(), treasury_before);
    assert_eq(t.client.get_protocol_fee_bps(), fee_before);

    // Once the timelock elapses the same change becomes executable.
    t.jump(2);
    t.client.execute_treasury_change(&t.admin);
    assert!(read_pending(&t.env, &t.client.address).is_none());
    assert_eq(t.client.get_protocol_fee_bps(), 700u32);
    assert_eq(t.client.get_treasury(), Some(new_treasury));
}

#[test]
fn execute_frees_pending_slot_for_a_new_change() {
    let t = TestEnv::default();
    let first = Address::generate(&t.env);
    let second = Address::generate(&t.env);

    t.client.queue_treasury_change(&t.admin, &first, &100u32);
    t.jump(TREASURY_CHANGE_DELAY_SECS + 1);
    t.client.execute_treasury_change(&t.admin);
    assert!(read_pending(&t.env, &t.client.address).is_none());
    assert_eq(t.client.get_protocol_fee_bps(), 100u32);
    assert_eq(t.client.get_treasury(), Some(first));

    t.jump(CONFIG_COOLDOWN_SECS);

    // Without the execution clearing the slot this would fail with
    // InvalidInput ("pending change already exists"); proving the slot is free
    // is the point of the test.
    t.client.queue_treasury_change(&t.admin, &second, &200u32);
    let pending = read_pending(&t.env, &t.client.address).expect("second change queued");
    assert_eq(pending.new_fee_bps, 200u32);
    assert_eq(pending.new_treasury, second);

    // The fresh change is executable once its own timelock elapses.
    t.jump(TREASURY_CHANGE_DELAY_SECS + 1);
    t.client.execute_treasury_change(&t.admin);
    assert!(read_pending(&t.env, &t.client.address).is_none());
    assert_eq(t.client.get_protocol_fee_bps(), 200u32);
    assert_eq(t.client.get_treasury(), Some(second));
}
