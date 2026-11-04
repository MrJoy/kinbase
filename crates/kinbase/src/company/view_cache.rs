//! One reduced Company view shared by every read, rebuilt only when its inputs
//! change.
//!
//! `/snapshot`, `/facts` and `/facts/<id>` each re-reduced the whole fact log
//! on every request. At ~12k facts in one deployment one snapshot cost ~300 MiB
//! and 40-60 s of service time; a client that gave up at its read budget did not
//! cancel that work, nothing capped how many ran at once, and a handful of
//! overlapping refreshes plus an ingest paging `/facts` ran the service out of
//! memory.
//!
//! The reduction is a pure function of the admitted event log, the trust state
//! and `as_of` (architecture §6). The log is append-only (its rows are
//! immutable and every write appends), so the service cursor plus a digest of
//! the trust state names the first two exactly. `as_of` reaches the reducer
//! only through step 4 -- an event not yet effective, or past its declared
//! validity -- so a view reduced at one instant is the view at any other
//! instant no event's `effective_from` or expiry falls between. Readers inside
//! that window share the cached reduction; a reader outside it, or at a newer
//! cursor, rebuilds. Rebuilds are serialized: concurrent readers that miss wait
//! for the one rebuild in flight instead of each starting their own, while
//! readers that hit never wait. Two reductions are kept, and the one that holds
//! at the service's own clock is never the one evicted, so a reader asking for
//! a historical `as_of` cannot push `/snapshot` into the rebuild queue.

use super::db::CompanyDb;
use super::trust::TrustState;
use crate::error::ContractError;
use crate::reducer::CurrentView;
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};

/// What a reduction was computed from, apart from `as_of`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ViewKey {
    cursor: i64,
    trust_digest: String,
}

impl ViewKey {
    fn of(trust_state: &TrustState) -> Self {
        // The registry table is updated in place when an authority is revoked,
        // so the cursor alone does not name the trust a reduction used.
        let trust = json!({
            "steward_keys": trust_state.steward_keys,
            "revocations": trust_state.revocations,
            "scope_revocations": trust_state.scope_revocations,
            "registry": trust_state.registry,
            "authority_cursor": trust_state.authority_cursor,
        });
        Self {
            cursor: trust_state.cursor,
            trust_digest: crate::hash::sha256_bytes(&crate::json::canonical_bytes(&trust)),
        }
    }
}

/// A reduction and the log-derived indexes the read endpoints build beside it.
pub struct CompanyView {
    key: ViewKey,
    /// The `as_of` the view was reduced at. `view.as_of` carries it too; it is
    /// the reduction instant, and the view is identical for every `as_of` in
    /// this entry's window, so readers use their own `as_of`, never this one.
    reduced_at: String,
    /// Every `effective_from` and expiry instant in the admitted log, sorted.
    boundaries: Vec<String>,
    pub view: CurrentView,
    /// The fields `/facts` publishes for a non-current event, by event id.
    /// Only these: the whole parsed log held resident would cost more than the
    /// per-request copies this cache exists to remove.
    pub payloads: BTreeMap<String, Value>,
    /// Lifecycle admissions derived from the log, before any reader's scope
    /// filter; audited refusals are read per request.
    pub lifecycle_rows: Vec<Value>,
    /// Snapshot content digests already computed against this reduction, by
    /// what else the content depends on (scopes, repository, side tables).
    /// Dropped with the entry, so a digest never outlives its inputs.
    content_digests: Mutex<DigestMemo>,
    /// Every fact and unknown event by cursor, newest first: what a snapshot's
    /// event window is chosen from. Only the rows a window sends are loaded.
    pub event_index: Vec<EventRef>,
    /// Parent bindings of each current fact that has parents, resolved to the
    /// parents' logical keys, in the reduction's fact order.
    pub fact_parents: BTreeMap<String, Value>,
}

/// Where an admitted event sits in the log, without its document.
pub struct EventRef {
    pub cursor: i64,
    pub kind: &'static str,
    pub authority_scope: String,
}

impl CompanyView {
    /// The snapshot content digest recorded for `key` against this reduction.
    pub fn content_digest(&self, key: &str) -> Option<String> {
        lock(&self.content_digests).digests.get(key).cloned()
    }

    /// Clients choose part of the key (`repository`, `events_since`), so the
    /// memo is capped: past the cap a new key replaces the oldest one held,
    /// never whichever sorts first, so a flood of keys cannot keep evicting
    /// real ones that happen to sort early.
    pub fn remember_content_digest(&self, key: String, digest: String) {
        let mut memo = lock(&self.content_digests);
        if !memo.digests.contains_key(&key) {
            if memo.digests.len() >= MAX_CONTENT_DIGESTS
                && let Some(oldest) = memo.order.pop_front()
            {
                memo.digests.remove(&oldest);
            }
            memo.order.push_back(key.clone());
        }
        memo.digests.insert(key, digest);
    }

    /// Whether this reduction is the reduction at `as_of`: no boundary lies in
    /// the half-open interval between the two instants, in either direction.
    fn holds_at(&self, as_of: &str) -> bool {
        let (low, high) = if as_of < self.reduced_at.as_str() {
            (as_of, self.reduced_at.as_str())
        } else {
            (self.reduced_at.as_str(), as_of)
        };
        let first_after_low = self
            .boundaries
            .partition_point(|boundary| boundary.as_str() <= low);
        self.boundaries
            .get(first_after_low)
            .is_none_or(|boundary| boundary.as_str() > high)
    }
}

/// Content digests in the order they were first remembered.
#[derive(Default)]
struct DigestMemo {
    digests: BTreeMap<String, String>,
    order: VecDeque<String>,
}

/// Content digests remembered per reduction: one per scope set, repository and
/// `events_since` a client asked for, which is a few dozen for a whole estate.
const MAX_CONTENT_DIGESTS: usize = 256;

/// What `/facts` reads from a non-current event's payload.
const PUBLISHED_EVENT_FIELDS: [&str; 8] = [
    "fact_id",
    "statement",
    "disposition",
    "atom_kind",
    "authority_id",
    "authority_scope",
    "asserted_at",
    "effective_until",
];

/// Reductions kept at once: the one at the service's clock, and one for a
/// reader asking about another instant.
const SLOTS: usize = 2;

#[derive(Default)]
pub struct ViewCache {
    entries: Mutex<Vec<Arc<CompanyView>>>,
    rebuild: Mutex<()>,
}

impl ViewCache {
    /// The Company view at `as_of` for this trust state, reduced at most once
    /// per change of its inputs. `now` is the service's clock, which decides
    /// what to keep when a reader asks about another instant.
    pub fn read(
        &self,
        db: &CompanyDb,
        trust_state: &TrustState,
        as_of: &str,
        now: &str,
    ) -> Result<Arc<CompanyView>, ContractError> {
        let key = ViewKey::of(trust_state);
        if let Some(hit) = self.lookup(&key, as_of) {
            return Ok(hit);
        }
        let _turn = lock(&self.rebuild);
        // Another reader may have rebuilt it while this one waited its turn.
        if let Some(hit) = self.lookup(&key, as_of) {
            return Ok(hit);
        }
        let built = Arc::new(build(db, trust_state, key, as_of)?);
        self.remember(Arc::clone(&built), now);
        Ok(built)
    }

    fn lookup(&self, key: &ViewKey, as_of: &str) -> Option<Arc<CompanyView>> {
        lock(&self.entries)
            .iter()
            .find(|entry| entry.key == *key && entry.holds_at(as_of))
            .map(Arc::clone)
    }

    fn remember(&self, built: Arc<CompanyView>, now: &str) {
        let mut entries = lock(&self.entries);
        // A reduction of an older log or trust state is never read again.
        entries.retain(|entry| entry.key == built.key);
        if entries.len() >= SLOTS {
            let victim = entries
                .iter()
                .position(|entry| !entry.holds_at(now))
                .unwrap_or(0);
            entries.remove(victim);
        }
        entries.push(built);
    }
}

/// A panic while holding either lock leaves nothing half-written: the entry is
/// replaced whole, and the rebuild lock guards no data. Keep serving.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn build(
    db: &CompanyDb,
    trust_state: &TrustState,
    key: ViewKey,
    as_of: &str,
) -> Result<CompanyView, ContractError> {
    let input = super::reduction::company_reducer_input(db, trust_state, as_of)?;
    let mut boundaries: Vec<String> = input
        .events
        .iter()
        .flat_map(|admitted| {
            [
                Some(admitted.event.effective_from.clone()),
                crate::reducer::expiry_of(&admitted.event),
            ]
        })
        .flatten()
        .collect();
    boundaries.sort();
    boundaries.dedup();
    let view = crate::reducer::reduce(&input);
    // The parsed log is the largest thing a rebuild holds; release it before
    // the passes below parse the log again.
    drop(input);
    let mut payloads = BTreeMap::new();
    let mut event_index = Vec::new();
    let mut parents_of: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
    for (cursor, payload, _) in db.events_of_kind("fact-event")? {
        event_index.push(EventRef {
            cursor,
            kind: "fact-event",
            authority_scope: crate::json::get_str(&payload, "authority_scope")
                .unwrap_or_default()
                .to_owned(),
        });
        let event_id = crate::json::get_str(&payload, "event_id").unwrap_or_default();
        parents_of.insert(
            event_id.to_owned(),
            (
                crate::json::get_str(&payload, "logical_key")
                    .unwrap_or_default()
                    .to_owned(),
                crate::json::get_array(&payload, "parents")
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
            ),
        );
        if crate::json::get_str(&payload, "event_id").is_none() {
            continue;
        }
        let published: serde_json::Map<String, Value> = PUBLISHED_EVENT_FIELDS
            .iter()
            .filter_map(|field| {
                payload
                    .get(*field)
                    .map(|value| ((*field).to_owned(), value.clone()))
            })
            .collect();
        payloads.insert(event_id.to_owned(), Value::Object(published));
    }
    for (cursor, payload, _) in db.events_of_kind("unknown-event")? {
        event_index.push(EventRef {
            cursor,
            kind: "unknown-event",
            authority_scope: crate::json::get_str(&payload, "authority_scope")
                .unwrap_or_default()
                .to_owned(),
        });
    }
    event_index.sort_by(|left, right| right.cursor.cmp(&left.cursor));
    let mut fact_parents = BTreeMap::new();
    for fact in &view.facts {
        let Some((_, parents)) = parents_of.get(&fact.event_id) else {
            continue;
        };
        if parents.is_empty() {
            continue;
        }
        let resolved: Vec<Value> = parents
            .iter()
            .map(|parent| {
                json!({
                    "event_id": parent,
                    "logical_key": parents_of.get(parent).map(|(key, _)| key.clone()).unwrap_or_default()
                })
            })
            .collect();
        fact_parents.insert(fact.fact_id.clone(), Value::Array(resolved));
    }
    drop(parents_of);
    let lifecycle_rows = super::reduction::lifecycle_event_rows(db, trust_state);
    Ok(CompanyView {
        key,
        reduced_at: as_of.to_owned(),
        boundaries,
        view,
        payloads,
        lifecycle_rows,
        content_digests: Mutex::default(),
        event_index,
        fact_parents,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(reduced_at: &str, boundaries: &[&str]) -> CompanyView {
        CompanyView {
            key: ViewKey {
                cursor: 1,
                trust_digest: String::new(),
            },
            reduced_at: reduced_at.to_owned(),
            boundaries: boundaries.iter().map(|b| (*b).to_owned()).collect(),
            view: crate::reducer::reduce(&crate::reducer::ReducerInput {
                store_kind: "company".to_owned(),
                events: Vec::new(),
                unknowns: Vec::new(),
                tombstones: Vec::new(),
                revocations: Vec::new(),
                as_of: reduced_at.to_owned(),
                authority_cursor: "1".to_owned(),
                revocation_fresh: true,
                fact_valid_until: None,
                certificate_valid: true,
                authority_owner_by_scope: BTreeMap::new(),
                steward_authority_id: None,
            }),
            payloads: BTreeMap::new(),
            lifecycle_rows: Vec::new(),
            content_digests: Mutex::default(),
            event_index: Vec::new(),
            fact_parents: BTreeMap::new(),
        }
    }

    const T0: &str = "2026-10-19T10:00:00.000Z";
    const T1: &str = "2026-10-19T11:00:00.000Z";
    const T2: &str = "2026-10-19T12:00:00.000Z";
    const T3: &str = "2026-10-19T13:00:00.000Z";

    #[test]
    fn a_view_holds_until_an_event_becomes_effective_or_expires() {
        let cached = entry(T1, &[T0, T2]);
        // Same window either side of the reduction instant.
        assert!(cached.holds_at(T1));
        assert!(cached.holds_at("2026-10-19T11:59:59.999Z"));
        assert!(cached.holds_at(T0));
        // Reaching a boundary flips `effective_from > as_of` and
        // `until <= as_of`: the reduction at T2 differs from the one at T1.
        assert!(!cached.holds_at(T2));
        assert!(!cached.holds_at(T3));
        // Earlier than T0 crosses T0 going back.
        assert!(!cached.holds_at("2026-10-19T09:59:59.999Z"));
        // A log with no boundaries holds at every instant.
        assert!(entry(T1, &[]).holds_at(T3));
    }

    #[test]
    fn client_chosen_memo_keys_are_capped_oldest_first() {
        let cached = entry(T1, &[]);
        // The first key remembered sorts last; the keys after it sort first.
        cached.remember_content_digest("zz-oldest".to_owned(), "oldest".to_owned());
        for index in 0..MAX_CONTENT_DIGESTS {
            cached.remember_content_digest(format!("key-{index:04}"), format!("digest-{index}"));
        }
        assert_eq!(
            lock(&cached.content_digests).digests.len(),
            MAX_CONTENT_DIGESTS
        );
        // The oldest went, not the key that sorts first.
        assert_eq!(cached.content_digest("zz-oldest"), None);
        assert_eq!(
            cached.content_digest("key-0000"),
            Some("digest-0".to_owned())
        );
        // Re-recording a held key never evicts another.
        cached.remember_content_digest("key-0000".to_owned(), "again".to_owned());
        assert_eq!(
            lock(&cached.content_digests).digests.len(),
            MAX_CONTENT_DIGESTS
        );
        assert_eq!(
            cached.content_digest("key-0001"),
            Some("digest-1".to_owned())
        );
    }

    #[test]
    fn a_historical_reader_never_evicts_the_reduction_at_the_clock() {
        let cache = ViewCache::default();
        let key = entry(T1, &[]).key;
        // The service's clock is T1; the live reduction holds between T0 and T2.
        let live = Arc::new(entry(T1, &[T0, T2]));
        cache.remember(Arc::clone(&live), T1);
        // Readers asking about other instants come and go.
        for instant in [T3, "2026-10-19T09:00:00.000Z", T3] {
            cache.remember(Arc::new(entry(instant, &[T0, T2])), T1);
            let hit = cache.lookup(&key, T1).expect("the live reduction is kept");
            assert!(Arc::ptr_eq(&hit, &live));
        }
        assert_eq!(lock(&cache.entries).len(), SLOTS);
        // A newer log replaces everything built from the old one.
        let mut newer = entry(T1, &[]);
        newer.key.cursor = 2;
        cache.remember(Arc::new(newer), T1);
        assert_eq!(lock(&cache.entries).len(), 1);
        assert!(cache.lookup(&key, T1).is_none());
    }
}
