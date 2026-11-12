//! Byte-accounted DNS response cache and cancellation-safe single-flight slots.
//!
//! Store wire bytes instead of parsed RData trees so compressed/unusual answers
//! cannot turn a small entry count into an unbounded retained heap.

use std::collections::HashMap;
use std::io;
use std::num::NonZeroUsize;
use std::sync::{Arc, Weak};
use std::time::Duration;

use hickory_resolver::proto::op::{Message, ResponseCode};
use hickory_resolver::proto::rr::RData;
use lru::LruCache;
use parking_lot::Mutex;
use tokio::time::Instant;

pub(super) const CACHE_ENTRIES: usize = 1024;
pub(super) const CACHE_BYTES: usize = 1024 * 1024;
const ENTRY_OVERHEAD: usize = 320;
const MAX_FLIGHTS: usize = 128;

#[derive(Clone)]
pub(super) struct Answer {
    bytes: Arc<[u8]>,
    completed: Instant,
}

impl Answer {
    pub fn new(message: &Message) -> io::Result<Self> {
        Ok(Self {
            bytes: message.to_vec().map_err(io::Error::other)?.into(),
            completed: Instant::now(),
        })
    }

    pub fn message(&self) -> io::Result<Message> {
        let mut message = super::message::decode(&self.bytes)?;
        let elapsed = self.completed.elapsed().as_secs().min(u64::from(u32::MAX)) as u32;
        for record in message
            .answers
            .iter_mut()
            .chain(message.authorities.iter_mut())
            .chain(message.additionals.iter_mut())
        {
            record.ttl = record.ttl.saturating_sub(elapsed);
        }
        Ok(message)
    }
}

pub(super) type FlightResult = Result<Answer, Arc<io::Error>>;
pub(super) type Flight = tokio::sync::Mutex<Option<FlightResult>>;

struct Entry {
    answer: Answer,
    expires: Instant,
    charged: usize,
}

struct State {
    entries: LruCache<Box<[u8]>, Entry>,
    bytes: usize,
    // Weak ownership means cancellation/TTL-zero results cannot remain alive
    // just because no later request happens to revisit their key.
    flights: HashMap<Box<[u8]>, Weak<Flight>>,
}

pub(super) struct ResponseCache {
    state: Mutex<State>,
    max_entries: usize,
    max_bytes: usize,
}

impl Default for ResponseCache {
    fn default() -> Self {
        Self::new(CACHE_ENTRIES, CACHE_BYTES)
    }
}

impl ResponseCache {
    fn new(max_entries: usize, max_bytes: usize) -> Self {
        // Avoid eagerly allocating the entire entry table.
        let mut entries = LruCache::unbounded();
        entries.resize(NonZeroUsize::new(max_entries.max(1)).unwrap());
        Self {
            state: Mutex::new(State {
                entries,
                bytes: 0,
                flights: HashMap::new(),
            }),
            max_entries,
            max_bytes,
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<Answer> {
        let mut state = self.state.lock();
        if let Some(entry) = state.entries.get(key) {
            if Instant::now() < entry.expires {
                return Some(entry.answer.clone());
            }
        }
        if let Some(expired) = state.entries.pop(key) {
            state.bytes -= expired.charged;
        }
        None
    }

    pub fn insert(&self, key: &[u8], answer: Answer, message: &Message) {
        let ttl = cache_ttl(message);
        if ttl == 0 || self.max_entries == 0 {
            return;
        }
        let charged = key
            .len()
            .saturating_add(answer.bytes.len())
            .saturating_add(ENTRY_OVERHEAD);
        if charged > self.max_bytes {
            return;
        }
        let mut state = self.state.lock();
        if let Some(previous) = state.entries.pop(key) {
            state.bytes -= previous.charged;
        }
        while state.entries.len() >= self.max_entries
            || state.bytes.saturating_add(charged) > self.max_bytes
        {
            let Some((_, old)) = state.entries.pop_lru() else {
                break;
            };
            state.bytes -= old.charged;
        }
        state.bytes += charged;
        state.entries.put(
            key.into(),
            Entry {
                expires: answer.completed + Duration::from_secs(u64::from(ttl)),
                answer,
                charged,
            },
        );
    }

    pub fn flight(&self, key: &[u8]) -> io::Result<Arc<Flight>> {
        let mut state = self.state.lock();
        state.flights.retain(|_, slot| slot.strong_count() != 0);
        if let Some(slot) = state.flights.get(key).and_then(Weak::upgrade) {
            return Ok(slot);
        }
        if state.flights.len() >= MAX_FLIGHTS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "DNS query admission exhausted",
            ));
        }
        let slot = Arc::new(tokio::sync::Mutex::new(None));
        state.flights.insert(key.into(), Arc::downgrade(&slot));
        Ok(slot)
    }

    /// Completed requests are shared only with callers already waiting on that
    /// generation. A later request must consult TTL cache or start a fresh query,
    /// especially after a setup timeout or a TTL-zero response.
    pub fn finish_flight(&self, key: &[u8], flight: &Arc<Flight>) {
        let mut state = self.state.lock();
        if state
            .flights
            .get(key)
            .and_then(Weak::upgrade)
            .is_some_and(|current| Arc::ptr_eq(&current, flight))
        {
            state.flights.remove(key);
        }
    }
}

fn cache_ttl(message: &Message) -> u32 {
    if message.metadata.truncation || super::message::is_signed(message) {
        return 0;
    }
    match message.metadata.response_code {
        ResponseCode::NoError if !message.answers.is_empty() => message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .chain(message.additionals.iter())
            .map(|record| record.ttl)
            .min()
            .unwrap_or(0),
        ResponseCode::NoError | ResponseCode::NXDomain => message
            .authorities
            .iter()
            .filter_map(|record| match &record.data {
                RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
                _ => None,
            })
            .min()
            .unwrap_or(0),
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::{
        op::Query,
        rr::{Name, Record, RecordType, rdata::A},
    };

    fn response(ttl: u32) -> Message {
        let mut message = Message::query();
        let name = Name::from_ascii("cache.test.").unwrap();
        message.add_query(Query::query(name.clone(), RecordType::A));
        let mut message = message.into_response();
        message.add_answer(Record::from_rdata(
            name,
            ttl,
            RData::A(A::new(192, 0, 2, 1)),
        ));
        message
    }

    #[tokio::test(start_paused = true)]
    async fn ttl_is_aged_and_never_extended() {
        let cache = ResponseCache::default();
        let reply = response(3);
        cache.insert(b"query", Answer::new(&reply).unwrap(), &reply);
        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(
            cache.get(b"query").unwrap().message().unwrap().answers[0].ttl,
            1
        );
        tokio::time::advance(Duration::from_secs(1)).await;
        assert!(cache.get(b"query").is_none());
        assert_eq!(cache.state.lock().bytes, 0);
    }

    #[test]
    fn byte_and_entry_limits_evict_without_retaining_oversized_answers() {
        let reply = response(60);
        let answer = Answer::new(&reply).unwrap();
        let charged = 1 + answer.bytes.len() + ENTRY_OVERHEAD;
        let cache = ResponseCache::new(2, charged * 2);
        for key in [b"a", b"b", b"c"] {
            cache.insert(key, answer.clone(), &reply);
        }
        assert!(cache.get(b"a").is_none());
        assert_eq!(cache.state.lock().entries.len(), 2);
        assert!(cache.state.lock().bytes <= charged * 2);
        cache.insert(&vec![0; charged * 2], answer, &reply);
        assert_eq!(cache.state.lock().entries.len(), 2);
    }

    #[test]
    fn flights_share_ownership_and_cancellation_releases_slot() {
        let cache = ResponseCache::default();
        let first = cache.flight(b"same").unwrap();
        let second = cache.flight(b"same").unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        drop(first);
        drop(second);
        let next = cache.flight(b"next").unwrap();
        assert_eq!(cache.state.lock().flights.len(), 1);
        drop(next);
    }

    #[test]
    fn completed_flight_cannot_poison_retry_or_remove_next_generation() {
        let cache = ResponseCache::default();
        let first = cache.flight(b"retry").unwrap();
        cache.finish_flight(b"retry", &first);
        let second = cache.flight(b"retry").unwrap();
        assert!(!Arc::ptr_eq(&first, &second));
        cache.finish_flight(b"retry", &first);
        assert!(Arc::ptr_eq(&second, &cache.flight(b"retry").unwrap()));
    }

    #[test]
    fn failures_and_zero_ttl_are_not_cached() {
        let cache = ResponseCache::default();
        for ttl in [0, 60] {
            let mut reply = response(ttl);
            if ttl != 0 {
                reply.metadata.response_code = ResponseCode::ServFail;
            }
            cache.insert(b"query", Answer::new(&reply).unwrap(), &reply);
            assert!(cache.get(b"query").is_none());
        }
    }
}
