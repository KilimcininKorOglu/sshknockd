use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct Bucket {
    tokens: u32,
    last_refill: Instant,
}

#[derive(Debug, Clone)]
pub struct TokenBucketLimiter<K> {
    capacity: u32,
    refill: u32,
    interval: Duration,
    buckets: HashMap<K, Bucket>,
}

impl<K> TokenBucketLimiter<K>
where
    K: Eq + Hash + Clone,
{
    /// Creates a token bucket limiter.
    pub fn new(capacity: u32, refill: u32, interval: Duration) -> Self {
        Self {
            capacity,
            refill,
            interval,
            buckets: HashMap::new(),
        }
    }

    /// Returns true when the key may consume one token.
    pub fn allow(&mut self, key: K, now: Instant) -> bool {
        let bucket = self.buckets.entry(key).or_insert(Bucket {
            tokens: self.capacity,
            last_refill: now,
        });
        let elapsed = now.duration_since(bucket.last_refill);
        if elapsed >= self.interval {
            let intervals = elapsed.as_secs() / self.interval.as_secs().max(1);
            let add = self
                .refill
                .saturating_mul(intervals.try_into().unwrap_or(u32::MAX));
            bucket.tokens = self.capacity.min(bucket.tokens.saturating_add(add));
            bucket.last_refill = now;
        }
        if bucket.tokens == 0 {
            false
        } else {
            bucket.tokens -= 1;
            true
        }
    }
}
