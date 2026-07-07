use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
struct Bucket {
    tokens: u32,
    last_refill: Instant,
    last_seen: Instant,
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

    /// Returns the number of tracked limiter buckets.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    fn idle_ttl(&self) -> Duration {
        match self.interval.checked_mul(2) {
            Some(duration) => duration,
            None => Duration::MAX,
        }
    }

    fn prune_idle(&mut self, now: Instant) {
        let idle_ttl = self.idle_ttl();
        self.buckets
            .retain(|_, bucket| now.duration_since(bucket.last_seen) < idle_ttl);
    }

    /// Returns true when the key may consume one token.
    pub fn allow(&mut self, key: K, now: Instant) -> bool {
        self.prune_idle(now);
        let bucket = self.buckets.entry(key).or_insert(Bucket {
            tokens: self.capacity,
            last_refill: now,
            last_seen: now,
        });
        bucket.last_seen = now;
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
