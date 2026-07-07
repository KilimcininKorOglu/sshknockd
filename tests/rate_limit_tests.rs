use ssh_knock::rate_limit::TokenBucketLimiter;
use std::time::{Duration, Instant};

#[test]
fn denies_after_capacity_because_invalid_knocks_must_be_rate_limited() {
    let mut limiter = TokenBucketLimiter::new(2, 1, Duration::from_secs(60));
    let now = Instant::now();
    assert!(limiter.allow("client", now));
    assert!(limiter.allow("client", now));
    assert!(!limiter.allow("client", now));
}

#[test]
fn refills_after_interval_because_temporary_blocks_must_not_be_permanent() {
    let mut limiter = TokenBucketLimiter::new(1, 1, Duration::from_secs(60));
    let now = Instant::now();
    assert!(limiter.allow("client", now));
    assert!(!limiter.allow("client", now));
    assert!(limiter.allow("client", now + Duration::from_secs(60)));
}

#[test]
fn expires_idle_buckets_because_untrusted_sources_must_not_grow_memory_unbounded() {
    let mut limiter = TokenBucketLimiter::new(1, 1, Duration::from_secs(60));
    let now = Instant::now();

    assert!(limiter.allow("client-a", now));
    assert!(limiter.allow("client-b", now));
    assert_eq!(limiter.len(), 2);

    assert!(limiter.allow("client-c", now + Duration::from_secs(121)));

    assert_eq!(limiter.len(), 1);
}

#[test]
fn keeps_recent_buckets_because_active_sources_must_remain_rate_limited() {
    let mut limiter = TokenBucketLimiter::new(1, 1, Duration::from_secs(60));
    let now = Instant::now();

    assert!(limiter.allow("client-a", now));
    assert!(limiter.allow("client-b", now));
    assert!(limiter.allow("client-a", now + Duration::from_secs(100)));
    assert_eq!(limiter.len(), 2);

    assert!(limiter.allow("client-c", now + Duration::from_secs(150)));

    assert_eq!(limiter.len(), 2);
}
