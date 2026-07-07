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
