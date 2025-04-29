## Notes

### on the rust api solution

Because Rust’s test harness runs tests in parallel by default, two tests can interleave:

1. A truncates
2. B truncates
3. A inserts seed
4. B inserts seed → duplicate-key error
 
Use this command to run the tests:

```bash
cargo test --test test_app -- --test-threads=1
```