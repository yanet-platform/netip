use std::fmt::Write;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use netip::MacAddr;

fn bench_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("macaddr");

    group.throughput(Throughput::Elements(1));
    group.bench_function("MacAddr::parse_ascii colon-separated", |b| {
        let s = b"3a:ac:26:9b:5b:f9";
        b.iter(|| core::hint::black_box(MacAddr::parse_ascii(core::hint::black_box(s))));
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("MacAddr::parse_ascii hyphen-separated", |b| {
        let s = b"3a-ac-26-9b-5b-f9";
        b.iter(|| core::hint::black_box(MacAddr::parse_ascii(core::hint::black_box(s))));
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("MacAddr::parse_ascii invalid hex error path", |b| {
        let s = b"3a:ac:26:9b:5b:fg";
        b.iter(|| core::hint::black_box(MacAddr::parse_ascii(core::hint::black_box(s))));
    });

    group.finish();
}

fn bench_display(c: &mut Criterion) {
    let mut group = c.benchmark_group("macaddr");

    group.throughput(Throughput::Elements(1));
    group.bench_function("MacAddr::to_string", |b| {
        let mac = MacAddr::new(0x3a, 0xac, 0x26, 0x9b, 0x5b, 0xf9);
        b.iter(|| core::hint::black_box(core::hint::black_box(&mac).to_string()));
    });

    group.throughput(Throughput::Elements(1));
    group.bench_function("MacAddr::fmt into reused buffer", |b| {
        let mac = MacAddr::new(0x3a, 0xac, 0x26, 0x9b, 0x5b, 0xf9);
        let mut buf = String::with_capacity(17);
        b.iter(|| {
            buf.clear();
            write!(buf, "{}", core::hint::black_box(&mac)).unwrap();
            core::hint::black_box(&buf);
        });
    });

    // Bulk formatting: 64 distinct addresses, each via a fresh (unsized)
    // `to_string()`. This mirrors bulk serialization / logging call sites,
    // where every call pays its own allocator round-trip instead of reusing
    // a pre-sized buffer, unlike the single-value bench above.
    group.throughput(Throughput::Elements(64));
    group.bench_function("MacAddr::to_string bulk 64x", |b| {
        let macs: [MacAddr; 64] = core::array::from_fn(|i| MacAddr::from(0x0102_0304_0506u64.wrapping_add(i as u64)));
        b.iter(|| {
            for mac in core::hint::black_box(&macs) {
                core::hint::black_box(mac.to_string());
            }
        });
    });

    group.finish();
}

fn bench_cmp(c: &mut Criterion) {
    let mut group = c.benchmark_group("macaddr");

    group.bench_function("MacAddr::cmp", |b| {
        let a = MacAddr::new(0x3a, 0xac, 0x26, 0x9b, 0x5b, 0xf9);
        let b_mac = MacAddr::new(0x3a, 0xac, 0x26, 0x9b, 0x5b, 0xfa);
        b.iter(|| core::hint::black_box(core::hint::black_box(&a).cmp(core::hint::black_box(&b_mac))));
    });

    group.finish();
}

criterion_group!(benches, bench_parse, bench_display, bench_cmp);
criterion_main!(benches);
