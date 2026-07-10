use core::net::{Ipv4Addr, Ipv6Addr};

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use netip::{Ipv4Network, Ipv6Network};

fn bench_net_addrs(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.throughput(Throughput::Elements(256));
    group.bench_function("Ipv4Network::addrs /24", |b| {
        let net = Ipv4Network::parse("77.88.55.0/24").unwrap();
        b.iter(|| {
            for addr in net.addrs() {
                core::hint::black_box(addr);
            }
        });
    });

    group.throughput(Throughput::Elements(65536));
    group.bench_function("Ipv4Network::addrs /16", |b| {
        let net = Ipv4Network::parse("77.88.0.0/16").unwrap();
        b.iter(|| {
            for addr in net.addrs() {
                core::hint::black_box(addr);
            }
        });
    });

    group.throughput(Throughput::Elements(256));
    group.bench_function("Ipv4Network::addrs non-contiguous 8 host bits", |b| {
        let net = Ipv4Network::parse("192.168.0.1/255.255.0.255").unwrap();
        b.iter(|| {
            for addr in net.addrs() {
                core::hint::black_box(addr);
            }
        });
    });

    group.throughput(Throughput::Elements(256));
    group.bench_function("Ipv6Network::addrs /120", |b| {
        let net = Ipv6Network::parse("2a02:6b8:c00::1234:0:0/120").unwrap();
        b.iter(|| {
            for addr in net.addrs() {
                core::hint::black_box(addr);
            }
        });
    });

    group.throughput(Throughput::Elements(65536));
    group.bench_function("Ipv6Network::addrs /112", |b| {
        let net = Ipv6Network::parse("2a02:6b8:c00::1234:0:0/112").unwrap();
        b.iter(|| {
            for addr in net.addrs() {
                core::hint::black_box(addr);
            }
        });
    });

    group.throughput(Throughput::Elements(256));
    group.bench_function("Ipv6Network::addrs non-contiguous 8 host bits", |b| {
        let net = Ipv6Network::new(
            Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
        );
        b.iter(|| {
            for addr in net.addrs() {
                core::hint::black_box(addr);
            }
        });
    });

    group.finish();
}

fn bench_net_addrs_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.bench_function("Ipv4Network::addrs count /24", |b| {
        let net = Ipv4Network::parse("77.88.55.0/24").unwrap();
        b.iter(|| {
            core::hint::black_box(net.addrs().count());
        });
    });

    group.bench_function("Ipv6Network::addrs count /120", |b| {
        let net = Ipv6Network::parse("2a02:6b8:c00::1234:0:0/120").unwrap();
        b.iter(|| {
            core::hint::black_box(net.addrs().count());
        });
    });

    group.bench_function("Ipv6Network::addrs count /112", |b| {
        let net = Ipv6Network::parse("2a02:6b8:c00::1234:0:0/112").unwrap();
        b.iter(|| {
            core::hint::black_box(net.addrs().count());
        });
    });

    group.bench_function("Ipv6Network::addrs count non-contiguous 8 host bits", |b| {
        let net = Ipv6Network::new(
            Ipv6Addr::new(0x2a02, 0x6b8, 0xc00, 0, 0, 0x1234, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
        );
        b.iter(|| {
            core::hint::black_box(net.addrs().count());
        });
    });

    group.finish();
}

fn bench_intersection(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.bench_function("Ipv4Network::intersects contiguous", |b| {
        let n0 = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let n1 = Ipv4Network::parse("192.168.1.0/24").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).intersects(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::intersection contiguous overlapping", |b| {
        let n0 = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let n1 = Ipv4Network::parse("192.168.1.0/24").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).intersection(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::intersection contiguous disjoint", |b| {
        let n0 = Ipv4Network::parse("192.168.0.0/16").unwrap();
        let n1 = Ipv4Network::parse("10.0.0.0/8").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).intersection(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::intersection non-contiguous", |b| {
        let n0 = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(255, 0, 0, 255));
        let n1 = Ipv4Network::new(Ipv4Addr::new(10, 1, 0, 0), Ipv4Addr::new(255, 255, 0, 0));
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).intersection(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::intersects contiguous", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/32").unwrap();
        let n1 = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).intersects(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::intersection contiguous overlapping", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/32").unwrap();
        let n1 = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).intersection(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::intersection contiguous disjoint", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/32").unwrap();
        let n1 = Ipv6Network::parse("fe80::/10").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).intersection(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::intersection non-contiguous", |b| {
        let n0 = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xffff, 0, 0, 0, 0, 0, 0, 0xffff),
        );
        let n1 = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 1, 0, 0, 0, 0, 0, 0),
            Ipv6Addr::new(0xffff, 0xffff, 0, 0, 0, 0, 0, 0),
        );
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).intersection(core::hint::black_box(&n1)));
        });
    });

    group.finish();
}

fn bench_contains(c: &mut Criterion) {
    use netip::IpNetwork;

    let mut group = c.benchmark_group("netip");

    group.bench_function("Ipv4Network::contains contiguous true", |b| {
        let n0 = Ipv4Network::parse("10.0.0.0/8").unwrap();
        let n1 = Ipv4Network::parse("10.1.0.0/16").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).contains(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::contains contiguous false", |b| {
        let n0 = Ipv4Network::parse("10.0.0.0/8").unwrap();
        let n1 = Ipv4Network::parse("192.168.0.0/16").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).contains(core::hint::black_box(&n1)));
        });
    });

    // Mask "255.0.0.255" leaves a hole in the two middle octets, so the
    // contained network may differ freely there while still matching on the
    // fixed first and last octets.
    group.bench_function("Ipv4Network::contains non-contiguous", |b| {
        let n0 = Ipv4Network::parse("10.0.0.0/255.0.0.255").unwrap();
        let n1 = Ipv4Network::parse("10.5.9.0/255.255.0.255").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).contains(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::contains contiguous true", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/32").unwrap();
        let n1 = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).contains(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::contains contiguous false", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/32").unwrap();
        let n1 = Ipv6Network::parse("fe80::/10").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).contains(core::hint::black_box(&n1)));
        });
    });

    // Mask "ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff" leaves an 8-bit hole in
    // the third group, so the contained network's low byte there is free.
    group.bench_function("Ipv6Network::contains non-contiguous", |b| {
        let n0 = Ipv6Network::parse("2001:db8:c00::1/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff").unwrap();
        let n1 = Ipv6Network::parse("2001:db8:c05::1/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).contains(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("IpNetwork::contains v4", |b| {
        let n0 = IpNetwork::parse("10.0.0.0/8").unwrap();
        let n1 = IpNetwork::parse("10.1.0.0/16").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).contains(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("IpNetwork::contains v6", |b| {
        let n0 = IpNetwork::parse("2001:db8::/32").unwrap();
        let n1 = IpNetwork::parse("2001:db8:1::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).contains(core::hint::black_box(&n1)));
        });
    });

    group.finish();
}

// `Contiguous<Ipv4Network>::contains` / `Contiguous<Ipv6Network>::contains`
// override the general `contains` check: the general formula's mask subset test
// (`mask & mask == mask`) becomes a plain unsigned integer comparison, valid
// only because the `Contiguous` invariant guarantees both masks are contiguous.
// Each override is benchmarked against the same values compared through `Deref`
// (via an explicit `&Ipv4Network` / `&Ipv6Network` binding) to reach the
// general `contains` check.
fn bench_contiguous_contains(c: &mut Criterion) {
    use netip::Contiguous;

    let mut group = c.benchmark_group("netip");

    group.bench_function("Contiguous<Ipv4Network>::contains true", |b| {
        let n0 = Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap();
        let n1 = Contiguous::<Ipv4Network>::parse("10.1.0.0/16").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).contains(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Contiguous<Ipv4Network>::contains false", |b| {
        let n0 = Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap();
        let n1 = Contiguous::<Ipv4Network>::parse("192.168.0.0/16").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).contains(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::contains via Deref true", |b| {
        let n0 = Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap();
        let n1 = Contiguous::<Ipv4Network>::parse("10.1.0.0/16").unwrap();
        b.iter(|| {
            let a: &Ipv4Network = core::hint::black_box(&n0);
            let b: &Ipv4Network = core::hint::black_box(&n1);
            core::hint::black_box(a.contains(b));
        });
    });

    group.bench_function("Ipv4Network::contains via Deref false", |b| {
        let n0 = Contiguous::<Ipv4Network>::parse("10.0.0.0/8").unwrap();
        let n1 = Contiguous::<Ipv4Network>::parse("192.168.0.0/16").unwrap();
        b.iter(|| {
            let a: &Ipv4Network = core::hint::black_box(&n0);
            let b: &Ipv4Network = core::hint::black_box(&n1);
            core::hint::black_box(a.contains(b));
        });
    });

    group.bench_function("Contiguous<Ipv6Network>::contains true", |b| {
        let n0 = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let n1 = Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).contains(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Contiguous<Ipv6Network>::contains false", |b| {
        let n0 = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let n1 = Contiguous::<Ipv6Network>::parse("fe80::/10").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).contains(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::contains via Deref true", |b| {
        let n0 = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let n1 = Contiguous::<Ipv6Network>::parse("2001:db8:1::/48").unwrap();
        b.iter(|| {
            let a: &Ipv6Network = core::hint::black_box(&n0);
            let b: &Ipv6Network = core::hint::black_box(&n1);
            core::hint::black_box(a.contains(b));
        });
    });

    group.bench_function("Ipv6Network::contains via Deref false", |b| {
        let n0 = Contiguous::<Ipv6Network>::parse("2001:db8::/32").unwrap();
        let n1 = Contiguous::<Ipv6Network>::parse("fe80::/10").unwrap();
        b.iter(|| {
            let a: &Ipv6Network = core::hint::black_box(&n0);
            let b: &Ipv6Network = core::hint::black_box(&n1);
            core::hint::black_box(a.contains(b));
        });
    });

    group.finish();
}

// Consumes a boxed `dyn Iterator` from behind an `#[inline(never)]` boundary
// so `iter.next()` is a genuine indirect call through the vtable rather than
// something the optimizer can devirtualize back into a concrete, hoistable
// loop -- this is the scenario where `Contiguous`'s hard-wired iterator has a
// real, reproducible edge over the general one (unlike a plain `for` loop,
// where LLVM already hoists the per-item mask-contiguity check).
#[inline(never)]
fn consume_boxed_v4(iter: Box<dyn Iterator<Item = Ipv4Addr>>) -> u32 {
    let mut acc = 0u32;
    for addr in iter {
        acc ^= addr.to_bits();
    }
    acc
}

#[inline(never)]
fn consume_boxed_v6(iter: Box<dyn Iterator<Item = Ipv6Addr>>) -> u128 {
    let mut acc = 0u128;
    for addr in iter {
        acc ^= addr.to_bits();
    }
    acc
}

fn bench_contiguous_addrs(c: &mut Criterion) {
    use netip::Contiguous;

    let mut group = c.benchmark_group("netip");

    // `net`/`other` are re-black-boxed on every `b.iter()` call (not just the
    // yielded addresses) so the compiler can't prove the whole loop is
    // invariant across the repeated outer benchmark loop and hoist/CSE it
    // away entirely -- that hoisting is a real risk here since these loops
    // are small enough to fully inline, unlike the bigger general iterator.

    group.throughput(Throughput::Elements(65536));
    group.bench_function("Contiguous<Ipv4Network>::addrs /16", |b| {
        let net = Contiguous::<Ipv4Network>::parse("77.88.0.0/16").unwrap();
        b.iter(|| {
            for addr in core::hint::black_box(net).addrs() {
                core::hint::black_box(addr);
            }
        });
    });

    group.bench_function("Ipv4Network::addrs via Deref /16", |b| {
        let net = Contiguous::<Ipv4Network>::parse("77.88.0.0/16").unwrap();
        b.iter(|| {
            for addr in (*core::hint::black_box(net)).addrs() {
                core::hint::black_box(addr);
            }
        });
    });

    group.bench_function("Contiguous<Ipv4Network>::addrs boxed dyn Iterator /16", |b| {
        let net = Contiguous::<Ipv4Network>::parse("77.88.0.0/16").unwrap();
        b.iter(|| {
            let iter: Box<dyn Iterator<Item = Ipv4Addr>> = Box::new(core::hint::black_box(net).addrs());
            core::hint::black_box(consume_boxed_v4(iter));
        });
    });

    group.bench_function("Ipv4Network::addrs via Deref boxed dyn Iterator /16", |b| {
        let net = Contiguous::<Ipv4Network>::parse("77.88.0.0/16").unwrap();
        b.iter(|| {
            let iter: Box<dyn Iterator<Item = Ipv4Addr>> = Box::new((*core::hint::black_box(net)).addrs());
            core::hint::black_box(consume_boxed_v4(iter));
        });
    });

    group.bench_function("Contiguous<Ipv4Network>::addrs zip /16", |b| {
        let net = Contiguous::<Ipv4Network>::parse("77.88.0.0/16").unwrap();
        let other = Contiguous::<Ipv4Network>::parse("77.89.0.0/16").unwrap();
        b.iter(|| {
            let mut acc = 0u32;
            for (x, y) in core::hint::black_box(net)
                .addrs()
                .zip(core::hint::black_box(other).addrs())
            {
                acc ^= x.to_bits() ^ y.to_bits();
            }
            core::hint::black_box(acc);
        });
    });

    group.bench_function("Ipv4Network::addrs via Deref zip /16", |b| {
        let net = Contiguous::<Ipv4Network>::parse("77.88.0.0/16").unwrap();
        let other = Contiguous::<Ipv4Network>::parse("77.89.0.0/16").unwrap();
        b.iter(|| {
            let mut acc = 0u32;
            for (x, y) in (*core::hint::black_box(net))
                .addrs()
                .zip((*core::hint::black_box(other)).addrs())
            {
                acc ^= x.to_bits() ^ y.to_bits();
            }
            core::hint::black_box(acc);
        });
    });

    group.bench_function("Contiguous<Ipv6Network>::addrs /112", |b| {
        let net = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/112").unwrap();
        b.iter(|| {
            for addr in core::hint::black_box(net).addrs() {
                core::hint::black_box(addr);
            }
        });
    });

    group.bench_function("Ipv6Network::addrs via Deref /112", |b| {
        let net = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/112").unwrap();
        b.iter(|| {
            for addr in (*core::hint::black_box(net)).addrs() {
                core::hint::black_box(addr);
            }
        });
    });

    group.bench_function("Contiguous<Ipv6Network>::addrs boxed dyn Iterator /112", |b| {
        let net = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/112").unwrap();
        b.iter(|| {
            let iter: Box<dyn Iterator<Item = Ipv6Addr>> = Box::new(core::hint::black_box(net).addrs());
            core::hint::black_box(consume_boxed_v6(iter));
        });
    });

    group.bench_function("Ipv6Network::addrs via Deref boxed dyn Iterator /112", |b| {
        let net = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/112").unwrap();
        b.iter(|| {
            let iter: Box<dyn Iterator<Item = Ipv6Addr>> = Box::new((*core::hint::black_box(net)).addrs());
            core::hint::black_box(consume_boxed_v6(iter));
        });
    });

    group.bench_function("Contiguous<Ipv6Network>::addrs zip /112", |b| {
        let net = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/112").unwrap();
        let other = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::1235:0:0/112").unwrap();
        b.iter(|| {
            let mut acc = 0u128;
            for (x, y) in core::hint::black_box(net)
                .addrs()
                .zip(core::hint::black_box(other).addrs())
            {
                acc ^= x.to_bits() ^ y.to_bits();
            }
            core::hint::black_box(acc);
        });
    });

    group.bench_function("Ipv6Network::addrs via Deref zip /112", |b| {
        let net = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/112").unwrap();
        let other = Contiguous::<Ipv6Network>::parse("2a02:6b8:c00::1235:0:0/112").unwrap();
        b.iter(|| {
            let mut acc = 0u128;
            for (x, y) in (*core::hint::black_box(net))
                .addrs()
                .zip((*core::hint::black_box(other)).addrs())
            {
                acc ^= x.to_bits() ^ y.to_bits();
            }
            core::hint::black_box(acc);
        });
    });

    group.finish();
}

fn bench_bicontiguous_addrs(c: &mut Criterion) {
    use netip::BiContiguous;

    let mut group = c.benchmark_group("netip");

    // `net` is re-black-boxed on every `b.iter()` call (not just the yielded
    // addresses), for the same reason as `bench_contiguous_addrs`: these
    // loops are small enough that the compiler could otherwise hoist them
    // out of criterion's repeated-call structure entirely.

    group.throughput(Throughput::Elements(256));
    group.bench_function("BiContiguous<Ipv6Network>::addrs 8 host bits (4+4)", |b| {
        let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ffff:fff0:ffff:ffff:ffff:fff0")
            .unwrap();
        b.iter(|| {
            for addr in core::hint::black_box(net).addrs() {
                core::hint::black_box(addr);
            }
        });
    });

    group.bench_function("Ipv6Network::addrs via Deref 8 host bits (4+4)", |b| {
        let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ffff:fff0:ffff:ffff:ffff:fff0")
            .unwrap();
        b.iter(|| {
            for addr in (*core::hint::black_box(net)).addrs() {
                core::hint::black_box(addr);
            }
        });
    });

    group.throughput(Throughput::Elements(65536));
    group.bench_function("BiContiguous<Ipv6Network>::addrs 16 host bits (8+8)", |b| {
        let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ffff:ff00:ffff:ffff:ffff:ff00")
            .unwrap();
        b.iter(|| {
            for addr in core::hint::black_box(net).addrs() {
                core::hint::black_box(addr);
            }
        });
    });

    group.bench_function("Ipv6Network::addrs via Deref 16 host bits (8+8)", |b| {
        let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:0:0/ffff:ffff:ffff:ff00:ffff:ffff:ffff:ff00")
            .unwrap();
        b.iter(|| {
            for addr in (*core::hint::black_box(net)).addrs() {
                core::hint::black_box(addr);
            }
        });
    });

    group.finish();
}

fn bench_bicontiguous_is_contiguous(c: &mut Criterion) {
    use netip::BiContiguous;

    let mut group = c.benchmark_group("netip");

    // A proper two-run bi-contiguous mask (`p = 40`, `q = 32`): not contiguous,
    // so the override's per-half check inspects both 64-bit words before
    // answering. `net` is re-black-boxed on every `b.iter()` call so the small
    // kernel cannot be hoisted out of criterion's repeated-call structure.
    group.bench_function("BiContiguous<Ipv6Network>::is_contiguous two-run", |b| {
        let net =
            BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(net).is_contiguous());
        });
    });

    group.bench_function("Ipv6Network::is_contiguous via Deref two-run", |b| {
        let net =
            BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
        b.iter(|| {
            core::hint::black_box((*core::hint::black_box(net)).is_contiguous());
        });
    });

    // A degenerate contiguous member (`q = 0`): a plain CIDR mask whose low
    // 64-bit word is zero, so the override short-circuits on the first test.
    group.bench_function("BiContiguous<Ipv6Network>::is_contiguous contiguous", |b| {
        let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::/40").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(net).is_contiguous());
        });
    });

    group.bench_function("Ipv6Network::is_contiguous via Deref contiguous", |b| {
        let net = BiContiguous::<Ipv6Network>::parse("2a02:6b8:c00::/40").unwrap();
        b.iter(|| {
            core::hint::black_box((*core::hint::black_box(net)).is_contiguous());
        });
    });

    group.finish();
}

fn bench_merge(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.bench_function("Ipv4Network::merge equal-mask adjacent", |b| {
        let n0 = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let n1 = Ipv4Network::parse("192.168.1.0/24").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::merge equal-mask non-mergeable", |b| {
        let n0 = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let n1 = Ipv4Network::parse("192.168.3.0/24").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::merge containment", |b| {
        let n0 = Ipv4Network::parse("10.0.0.0/8").unwrap();
        let n1 = Ipv4Network::parse("10.1.0.0/16").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::merge comparable masks address mismatch", |b| {
        let n0 = Ipv4Network::parse("10.0.0.0/8").unwrap();
        let n1 = Ipv4Network::parse("172.16.0.0/16").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::merge incomparable masks", |b| {
        let n0 = Ipv4Network::parse("10.0.0.1/255.255.0.255").unwrap();
        let n1 = Ipv4Network::parse("10.0.0.1/255.0.255.255").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::merge non-contiguous", |b| {
        let n0 = Ipv4Network::new(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::from(0xffff00ffu32));
        let n1 = Ipv4Network::new(Ipv4Addr::new(10, 1, 0, 1), Ipv4Addr::from(0xffff00ffu32));
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::merge equal-mask adjacent", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/48").unwrap();
        let n1 = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::merge equal-mask non-mergeable", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/48").unwrap();
        let n1 = Ipv6Network::parse("2001:db8:5::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::merge containment", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/32").unwrap();
        let n1 = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::merge comparable masks address mismatch", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/32").unwrap();
        let n1 = Ipv6Network::parse("2001:beef:1::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::merge incomparable masks", |b| {
        let n0 = Ipv6Network::parse("2001:db8::1/ffff:0:ffff::").unwrap();
        let n1 = Ipv6Network::parse("2001:db8::1/0:ffff:ffff::").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::merge non-contiguous", |b| {
        let n0 = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xffff, 0xff00, 0, 0, 0, 0, 0, 0xffff),
        );
        let n1 = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0x0100, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xffff, 0xff00, 0, 0, 0, 0, 0, 0xffff),
        );
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge(core::hint::black_box(&n1)));
        });
    });

    group.finish();
}

fn bench_is_adjacent(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.bench_function("Ipv4Network::is_adjacent contiguous", |b| {
        let n0 = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let n1 = Ipv4Network::parse("192.168.1.0/24").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).is_adjacent(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::is_adjacent non-adjacent", |b| {
        let n0 = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let n1 = Ipv4Network::parse("192.168.3.0/24").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).is_adjacent(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::is_adjacent non-contiguous", |b| {
        let n0 = Ipv4Network::parse("10.0.0.1/255.255.0.255").unwrap();
        let n1 = Ipv4Network::parse("10.1.0.1/255.255.0.255").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).is_adjacent(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::is_adjacent contiguous", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/48").unwrap();
        let n1 = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).is_adjacent(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::is_adjacent non-contiguous", |b| {
        let n0 = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xffff, 0xff00, 0, 0, 0, 0, 0, 0xffff),
        );
        let n1 = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0x0100, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xffff, 0xff00, 0, 0, 0, 0, 0, 0xffff),
        );
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).is_adjacent(core::hint::black_box(&n1)));
        });
    });

    group.finish();
}

// Paired with `is_adjacent` on identical inputs so the extra `bswap` the
// lowest-bit test needs (its `m & -m` isolation is not byte-order-agnostic,
// unlike `is_adjacent`'s power-of-two test) is directly visible.
fn bench_is_adjacent_by_lowest_mask_bit(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.bench_function("Ipv4Network::is_adjacent CIDR siblings (A/B)", |b| {
        let n0 = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let n1 = Ipv4Network::parse("192.168.1.0/24").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).is_adjacent(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::is_adjacent_by_lowest_mask_bit CIDR siblings", |b| {
        let n0 = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let n1 = Ipv4Network::parse("192.168.1.0/24").unwrap();
        b.iter(|| {
            core::hint::black_box(
                core::hint::black_box(&n0).is_adjacent_by_lowest_mask_bit(core::hint::black_box(&n1)),
            );
        });
    });

    group.bench_function(
        "Ipv4Network::is_adjacent_by_lowest_mask_bit adjacent non-lowest bit",
        |b| {
            let n0 = Ipv4Network::parse("0.0.0.0/2").unwrap();
            let n1 = Ipv4Network::parse("128.0.0.0/2").unwrap();
            b.iter(|| {
                core::hint::black_box(
                    core::hint::black_box(&n0).is_adjacent_by_lowest_mask_bit(core::hint::black_box(&n1)),
                );
            });
        },
    );

    group.bench_function("Ipv4Network::is_adjacent_by_lowest_mask_bit non-contiguous", |b| {
        let n0 = Ipv4Network::parse("10.0.0.0/255.255.0.255").unwrap();
        let n1 = Ipv4Network::parse("10.0.0.1/255.255.0.255").unwrap();
        b.iter(|| {
            core::hint::black_box(
                core::hint::black_box(&n0).is_adjacent_by_lowest_mask_bit(core::hint::black_box(&n1)),
            );
        });
    });

    group.bench_function("Ipv6Network::is_adjacent CIDR siblings (A/B)", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/48").unwrap();
        let n1 = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).is_adjacent(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::is_adjacent_by_lowest_mask_bit CIDR siblings", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/48").unwrap();
        let n1 = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(
                core::hint::black_box(&n0).is_adjacent_by_lowest_mask_bit(core::hint::black_box(&n1)),
            );
        });
    });

    group.bench_function(
        "Ipv6Network::is_adjacent_by_lowest_mask_bit adjacent non-lowest bit",
        |b| {
            let n0 = Ipv6Network::parse("::/2").unwrap();
            let n1 = Ipv6Network::parse("8000::/2").unwrap();
            b.iter(|| {
                core::hint::black_box(
                    core::hint::black_box(&n0).is_adjacent_by_lowest_mask_bit(core::hint::black_box(&n1)),
                );
            });
        },
    );

    group.bench_function("Ipv6Network::is_adjacent_by_lowest_mask_bit non-contiguous", |b| {
        let n0 = Ipv6Network::parse("::/ffff:ffff::ffff").unwrap();
        let n1 = Ipv6Network::parse("::1/ffff:ffff::ffff").unwrap();
        b.iter(|| {
            core::hint::black_box(
                core::hint::black_box(&n0).is_adjacent_by_lowest_mask_bit(core::hint::black_box(&n1)),
            );
        });
    });

    group.finish();
}

// Paired with `merge` on identical inputs so the cost of the class-closed
// subset is directly visible against the general merge. The "adjacent
// non-lowest bit" pair is where they diverge: `merge` combines it (into a
// non-contiguous block), `merge_by_lowest_mask_bit` rejects it. The
// "containment" pair exercises the leading `contains` fast path they share.
fn bench_merge_by_lowest_mask_bit(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.bench_function("Ipv4Network::merge CIDR siblings (A/B)", |b| {
        let n0 = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let n1 = Ipv4Network::parse("192.168.1.0/24").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::merge_by_lowest_mask_bit CIDR siblings", |b| {
        let n0 = Ipv4Network::parse("192.168.0.0/24").unwrap();
        let n1 = Ipv4Network::parse("192.168.1.0/24").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge_by_lowest_mask_bit(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::merge_by_lowest_mask_bit adjacent non-lowest bit", |b| {
        let n0 = Ipv4Network::parse("0.0.0.0/2").unwrap();
        let n1 = Ipv4Network::parse("128.0.0.0/2").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge_by_lowest_mask_bit(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::merge_by_lowest_mask_bit non-contiguous", |b| {
        let n0 = Ipv4Network::parse("10.0.0.0/255.255.0.255").unwrap();
        let n1 = Ipv4Network::parse("10.0.0.1/255.255.0.255").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge_by_lowest_mask_bit(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv4Network::merge_by_lowest_mask_bit containment", |b| {
        let n0 = Ipv4Network::parse("10.0.0.0/8").unwrap();
        let n1 = Ipv4Network::parse("10.1.0.0/16").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge_by_lowest_mask_bit(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::merge CIDR siblings (A/B)", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/48").unwrap();
        let n1 = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::merge_by_lowest_mask_bit CIDR siblings", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/48").unwrap();
        let n1 = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge_by_lowest_mask_bit(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::merge_by_lowest_mask_bit adjacent non-lowest bit", |b| {
        let n0 = Ipv6Network::parse("::/2").unwrap();
        let n1 = Ipv6Network::parse("8000::/2").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge_by_lowest_mask_bit(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::merge_by_lowest_mask_bit non-contiguous", |b| {
        let n0 = Ipv6Network::parse("::/ffff:ffff::ffff").unwrap();
        let n1 = Ipv6Network::parse("::1/ffff:ffff::ffff").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge_by_lowest_mask_bit(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::merge_by_lowest_mask_bit containment", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/32").unwrap();
        let n1 = Ipv6Network::parse("2001:db8:1::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).merge_by_lowest_mask_bit(core::hint::black_box(&n1)));
        });
    });

    group.finish();
}

fn bench_is_contiguous(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.bench_function("Ipv4Network::is_contiguous contiguous", |b| {
        let net = Ipv4Network::parse("192.168.0.0/16").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).is_contiguous());
        });
    });

    group.bench_function("Ipv4Network::is_contiguous non-contiguous", |b| {
        let net = Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(255, 255, 0, 255));
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).is_contiguous());
        });
    });

    group.bench_function("Ipv6Network::is_contiguous contiguous", |b| {
        let net = Ipv6Network::parse("2001:db8::/32").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).is_contiguous());
        });
    });

    group.bench_function("Ipv6Network::is_contiguous non-contiguous", |b| {
        let net = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xffff, 0, 0, 0, 0, 0, 0, 0xffff),
        );
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).is_contiguous());
        });
    });

    group.finish();
}

fn bench_is_bicontiguous(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.bench_function("Ipv6Network::is_bicontiguous bi-contiguous", |b| {
        let net = Ipv6Network::parse("2a02:1a1:c00::1234:abcd:0:0/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).is_bicontiguous());
        });
    });

    group.bench_function("Ipv6Network::is_bicontiguous non-bicontiguous", |b| {
        let net = Ipv6Network::new(
            Ipv6Addr::new(0xf0f0, 0xf0f0, 0xf0f0, 0xf0f0, 0, 0, 0, 0),
            Ipv6Addr::new(0xf0f0, 0xf0f0, 0xf0f0, 0xf0f0, 0, 0, 0, 0),
        );
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).is_bicontiguous());
        });
    });

    group.finish();
}

fn bench_aggregate(c: &mut Criterion) {
    use netip::{ipv4_aggregate, ipv6_aggregate};

    // Host route whose bit pattern always has an even popcount. XOR-ing any
    // two even-popcount values yields an even popcount too, which can never
    // equal 1 — so no two of these addresses are single-bit (sibling) pairs,
    // and since every network shares the same all-ones mask, none can
    // contain another either. `aggregate` is left with nothing to merge, so
    // each candidate pays the full O(current stack size) scan for nothing:
    // this is the worst case, Theta(N^2), for the single-pass collapse loop.
    fn never_merges_host(i: u32) -> u32 {
        let host = 2 * i;
        if host.count_ones().is_multiple_of(2) {
            host
        } else {
            host + 1
        }
    }

    fn ipv4_never_merges(count: u32) -> Vec<Ipv4Network> {
        (0..count)
            .map(|i| Ipv4Network::from_bits((10u32 << 24) | never_merges_host(i), 0xFFFFFFFF))
            .collect()
    }

    fn ipv6_never_merges(count: u32) -> Vec<Ipv6Network> {
        (0..count)
            .map(|i| Ipv6Network::from_bits((0x2001_0db8u128 << 96) | never_merges_host(i) as u128, !0u128))
            .collect()
    }

    let mut group = c.benchmark_group("netip");

    group.throughput(Throughput::Elements(256));
    group.bench_function("ipv4_aggregate 256x /24 -> /16", |b| {
        let template: Vec<Ipv4Network> = (0..=255u32)
            .map(|i| Ipv4Network::from_bits((192 << 24) | (168 << 16) | (i << 8), 0xFFFFFF00))
            .collect();
        b.iter_batched(
            || template.clone(),
            |mut nets| {
                core::hint::black_box(ipv4_aggregate(&mut nets));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.throughput(Throughput::Elements(1024));
    group.bench_function("ipv4_aggregate 1024 random /20../28", |b| {
        let template: Vec<Ipv4Network> = (0..1024u32)
            .map(|i| {
                let prefix = 20 + (i % 9);
                let mask = !0u32 << (32 - prefix);
                let addr = ((10u32 << 24) | (i.wrapping_mul(97) % (1 << 24))) & mask;
                Ipv4Network::from_bits(addr, mask)
            })
            .collect();
        b.iter_batched(
            || template.clone(),
            |mut nets| {
                core::hint::black_box(ipv4_aggregate(&mut nets));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.throughput(Throughput::Elements(256));
    group.bench_function("ipv6_aggregate 256x /48 -> /40", |b| {
        let template: Vec<Ipv6Network> = (0..=255u128)
            .map(|i| {
                let addr = (0x2001_0db8u128 << 96) | (i << 80);
                let mask = !0u128 << 80;
                Ipv6Network::from_bits(addr, mask)
            })
            .collect();
        b.iter_batched(
            || template.clone(),
            |mut nets| {
                core::hint::black_box(ipv6_aggregate(&mut nets));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.throughput(Throughput::Elements(1024));
    group.bench_function("ipv4_aggregate 1024x /32 never-merges", |b| {
        let template = ipv4_never_merges(1024);
        b.iter_batched(
            || template.clone(),
            |mut nets| {
                core::hint::black_box(ipv4_aggregate(&mut nets));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.throughput(Throughput::Elements(256));
    group.bench_function("ipv4_aggregate 256x /32 never-merges", |b| {
        let template = ipv4_never_merges(256);
        b.iter_batched(
            || template.clone(),
            |mut nets| {
                core::hint::black_box(ipv4_aggregate(&mut nets));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.throughput(Throughput::Elements(1024));
    group.bench_function("ipv6_aggregate 1024x /128 never-merges", |b| {
        let template = ipv6_never_merges(1024);
        b.iter_batched(
            || template.clone(),
            |mut nets| {
                core::hint::black_box(ipv6_aggregate(&mut nets));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.throughput(Throughput::Elements(256));
    group.bench_function("ipv6_aggregate 256x /128 never-merges", |b| {
        let template = ipv6_never_merges(256);
        b.iter_batched(
            || template.clone(),
            |mut nets| {
                core::hint::black_box(ipv6_aggregate(&mut nets));
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.finish();
}

fn bench_aggregate_contiguous(c: &mut Criterion) {
    use criterion::BenchmarkId;
    use netip::{Contiguous, ipv4_aggregate, ipv4_aggregate_contiguous, ipv6_aggregate, ipv6_aggregate_contiguous};

    // Host route whose bit pattern always has an even popcount, so no two are
    // single-bit (buddy) siblings and — sharing the same /32 mask — none
    // contains another. The general aggregate pays its worst-case quadratic
    // full-stack scan on these, while the contiguous pass stays O(N log N).
    fn never_merges_host(i: u32) -> u32 {
        let host = 2 * i;
        if host.count_ones().is_multiple_of(2) {
            host
        } else {
            host + 1
        }
    }

    fn ipv4_never_merges_plain(count: u32) -> Vec<Ipv4Network> {
        (0..count)
            .map(|i| Ipv4Network::from_bits((10u32 << 24) | never_merges_host(i), 0xFFFFFFFF))
            .collect()
    }

    fn ipv4_never_merges_contiguous(count: u32) -> Vec<Contiguous<Ipv4Network>> {
        (0..count)
            .map(|i| {
                let addr = Ipv4Addr::from_bits((10u32 << 24) | never_merges_host(i));
                Contiguous::<Ipv4Network>::parse(&format!("{addr}/32")).unwrap()
            })
            .collect()
    }

    // `count` consecutive aligned /24 blocks that tile a single parent and, for
    // power-of-two counts, aggregate all the way down to it.
    fn ipv4_cascade_plain(count: u32) -> Vec<Ipv4Network> {
        (0..count)
            .map(|i| Ipv4Network::from_bits((10u32 << 24) | (i << 8), 0xFFFFFF00))
            .collect()
    }

    fn ipv4_cascade_contiguous(count: u32) -> Vec<Contiguous<Ipv4Network>> {
        (0..count)
            .map(|i| {
                let addr = Ipv4Addr::from_bits((10u32 << 24) | (i << 8));
                Contiguous::<Ipv4Network>::parse(&format!("{addr}/24")).unwrap()
            })
            .collect()
    }

    fn ipv6_never_merges_plain(count: u32) -> Vec<Ipv6Network> {
        (0..count)
            .map(|i| Ipv6Network::from_bits((0x2001_0db8u128 << 96) | never_merges_host(i) as u128, !0u128))
            .collect()
    }

    fn ipv6_never_merges_contiguous(count: u32) -> Vec<Contiguous<Ipv6Network>> {
        (0..count)
            .map(|i| {
                let addr = Ipv6Addr::from_bits((0x2001_0db8u128 << 96) | never_merges_host(i) as u128);
                Contiguous::<Ipv6Network>::parse(&format!("{addr}/128")).unwrap()
            })
            .collect()
    }

    fn ipv6_cascade_plain(count: u32) -> Vec<Ipv6Network> {
        (0..count)
            .map(|i| Ipv6Network::from_bits((0x2001_0db8u128 << 96) | ((i as u128) << 8), !0u128 << 8))
            .collect()
    }

    fn ipv6_cascade_contiguous(count: u32) -> Vec<Contiguous<Ipv6Network>> {
        (0..count)
            .map(|i| {
                let addr = Ipv6Addr::from_bits((0x2001_0db8u128 << 96) | ((i as u128) << 8));
                Contiguous::<Ipv6Network>::parse(&format!("{addr}/120")).unwrap()
            })
            .collect()
    }

    let mut group = c.benchmark_group("netip");

    for &size in &[1024u32, 4096, 16384] {
        group.throughput(Throughput::Elements(size as u64));

        let template = ipv4_never_merges_plain(size);
        group.bench_with_input(
            BenchmarkId::new("ipv4_aggregate never-merges", size),
            &template,
            |b, template| {
                b.iter_batched(
                    || template.clone(),
                    |mut nets| core::hint::black_box(ipv4_aggregate(&mut nets)).len(),
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        let template = ipv4_never_merges_contiguous(size);
        group.bench_with_input(
            BenchmarkId::new("ipv4_aggregate_contiguous never-merges", size),
            &template,
            |b, template| {
                b.iter_batched(
                    || template.clone(),
                    |mut nets| core::hint::black_box(ipv4_aggregate_contiguous(&mut nets)).len(),
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        let template = ipv4_cascade_plain(size);
        group.bench_with_input(
            BenchmarkId::new("ipv4_aggregate cascade", size),
            &template,
            |b, template| {
                b.iter_batched(
                    || template.clone(),
                    |mut nets| core::hint::black_box(ipv4_aggregate(&mut nets)).len(),
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        let template = ipv4_cascade_contiguous(size);
        group.bench_with_input(
            BenchmarkId::new("ipv4_aggregate_contiguous cascade", size),
            &template,
            |b, template| {
                b.iter_batched(
                    || template.clone(),
                    |mut nets| core::hint::black_box(ipv4_aggregate_contiguous(&mut nets)).len(),
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        let template = ipv6_never_merges_plain(size);
        group.bench_with_input(
            BenchmarkId::new("ipv6_aggregate never-merges", size),
            &template,
            |b, template| {
                b.iter_batched(
                    || template.clone(),
                    |mut nets| core::hint::black_box(ipv6_aggregate(&mut nets)).len(),
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        let template = ipv6_never_merges_contiguous(size);
        group.bench_with_input(
            BenchmarkId::new("ipv6_aggregate_contiguous never-merges", size),
            &template,
            |b, template| {
                b.iter_batched(
                    || template.clone(),
                    |mut nets| core::hint::black_box(ipv6_aggregate_contiguous(&mut nets)).len(),
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        let template = ipv6_cascade_plain(size);
        group.bench_with_input(
            BenchmarkId::new("ipv6_aggregate cascade", size),
            &template,
            |b, template| {
                b.iter_batched(
                    || template.clone(),
                    |mut nets| core::hint::black_box(ipv6_aggregate(&mut nets)).len(),
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        let template = ipv6_cascade_contiguous(size);
        group.bench_with_input(
            BenchmarkId::new("ipv6_aggregate_contiguous cascade", size),
            &template,
            |b, template| {
                b.iter_batched(
                    || template.clone(),
                    |mut nets| core::hint::black_box(ipv6_aggregate_contiguous(&mut nets)).len(),
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_bicontiguous_aggregate(c: &mut Criterion) {
    use criterion::BenchmarkId;
    use netip::{BiContiguous, ipv6_aggregate, ipv6_aggregate_bicontiguous};

    // Top `prefix` bits of a 64-bit half set to one, the rest zero.
    fn half_prefix_mask(prefix: u8) -> u64 {
        !u64::MAX.checked_shr(prefix as u32).unwrap_or(0)
    }

    fn shape_mask(hi_prefix: u8, lo_prefix: u8) -> u128 {
        ((half_prefix_mask(hi_prefix) as u128) << 64) | half_prefix_mask(lo_prefix) as u128
    }

    // Distinct networks spread across `shape_count` deep `(hi_prefix,
    // lo_prefix)` shapes with a distinct address each. Nothing merges and
    // nothing contains anything, so the level sweep only sorts and Phase C
    // probes without dropping -- the honest worst case, on which the general
    // `ipv6_aggregate` pays its quadratic full-stack scan.
    fn never_merges(count: u64, shape_count: u64) -> Vec<BiContiguous<Ipv6Network>> {
        (0..count)
            .map(|index| {
                let shape = index % shape_count;
                let hi_prefix = (20 + (shape * 7) % 44) as u8;
                let lo_prefix = (20 + (shape * 11) % 44) as u8;
                let hi = index.wrapping_mul(0x9E37_79B9_7F4A_7C15);
                let lo = index.wrapping_mul(0xBF58_476D_1CE4_E5B9) ^ 0xABCD_EF01_2345_6789;
                let mask = shape_mask(hi_prefix, lo_prefix);
                let addr = ((hi as u128) << 64) | lo as u128;
                BiContiguous::try_from(Ipv6Network::from_bits(addr & mask, mask)).unwrap()
            })
            .collect()
    }

    // Realistic masks: hi half /40 (a "site"), lo half /32 or /16, shared
    // across a small pool of sites. Every site's /32 low half nests in its /16
    // low half, so the containment sweep does real work while the shape count
    // stays tiny.
    fn geo(count: u64) -> Vec<BiContiguous<Ipv6Network>> {
        let site_count = (count / 50).clamp(4, 2000);
        (0..count)
            .map(|index| {
                let site = index % site_count;
                let hi = site.wrapping_mul(0x9E37_79B9_7F4A_7C15);
                let lo = index.wrapping_mul(0xBF58_476D_1CE4_E5B9);
                let lo_prefix: u8 = if index.is_multiple_of(2) { 32 } else { 16 };
                let mask = shape_mask(40, lo_prefix);
                let addr = ((hi as u128) << 64) | lo as u128;
                BiContiguous::try_from(Ipv6Network::from_bits(addr & mask, mask)).unwrap()
            })
            .collect()
    }

    // A dense grid of `(48, 48)` rectangles tiling one parent: 64 consecutive
    // low buddies under each of `count / 64` consecutive high buddies. Phase A
    // collapses each high block's low buddies, then Phase B merges the high
    // buddies -- the merge-heavy case that drives the sweep, not the
    // containment sweep.
    fn mergeable_grid(count: u64) -> Vec<BiContiguous<Ipv6Network>> {
        let mask = shape_mask(48, 48);
        (0..count)
            .map(|index| {
                let hi_index = index / 64;
                let lo_index = index % 64;
                let hi = 0x2001_0db8_0000_0000u64 | (hi_index << 16);
                let lo = lo_index << 16;
                let addr = ((hi as u128) << 64) | lo as u128;
                BiContiguous::try_from(Ipv6Network::from_bits(addr & mask, mask)).unwrap()
            })
            .collect()
    }

    // A hi-buddy chain threading down through the high-half prefix levels 64
    // to 9, alongside a large inert block of never-merging networks pinned to
    // high-half prefix 4. The chain's top bit stays fixed at `1` throughout
    // -- only lower bits change as it re-parents -- while the inert block's
    // top bit is always `0`, so neither can ever contain the other. This is
    // the case a localized re-sort accelerates: the pre-optimization
    // full-slice re-sort ran once per re-parenting level, paying for the
    // whole inert block every time, even though only the chain's own small
    // neighborhood ever changes order.
    fn resort_cascade(count: u64) -> Vec<BiContiguous<Ipv6Network>> {
        const CASCADE_FLOOR: u8 = 8;
        const MARKER: u64 = 1 << 63;

        let mut nets = Vec::with_capacity(count as usize);

        let finest_mask = shape_mask(64, 0);
        nets.push(BiContiguous::try_from(Ipv6Network::from_bits((MARKER as u128) << 64, finest_mask)).unwrap());
        nets.push(BiContiguous::try_from(Ipv6Network::from_bits(((MARKER | 1) as u128) << 64, finest_mask)).unwrap());
        for p in (CASCADE_FLOOR + 1)..64 {
            let buddy_bit = 1u64 << (64 - p);
            let mask = shape_mask(p, 0);
            let addr = ((MARKER | buddy_bit) as u128) << 64;
            nets.push(BiContiguous::try_from(Ipv6Network::from_bits(addr, mask)).unwrap());
        }

        let inert_count = count.saturating_sub(nets.len() as u64);
        let shape_count = 16u64.min(inert_count.max(1));
        for index in 0..inert_count {
            let shape = index % shape_count;
            let lo_prefix = (20 + (shape * 11) % 44) as u8;
            let mask = shape_mask(4, lo_prefix);
            let lo = index.wrapping_mul(0xBF58_476D_1CE4_E5B9) ^ 0xABCD_EF01_2345_6789;
            let addr = lo as u128;
            nets.push(BiContiguous::try_from(Ipv6Network::from_bits(addr & mask, mask)).unwrap());
        }

        nets
    }

    // Many distinct shapes with real cross-shape containment, sized to keep
    // post-sweep survivor counts in the low-hundreds -- the region the removed
    // small-N routing threshold (`CONTAINMENT_THRESHOLD`, formerly 96; see
    // `bicontiguous_find_containment`'s doc comment in
    // `src/net/bicontiguous.rs`) used to switch paths in. One wildcard
    // ancestor (`hi_prefix` 8, `lo_prefix` 0) contains every even-indexed
    // descendant; every odd-indexed descendant gets its own distinct shape and
    // survives, so Phase C's containment sweep does real work against a wide
    // shape fan instead of trivially passing every network through.
    fn containment_small(count: u64) -> Vec<BiContiguous<Ipv6Network>> {
        let container_mask = shape_mask(8, 0);
        let mut nets = Vec::with_capacity(count as usize);
        nets.push(BiContiguous::try_from(Ipv6Network::from_bits(0, container_mask)).unwrap());

        for index in 1..count {
            let tag = if index.is_multiple_of(2) { 0u64 } else { index & 0xFF };
            let hi_prefix = 9 + (index % 56) as u8;
            let lo_prefix = (index % 65) as u8;
            let mask = shape_mask(hi_prefix, lo_prefix);
            let hi = (tag << 56) | (index.wrapping_mul(0x9E37_79B9_7F4A_7C15) & 0x00FF_FFFF_FFFF_FFFF);
            let lo = index.wrapping_mul(0xBF58_476D_1CE4_E5B9) ^ 0xABCD_EF01_2345_6789;
            let addr = ((hi as u128) << 64) | lo as u128;
            nets.push(BiContiguous::try_from(Ipv6Network::from_bits(addr & mask, mask)).unwrap());
        }

        nets
    }

    let mut group = c.benchmark_group("netip");

    // Small-N containment-heavy fixture only, kept out of the main size loop
    // below so total bench time stays in check.
    for &size in &[16u64, 64, 256] {
        group.throughput(Throughput::Elements(size));

        let template = containment_small(size);
        group.bench_with_input(
            BenchmarkId::new("ipv6_aggregate_bicontiguous containment-small", size),
            &template,
            |b, template| {
                b.iter_batched(
                    || template.clone(),
                    |mut nets| core::hint::black_box(ipv6_aggregate_bicontiguous(&mut nets)).len(),
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    for &size in &[1024u64, 4096, 16384] {
        group.throughput(Throughput::Elements(size));

        let template = never_merges(size, 16);
        group.bench_with_input(
            BenchmarkId::new("ipv6_aggregate_bicontiguous never-merges", size),
            &template,
            |b, template| {
                b.iter_batched(
                    || template.clone(),
                    |mut nets| core::hint::black_box(ipv6_aggregate_bicontiguous(&mut nets)).len(),
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        let template: Vec<Ipv6Network> = never_merges(size, 16).iter().map(|net| **net).collect();
        group.bench_with_input(
            BenchmarkId::new("ipv6_aggregate never-merges", size),
            &template,
            |b, template| {
                b.iter_batched(
                    || template.clone(),
                    |mut nets| core::hint::black_box(ipv6_aggregate(&mut nets)).len(),
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        let template = geo(size);
        group.bench_with_input(
            BenchmarkId::new("ipv6_aggregate_bicontiguous geo", size),
            &template,
            |b, template| {
                b.iter_batched(
                    || template.clone(),
                    |mut nets| core::hint::black_box(ipv6_aggregate_bicontiguous(&mut nets)).len(),
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        let template = mergeable_grid(size);
        group.bench_with_input(
            BenchmarkId::new("ipv6_aggregate_bicontiguous mergeable-grid", size),
            &template,
            |b, template| {
                b.iter_batched(
                    || template.clone(),
                    |mut nets| core::hint::black_box(ipv6_aggregate_bicontiguous(&mut nets)).len(),
                    criterion::BatchSize::SmallInput,
                );
            },
        );

        let template = resort_cascade(size);
        group.bench_with_input(
            BenchmarkId::new("ipv6_aggregate_bicontiguous resort-cascade", size),
            &template,
            |b, template| {
                b.iter_batched(
                    || template.clone(),
                    |mut nets| core::hint::black_box(ipv6_aggregate_bicontiguous(&mut nets)).len(),
                    criterion::BatchSize::SmallInput,
                );
            },
        );
    }

    group.finish();
}

fn bench_binary_split(c: &mut Criterion) {
    use netip::{ipv4_binary_split, ipv6_binary_split};

    fn ipv4_consecutive(count: u32, prefix: u32) -> Vec<Ipv4Network> {
        let step = 1u32 << (32 - prefix);
        let mut nets: Vec<Ipv4Network> = (0..count)
            .map(|i| {
                let base = i * step;
                let o1 = (base >> 16) & 0xFF;
                let o2 = (base >> 8) & 0xFF;
                let o3 = base & 0xFF;
                Ipv4Network::parse(&format!("10.{o1}.{o2}.{o3}/{prefix}")).unwrap()
            })
            .collect();
        nets.sort();
        nets.dedup();
        nets
    }

    fn ipv6_consecutive(count: u32, prefix: u32) -> Vec<Ipv6Network> {
        let step = 1u32 << (128 - prefix);
        let mut nets: Vec<Ipv6Network> = (0..count)
            .map(|i| {
                let last = i * step;
                Ipv6Network::parse(&format!("2001:db8::{last:x}/{prefix}")).unwrap()
            })
            .collect();
        nets.sort();
        nets.dedup();
        nets
    }

    // Mask "255.255.0.255" leaves a hole in the third octet, so networks that
    // only differ in the fixed last octet do not overlap.
    fn ipv4_non_contiguous(count: u32) -> Vec<Ipv4Network> {
        let mut nets: Vec<Ipv4Network> = (0..count)
            .map(|i| Ipv4Network::parse(&format!("10.0.0.{i}/255.255.0.255")).unwrap())
            .collect();
        nets.sort();
        nets.dedup();
        nets
    }

    // Mask "ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff" leaves an 8-bit hole in
    // the third group, so networks that only differ in the fixed last group
    // do not overlap.
    fn ipv6_non_contiguous(count: u32) -> Vec<Ipv6Network> {
        let mut nets: Vec<Ipv6Network> = (0..count)
            .map(|i| {
                Ipv6Network::parse(&format!("2001:db8:c00::{i:x}/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff")).unwrap()
            })
            .collect();
        nets.sort();
        nets.dedup();
        nets
    }

    let mut group = c.benchmark_group("netip");

    group.throughput(Throughput::Elements(16));
    group.bench_function("ipv4_binary_split 16x /28", |b| {
        let nets = ipv4_consecutive(16, 28);
        b.iter(|| {
            core::hint::black_box(ipv4_binary_split(core::hint::black_box(&nets)));
        });
    });

    group.throughput(Throughput::Elements(64));
    group.bench_function("ipv4_binary_split 64x /28", |b| {
        let nets = ipv4_consecutive(64, 28);
        b.iter(|| {
            core::hint::black_box(ipv4_binary_split(core::hint::black_box(&nets)));
        });
    });

    group.throughput(Throughput::Elements(256));
    group.bench_function("ipv4_binary_split 256x /28", |b| {
        let nets = ipv4_consecutive(256, 28);
        b.iter(|| {
            core::hint::black_box(ipv4_binary_split(core::hint::black_box(&nets)));
        });
    });

    group.throughput(Throughput::Elements(1024));
    group.bench_function("ipv4_binary_split 1024x /28", |b| {
        let nets = ipv4_consecutive(1024, 28);
        b.iter(|| {
            core::hint::black_box(ipv4_binary_split(core::hint::black_box(&nets)));
        });
    });

    group.throughput(Throughput::Elements(256));
    group.bench_function("ipv4_binary_split 256x non-contiguous", |b| {
        let nets = ipv4_non_contiguous(256);
        b.iter(|| {
            core::hint::black_box(ipv4_binary_split(core::hint::black_box(&nets)));
        });
    });

    group.throughput(Throughput::Elements(16));
    group.bench_function("ipv6_binary_split 16x /124", |b| {
        let nets = ipv6_consecutive(16, 124);
        b.iter(|| {
            core::hint::black_box(ipv6_binary_split(core::hint::black_box(&nets)));
        });
    });

    group.throughput(Throughput::Elements(64));
    group.bench_function("ipv6_binary_split 64x /124", |b| {
        let nets = ipv6_consecutive(64, 124);
        b.iter(|| {
            core::hint::black_box(ipv6_binary_split(core::hint::black_box(&nets)));
        });
    });

    group.throughput(Throughput::Elements(256));
    group.bench_function("ipv6_binary_split 256x /124", |b| {
        let nets = ipv6_consecutive(256, 124);
        b.iter(|| {
            core::hint::black_box(ipv6_binary_split(core::hint::black_box(&nets)));
        });
    });

    group.throughput(Throughput::Elements(1024));
    group.bench_function("ipv6_binary_split 1024x /124", |b| {
        let nets = ipv6_consecutive(1024, 124);
        b.iter(|| {
            core::hint::black_box(ipv6_binary_split(core::hint::black_box(&nets)));
        });
    });

    group.throughput(Throughput::Elements(256));
    group.bench_function("ipv6_binary_split 256x non-contiguous", |b| {
        let nets = ipv6_non_contiguous(256);
        b.iter(|| {
            core::hint::black_box(ipv6_binary_split(core::hint::black_box(&nets)));
        });
    });

    group.finish();
}

// Regression guard: `supernet_for`'s fold is auto-vectorized by LLVM for
// `Ipv4Network` (8-wide SSE with a byte-shuffle transpose) but stays scalar
// for `Ipv6Network`; these benches make that per-element cost gap visible so
// a change that silently defeats vectorization (e.g. an early exit) shows up
// as a measured regression rather than going unnoticed.
fn bench_supernet_for(c: &mut Criterion) {
    // Consecutive /28s that all share the "10.0.0.0/16" prefix, so the fold
    // mask never collapses to zero: this is the realistic "summarize related
    // networks" case.
    fn ipv4_related(count: u32) -> Vec<Ipv4Network> {
        (0..count)
            .map(|i| {
                let host = i * 16;
                let o2 = (host >> 8) & 0xFF;
                let o3 = host & 0xFF;
                Ipv4Network::parse(&format!("10.0.{o2}.{o3}/28")).unwrap()
            })
            .collect()
    }

    // Consecutive /124s that all share the "2001:db8:1::/48" prefix.
    fn ipv6_related(count: u32) -> Vec<Ipv6Network> {
        (0..count)
            .map(|i| {
                let host = i * 16;
                Ipv6Network::parse(&format!("2001:db8:1::{host:x}/124")).unwrap()
            })
            .collect()
    }

    // Mask "255.255.0.255" leaves a hole in the third octet, so networks
    // differing only there do not affect the fold.
    fn ipv4_related_non_contiguous(count: u32) -> Vec<Ipv4Network> {
        (0..count)
            .map(|i| {
                let o1 = (i >> 8) & 0xFF;
                let o3 = i & 0xFF;
                Ipv4Network::parse(&format!("10.{o1}.0.{o3}/255.255.0.255")).unwrap()
            })
            .collect()
    }

    // Mask "ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff" leaves an 8-bit hole in
    // the third group, so networks differing only there do not affect the fold.
    fn ipv6_related_non_contiguous(count: u32) -> Vec<Ipv6Network> {
        (0..count)
            .map(|i| {
                Ipv6Network::parse(&format!("2001:db8:c00::{i:x}/ffff:ffff:ff00:ffff:ffff:ffff:ffff:ffff")).unwrap()
            })
            .collect()
    }

    let mut group = c.benchmark_group("netip");

    group.throughput(Throughput::Elements(64));
    group.bench_function("Ipv4Network::supernet_for 64x /28", |b| {
        let nets = ipv4_related(64);
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&nets[0]).supernet_for(core::hint::black_box(&nets[1..])));
        });
    });

    group.throughput(Throughput::Elements(1024));
    group.bench_function("Ipv4Network::supernet_for 1024x /28", |b| {
        let nets = ipv4_related(1024);
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&nets[0]).supernet_for(core::hint::black_box(&nets[1..])));
        });
    });

    group.throughput(Throughput::Elements(64));
    group.bench_function("Ipv6Network::supernet_for 64x /124", |b| {
        let nets = ipv6_related(64);
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&nets[0]).supernet_for(core::hint::black_box(&nets[1..])));
        });
    });

    group.throughput(Throughput::Elements(1024));
    group.bench_function("Ipv6Network::supernet_for 1024x /124", |b| {
        let nets = ipv6_related(1024);
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&nets[0]).supernet_for(core::hint::black_box(&nets[1..])));
        });
    });

    group.throughput(Throughput::Elements(1024));
    group.bench_function("Ipv4Network::supernet_for 1024x non-contiguous", |b| {
        let nets = ipv4_related_non_contiguous(1024);
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&nets[0]).supernet_for(core::hint::black_box(&nets[1..])));
        });
    });

    group.throughput(Throughput::Elements(1024));
    group.bench_function("Ipv6Network::supernet_for 1024x non-contiguous", |b| {
        let nets = ipv6_related_non_contiguous(1024);
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&nets[0]).supernet_for(core::hint::black_box(&nets[1..])));
        });
    });

    group.finish();
}

fn bench_difference(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.throughput(Throughput::Elements(32));
    group.bench_function("Ipv4Network::difference universe minus host", |b| {
        let source = Ipv4Network::parse("0.0.0.0/0").unwrap();
        let other = Ipv4Network::parse("1.2.3.4/32").unwrap();
        b.iter(|| {
            for net in core::hint::black_box(&source).difference(core::hint::black_box(&other)) {
                core::hint::black_box(net);
            }
        });
    });

    group.throughput(Throughput::Elements(128));
    group.bench_function("Ipv6Network::difference universe minus host", |b| {
        let source = Ipv6Network::parse("::/0").unwrap();
        let other = Ipv6Network::parse("2001:db8::1/128").unwrap();
        b.iter(|| {
            for net in core::hint::black_box(&source).difference(core::hint::black_box(&other)) {
                core::hint::black_box(net);
            }
        });
    });

    group.finish();
}

fn bench_difference_count(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.bench_function("Ipv4Network::difference count", |b| {
        let source = Ipv4Network::parse("0.0.0.0/0").unwrap();
        let other = Ipv4Network::parse("1.2.3.4/32").unwrap();
        b.iter(|| {
            let diff = core::hint::black_box(&source).difference(core::hint::black_box(&other));
            core::hint::black_box(diff.count());
        });
    });

    group.bench_function("Ipv6Network::difference count", |b| {
        let source = Ipv6Network::parse("::/0").unwrap();
        let other = Ipv6Network::parse("2001:db8::1/128").unwrap();
        b.iter(|| {
            let diff = core::hint::black_box(&source).difference(core::hint::black_box(&other));
            core::hint::black_box(diff.count());
        });
    });

    group.finish();
}

fn bench_difference_rev(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.throughput(Throughput::Elements(32));
    group.bench_function("Ipv4Network::difference rev universe minus host", |b| {
        let source = Ipv4Network::parse("0.0.0.0/0").unwrap();
        let other = Ipv4Network::parse("1.2.3.4/32").unwrap();
        b.iter(|| {
            for net in core::hint::black_box(&source)
                .difference(core::hint::black_box(&other))
                .rev()
            {
                core::hint::black_box(net);
            }
        });
    });

    group.throughput(Throughput::Elements(128));
    group.bench_function("Ipv6Network::difference rev universe minus host", |b| {
        let source = Ipv6Network::parse("::/0").unwrap();
        let other = Ipv6Network::parse("2001:db8::1/128").unwrap();
        b.iter(|| {
            for net in core::hint::black_box(&source)
                .difference(core::hint::black_box(&other))
                .rev()
            {
                core::hint::black_box(net);
            }
        });
    });

    group.finish();
}

fn bench_difference_last(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.bench_function("Ipv4Network::difference last", |b| {
        let source = Ipv4Network::parse("0.0.0.0/0").unwrap();
        let other = Ipv4Network::parse("1.2.3.4/32").unwrap();
        b.iter(|| {
            let diff = core::hint::black_box(&source).difference(core::hint::black_box(&other));
            core::hint::black_box(diff.last());
        });
    });

    group.bench_function("Ipv6Network::difference last", |b| {
        let source = Ipv6Network::parse("::/0").unwrap();
        let other = Ipv6Network::parse("2001:db8::1/128").unwrap();
        b.iter(|| {
            let diff = core::hint::black_box(&source).difference(core::hint::black_box(&other));
            core::hint::black_box(diff.last());
        });
    });

    group.finish();
}

fn bench_range_to_networks(c: &mut Criterion) {
    use netip::{ipv4_range_to_networks, ipv6_range_to_networks};

    let mut group = c.benchmark_group("netip");

    // Misaligned at both ends: `first = 1` has no trailing zero bits and
    // `last = u32::MAX - 1` is not block-aligned either, forcing the
    // documented worst case of `2 * 32 - 2 = 62` blocks.
    group.throughput(Throughput::Elements(62));
    group.bench_function("ipv4_range_to_networks misaligned worst-case", |b| {
        let first = Ipv4Addr::from_bits(1);
        let last = Ipv4Addr::from_bits(u32::MAX - 1);
        b.iter(|| {
            for net in ipv4_range_to_networks(core::hint::black_box(first), core::hint::black_box(last)) {
                core::hint::black_box(net);
            }
        });
    });

    // Same construction as above, forcing the documented worst case of
    // `2 * 128 - 2 = 254` blocks.
    group.throughput(Throughput::Elements(254));
    group.bench_function("ipv6_range_to_networks misaligned worst-case", |b| {
        let first = Ipv6Addr::from_bits(1);
        let last = Ipv6Addr::from_bits(u128::MAX - 1);
        b.iter(|| {
            for net in ipv6_range_to_networks(core::hint::black_box(first), core::hint::black_box(last)) {
                core::hint::black_box(net);
            }
        });
    });

    group.finish();
}

fn bench_to_ipv4_mapped(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.bench_function("Ipv6Network::to_ipv4_mapped contiguous", |b| {
        let net = Ipv6Network::parse("::ffff:192.168.1.0/120").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).to_ipv4_mapped());
        });
    });

    group.bench_function("Ipv6Network::to_ipv4_mapped non-contiguous", |b| {
        let net = Ipv6Network::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 1),
            Ipv6Addr::new(0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xff00),
        );
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).to_ipv4_mapped());
        });
    });

    group.bench_function("Ipv6Network::to_ipv4_mapped not mapped", |b| {
        let net = Ipv6Network::parse("2001:db8::/32").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).to_ipv4_mapped());
        });
    });

    group.finish();
}

fn bench_to_contiguous(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.bench_function("Ipv4Network::to_contiguous contiguous", |b| {
        let net = Ipv4Network::parse("192.168.0.0/16").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).to_contiguous());
        });
    });

    group.bench_function("Ipv4Network::to_contiguous non-contiguous", |b| {
        let net = Ipv4Network::new(Ipv4Addr::new(192, 168, 0, 1), Ipv4Addr::new(255, 255, 0, 255));
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).to_contiguous());
        });
    });

    group.bench_function("Ipv6Network::to_contiguous contiguous", |b| {
        let net = Ipv6Network::parse("2001:db8::/32").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).to_contiguous());
        });
    });

    group.bench_function("Ipv6Network::to_contiguous non-contiguous", |b| {
        let net = Ipv6Network::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xffff, 0xffff, 0xff00, 0, 0xffff, 0xffff, 0, 0),
        );
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).to_contiguous());
        });
    });

    group.finish();
}

fn bench_parse(c: &mut Criterion) {
    use netip::IpNetwork;

    let mut group = c.benchmark_group("netip");

    group.bench_function("Ipv4Network::parse CIDR", |b| {
        b.iter(|| core::hint::black_box(Ipv4Network::parse(core::hint::black_box("10.0.0.0/8"))));
    });

    group.bench_function("Ipv4Network::parse dotted mask", |b| {
        b.iter(|| core::hint::black_box(Ipv4Network::parse(core::hint::black_box("10.0.0.0/255.0.0.0"))));
    });

    group.bench_function("Ipv4Network::parse non-contiguous mask", |b| {
        b.iter(|| core::hint::black_box(Ipv4Network::parse(core::hint::black_box("192.168.0.1/255.255.0.255"))));
    });

    group.bench_function("Ipv4Network::parse bare", |b| {
        b.iter(|| core::hint::black_box(Ipv4Network::parse(core::hint::black_box("10.0.0.1"))));
    });

    group.bench_function("Ipv6Network::parse CIDR", |b| {
        b.iter(|| core::hint::black_box(Ipv6Network::parse(core::hint::black_box("2001:db8::/32"))));
    });

    group.bench_function("Ipv6Network::parse full mask", |b| {
        b.iter(|| core::hint::black_box(Ipv6Network::parse(core::hint::black_box("2001:db8::1/ffff:ffff::ffff"))));
    });

    group.bench_function("Ipv6Network::parse bare", |b| {
        b.iter(|| core::hint::black_box(Ipv6Network::parse(core::hint::black_box("2001:db8::1"))));
    });

    // The target case for the `splitn`-to-`split_once` refactor: previously
    // `IpNetwork::parse` re-scanned the buffer for `/` once per family parser
    // it tried, so a v6 string paid for two scans (a failed v4 attempt, then
    // v6). Now the buffer is scanned for `/` exactly once and the parts are
    // reused across both family parsers.
    group.bench_function("IpNetwork::parse v4 CIDR", |b| {
        b.iter(|| core::hint::black_box(IpNetwork::parse(core::hint::black_box("10.0.0.0/8"))));
    });

    group.bench_function("IpNetwork::parse v6 CIDR", |b| {
        b.iter(|| core::hint::black_box(IpNetwork::parse(core::hint::black_box("2001:db8::/32"))));
    });

    group.finish();
}

fn bench_ord(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.throughput(Throughput::Elements(1024));
    group.bench_function("Ipv4Network::sort_unstable 1024 random-ish", |b| {
        let template: Vec<Ipv4Network> = (0..1024u32)
            .map(|i| {
                let bits = i.wrapping_mul(2_654_435_761); // Knuth's multiplicative hash constant
                let prefix = 8 + (bits % 25); // spread prefixes across /8../32
                let o0 = (bits >> 24) & 0xFF;
                let o1 = (bits >> 16) & 0xFF;
                let o2 = (bits >> 8) & 0xFF;
                let o3 = bits & 0xFF;
                Ipv4Network::parse(&format!("{o0}.{o1}.{o2}.{o3}/{prefix}")).unwrap()
            })
            .collect();
        b.iter_batched(
            || template.clone(),
            |mut nets| {
                nets.sort_unstable();
                core::hint::black_box(&nets);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.throughput(Throughput::Elements(1024));
    group.bench_function("Ipv6Network::sort_unstable 1024 random-ish", |b| {
        let template: Vec<Ipv6Network> = (0..1024u32)
            .map(|i| {
                let bits = (i as u128).wrapping_mul(0x9E37_79B9_7F4A_7C15);
                let prefix = 16 + (bits % 113) as u32; // spread prefixes across /16../128
                let g0 = ((bits >> 112) & 0xFFFF) as u16;
                let g1 = ((bits >> 96) & 0xFFFF) as u16;
                let g2 = ((bits >> 80) & 0xFFFF) as u16;
                let g3 = ((bits >> 64) & 0xFFFF) as u16;
                Ipv6Network::parse(&format!("{g0:x}:{g1:x}:{g2:x}:{g3:x}::/{prefix}")).unwrap()
            })
            .collect();
        b.iter_batched(
            || template.clone(),
            |mut nets| {
                nets.sort_unstable();
                core::hint::black_box(&nets);
            },
            criterion::BatchSize::SmallInput,
        );
    });

    group.bench_function("Ipv4Network::cmp", |b| {
        let n0 = Ipv4Network::parse("10.0.0.0/8").unwrap();
        let n1 = Ipv4Network::parse("10.0.0.0/24").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).cmp(core::hint::black_box(&n1)));
        });
    });

    group.bench_function("Ipv6Network::cmp", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/32").unwrap();
        let n1 = Ipv6Network::parse("2001:db8::/48").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&n0).cmp(core::hint::black_box(&n1)));
        });
    });

    group.finish();
}

fn bench_display(c: &mut Criterion) {
    use netip::{IpNetwork, fmt::Compact};

    let mut group = c.benchmark_group("netip");

    group.bench_function("IpNetwork::to_string v4", |b| {
        let net = IpNetwork::parse("10.0.0.0/8").unwrap();
        b.iter(|| core::hint::black_box(core::hint::black_box(&net).to_string()));
    });

    group.bench_function("IpNetwork::to_string v6", |b| {
        let net = IpNetwork::parse("2001:db8::/32").unwrap();
        b.iter(|| core::hint::black_box(core::hint::black_box(&net).to_string()));
    });

    group.bench_function("Ipv4Network::to_string CIDR", |b| {
        let net = Ipv4Network::parse("10.0.0.0/8").unwrap();
        b.iter(|| core::hint::black_box(core::hint::black_box(&net).to_string()));
    });

    group.bench_function("Ipv4Network::to_string non-contiguous", |b| {
        let net = Ipv4Network::parse("192.168.0.1/255.255.0.255").unwrap();
        b.iter(|| core::hint::black_box(core::hint::black_box(&net).to_string()));
    });

    group.bench_function("Ipv6Network::to_string CIDR", |b| {
        let net = Ipv6Network::parse("2001:db8::/32").unwrap();
        b.iter(|| core::hint::black_box(core::hint::black_box(&net).to_string()));
    });

    group.bench_function("Ipv6Network::to_string non-contiguous", |b| {
        let net = Ipv6Network::parse("2001:db8::1/ffff:ffff:ff00::ffff:ffff:0:0").unwrap();
        b.iter(|| core::hint::black_box(core::hint::black_box(&net).to_string()));
    });

    group.bench_function("Compact<Ipv4Network>::to_string", |b| {
        let net = Ipv4Network::parse("10.0.0.0/24").unwrap();
        b.iter(|| core::hint::black_box(Compact(core::hint::black_box(net)).to_string()));
    });

    group.bench_function("Compact<Ipv6Network>::to_string", |b| {
        let net = Ipv6Network::parse("2001:db8::/32").unwrap();
        b.iter(|| core::hint::black_box(Compact(core::hint::black_box(net)).to_string()));
    });

    group.finish();
}

fn bench_prefix(c: &mut Criterion) {
    let mut group = c.benchmark_group("netip");

    group.bench_function("Ipv4Network::prefix contiguous", |b| {
        let net = Ipv4Network::parse("192.168.0.0/16").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).prefix());
        });
    });

    group.bench_function("Ipv4Network::prefix non-contiguous", |b| {
        let net = Ipv4Network::parse("192.168.0.1/255.255.0.255").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).prefix());
        });
    });

    // A 50/50 contiguous/non-contiguous input mix exercises both outcomes of
    // the contiguity check within one measurement.
    group.bench_function("Ipv4Network::prefix mixed", |b| {
        let nets = [
            Ipv4Network::parse("192.168.0.0/16").unwrap(),
            Ipv4Network::parse("192.168.0.1/255.255.0.255").unwrap(),
            Ipv4Network::parse("10.0.0.0/8").unwrap(),
            Ipv4Network::parse("10.0.0.1/255.0.0.255").unwrap(),
        ];
        b.iter(|| {
            for net in core::hint::black_box(&nets) {
                core::hint::black_box(net.prefix());
            }
        });
    });

    group.bench_function("Ipv6Network::prefix contiguous", |b| {
        let net = Ipv6Network::parse("2001:db8::/32").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).prefix());
        });
    });

    group.bench_function("Ipv6Network::prefix non-contiguous", |b| {
        let net = Ipv6Network::parse("2001:db8::1/ffff:ffff::ffff").unwrap();
        b.iter(|| {
            core::hint::black_box(core::hint::black_box(&net).prefix());
        });
    });

    group.bench_function("Ipv6Network::prefix mixed", |b| {
        let nets = [
            Ipv6Network::parse("2001:db8::/32").unwrap(),
            Ipv6Network::parse("2001:db8::1/ffff:ffff::ffff").unwrap(),
            Ipv6Network::parse("2a02:6b8::/48").unwrap(),
            Ipv6Network::parse("2a02:6b8::1/ffff:0:0:0:ffff::").unwrap(),
        ];
        b.iter(|| {
            for net in core::hint::black_box(&nets) {
                core::hint::black_box(net.prefix());
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_net_addrs,
    bench_net_addrs_count,
    bench_intersection,
    bench_contains,
    bench_contiguous_contains,
    bench_contiguous_addrs,
    bench_bicontiguous_addrs,
    bench_bicontiguous_is_contiguous,
    bench_merge,
    bench_is_adjacent,
    bench_is_adjacent_by_lowest_mask_bit,
    bench_merge_by_lowest_mask_bit,
    bench_is_contiguous,
    bench_is_bicontiguous,
    bench_aggregate,
    bench_aggregate_contiguous,
    bench_bicontiguous_aggregate,
    bench_binary_split,
    bench_supernet_for,
    bench_difference,
    bench_difference_count,
    bench_difference_rev,
    bench_difference_last,
    bench_range_to_networks,
    bench_to_ipv4_mapped,
    bench_to_contiguous,
    bench_prefix,
    bench_parse,
    bench_ord,
    bench_display
);
criterion_main!(benches);
