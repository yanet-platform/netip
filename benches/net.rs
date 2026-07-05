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

fn bench_aggregate(c: &mut Criterion) {
    use netip::{ipv4_aggregate, ipv6_aggregate};

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

criterion_group!(
    benches,
    bench_net_addrs,
    bench_net_addrs_count,
    bench_intersection,
    bench_contains,
    bench_merge,
    bench_is_adjacent,
    bench_is_contiguous,
    bench_aggregate,
    bench_binary_split,
    bench_difference,
    bench_difference_count,
    bench_range_to_networks,
    bench_to_ipv4_mapped,
    bench_to_contiguous,
    bench_parse,
    bench_ord,
    bench_display
);
criterion_main!(benches);
