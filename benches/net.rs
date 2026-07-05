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

    group.bench_function("Ipv6Network::merge containment", |b| {
        let n0 = Ipv6Network::parse("2001:db8::/32").unwrap();
        let n1 = Ipv6Network::parse("2001:db8:1::/48").unwrap();
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

    group.finish();
}

criterion_group!(
    benches,
    bench_net_addrs,
    bench_net_addrs_count,
    bench_intersection,
    bench_merge,
    bench_is_adjacent,
    bench_is_contiguous,
    bench_aggregate,
    bench_binary_split,
    bench_ord
);
criterion_main!(benches);
