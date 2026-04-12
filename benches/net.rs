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

    group.throughput(Throughput::Elements(256));
    group.bench_function("Ipv4Network::addrs count /24", |b| {
        let net = Ipv4Network::parse("77.88.55.0/24").unwrap();
        b.iter(|| {
            core::hint::black_box(net.addrs().count());
        });
    });
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

criterion_group!(
    benches,
    bench_net_addrs,
    bench_net_addrs_count,
    bench_intersection,
    bench_merge,
    bench_is_contiguous
);
criterion_main!(benches);
