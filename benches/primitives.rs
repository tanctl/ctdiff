use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ctdiff::*;

fn benchmark_ct_bytes_eq(c: &mut Criterion) {
    let data_small = vec![0x42; 32];
    let data_large = vec![0x42; 1024];
    
    c.bench_function("ct_bytes_eq_32", |b| {
        b.iter(|| ct_bytes_eq(black_box(&data_small), black_box(&data_small)))
    });
    
    c.bench_function("ct_bytes_eq_1024", |b| {
        b.iter(|| ct_bytes_eq(black_box(&data_large), black_box(&data_large)))
    });
}

fn benchmark_ct_lookup(c: &mut Criterion) {
    let data = (0..256).map(|i| i as u8).collect::<Vec<_>>();
    
    c.bench_function("ct_lookup_256", |b| {
        b.iter(|| ct_lookup(black_box(&data), black_box(128)))
    });
}

criterion_group!(benches, benchmark_ct_bytes_eq, benchmark_ct_lookup);
criterion_main!(benches);