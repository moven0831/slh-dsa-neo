use criterion::{Criterion, criterion_group, criterion_main};

fn single_fold(c: &mut Criterion) {
    // TODO: Phase 3 — bench one HT-layer fold step (486K R1CS).
    c.bench_function("single_fold_ht_layer_486k_placeholder", |b| {
        b.iter(|| std::hint::black_box(0u64))
    });
}

criterion_group!(benches, single_fold);
criterion_main!(benches);
