use criterion::{criterion_group, criterion_main, Criterion};

fn end_to_end(c: &mut Criterion) {
    // TODO: Phase 6 — headline number: sign + witness + 7-fold + finisher.
    c.bench_function("end_to_end_placeholder", |b| {
        b.iter(|| std::hint::black_box(0u64))
    });
}

criterion_group!(benches, end_to_end);
criterion_main!(benches);
