use criterion::{Criterion, criterion_group, criterion_main};

fn finisher(c: &mut Criterion) {
    // TODO: Phase 5 — bench Spartan2-GL finisher on accumulated CeClaim.
    c.bench_function("finisher_spartan2_gl_placeholder", |b| {
        b.iter(|| std::hint::black_box(0u64))
    });
}

criterion_group!(benches, finisher);
criterion_main!(benches);
