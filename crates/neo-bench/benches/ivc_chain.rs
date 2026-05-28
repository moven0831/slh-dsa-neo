use criterion::{Criterion, criterion_group, criterion_main};

fn ivc_chain(c: &mut Criterion) {
    // TODO: Phase 4 — bench 7-step IVC chain.
    c.bench_function("ivc_chain_7_step_placeholder", |b| {
        b.iter(|| std::hint::black_box(0u64))
    });
}

criterion_group!(benches, ivc_chain);
criterion_main!(benches);
