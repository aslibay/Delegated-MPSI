#![feature(portable_simd)]
#![feature(array_chunks)]
#![feature(int_roundings)]
use std::time::Duration;

use mpc_bench::{comm::FullMesh, Protocol};
use structopt::StructOpt;

use crate::approx_mpsi::ApproximateMpsi;

const SHARE_BYTE_COUNT: usize = 5;

mod approx_mpsi;
mod secret_sharing;

#[derive(StructOpt, Debug)]
#[structopt(name = "delegated-mpsi")]
struct Opt {
    #[structopt(short = "n", long)]
    party_count: usize,
    #[structopt(short = "k", long)]
    set_size: usize,
    #[structopt(short = "u", long)]
    domain_size: usize,
    #[structopt(short = "m", long)]
    bin_count: usize,
    #[structopt(short = "h", long)]
    hash_count: usize,
    #[structopt(short = "l", long)]
    latency: f64,
    #[structopt(short = "b", long)]
    bytes_per_sec: f64,
    #[structopt(short = "r", long)]
    repetitions: usize,
    #[structopt(short = "f", long)]
    results_filename: String,
}

fn main() {
    let opt: Opt = Opt::from_args();
    println!("{:#?}", opt);

    let network_description = if opt.latency == 0. && opt.bytes_per_sec == 0. {
        FullMesh::new()
    } else {
        FullMesh::new_with_overhead(Duration::from_secs_f64(opt.latency), opt.bytes_per_sec)
    };

    let stats = ApproximateMpsi::new(opt.bin_count, opt.hash_count, opt.domain_size, opt.set_size)
        .evaluate(
            "Experiment".to_string(),
            opt.party_count,
            &network_description,
            opt.repetitions,
        );

    stats.output_party_csv(1, opt.results_filename.as_str());
}
