use mpc_bench::{comm::Channels, statistics::Timings, Party, Protocol};
use rand::{rngs::OsRng, RngCore};

use crate::{
    secret_sharing::{conditionally_corrupt_share, create_zero_share},
    SHARE_BYTE_COUNT,
};
use sets_multisets::{
    bloom_filters::bloom_filter_indices,
    sets::{gen_sets_with_uniform_intersection, Set},
};

use crate::secret_sharing::SimdBytes;

#[derive(Debug, Clone, Copy)]
pub struct ApproximateMpsi {
    bin_count: usize,
    hash_count: usize,
    domain_size: usize,
    set_size: usize,
}

impl ApproximateMpsi {
    pub fn new(
        minimum_bin_count: usize,
        hash_count: usize,
        domain_size: usize,
        set_size: usize,
    ) -> Self {
        ApproximateMpsi {
            bin_count: (minimum_bin_count).div_ceil(64) * 64,
            hash_count,
            domain_size,
            set_size,
        }
    }
}

pub struct ApproximateMpsiParty {
    seeds: Vec<[u8; 16]>,
    bin_count: usize,
    hash_count: usize,
}

impl Party for ApproximateMpsiParty {
    type Input = Option<Set>;
    type Output = Option<Set>;

    fn run(
        &mut self,
        id: usize,
        n_parties: usize,
        input: &Self::Input,
        channels: &mut Channels,
        _timings: &mut Timings,
    ) -> Self::Output {
        match id {
            0 => {
                self.run_server_approx(n_parties, channels);
                None
            }
            1 => Some(self.run_querier_approx(input.as_ref().unwrap(), channels)),
            _ => {
                self.run_client_approx(input.as_ref().unwrap(), channels);
                None
            }
        }
    }
}

impl ApproximateMpsiParty {
    fn run_server_approx(&mut self, n_parties: usize, channels: &mut Channels) {
        // TODO: The server does not have to aggregate all values, but only those relevant for the query
        // Receive all clients' shares
        let mut received_share_iterator = (1..n_parties)
            .map(|id| SimdBytes::from_bytes(&channels.receive(&id).collect::<Vec<_>>()));

        // Aggregate the clients' shares
        // TODO: Check that the shares are the correct size?
        let mut aggregated_share = received_share_iterator.next().unwrap();
        for received_share in received_share_iterator {
            aggregated_share ^= received_share;
        }

        // Receive the query patterns from the querying party
        let query_patterns: Vec<Vec<usize>> =
            bincode::deserialize(&channels.receive(&1).collect::<Vec<u8>>()).unwrap();

        // Identify which shares XOR to 0 and which do not
        let shares: Vec<[u8; 5]> = aggregated_share
            .to_bytes()
            .array_chunks::<SHARE_BYTE_COUNT>()
            .copied()
            .collect();
        let mut results = vec![];
        for query_pattern in query_patterns {
            let mut xor = [0u8; SHARE_BYTE_COUNT];
            for index in query_pattern {
                for (x, y) in xor.iter_mut().zip(&shares[index]) {
                    *x ^= *y;
                }
            }
            results.push(xor == [0u8; SHARE_BYTE_COUNT]);
        }

        // Send the result to the querying party (id = 1)
        channels.send(&bincode::serialize(&results).unwrap(), &1);
    }

    fn run_querier_approx(&mut self, input: &Set, channels: &mut Channels) -> Set {
        // TODO: The querier only has to send the relevant bins
        // The first part of the protocol is identical to that of the other clients
        self.run_client_approx(input, channels);

        // Send the query patterns to the server
        let elements: Vec<usize> = input.elements.iter().copied().collect();
        let query_patterns: Vec<Vec<usize>> = elements
            .iter()
            .map(|element| bloom_filter_indices(element, self.bin_count, self.hash_count).collect())
            .collect();
        channels.send(&bincode::serialize(&query_patterns).unwrap(), &0);

        // Receive the query results from the server
        let reply = channels.receive(&0);
        let reply_vec: Vec<u8> = reply.collect();
        let query_results: Vec<bool> = bincode::deserialize(&reply_vec).unwrap();

        // Find the elements that for which the query result was 1
        Set::from_iter(
            elements
                .iter()
                .zip(query_results)
                .filter(|(_, res)| *res)
                .map(|(element, _)| *element),
        )
    }

    fn run_client_approx(&mut self, input: &Set, channels: &mut Channels) {
        // Encode the set as a permuted Bloom filter
        let bloom_filter = input.to_bloom_filter(self.bin_count, self.hash_count);
        let permuted_bloom_filter = bloom_filter;

        // Create a share that is corrupted whenever there is a 1
        let share = create_zero_share(&self.seeds, SHARE_BYTE_COUNT * self.bin_count);
        let conditional_share = conditionally_corrupt_share(
            share,
            &permuted_bloom_filter
                .into_iter()
                .map(|b| !b)
                .collect::<Vec<_>>(),
        );

        // Send this party's share to the server
        channels.send(&conditional_share.to_bytes(), &0);
    }
}

impl Protocol for ApproximateMpsi {
    type Party = ApproximateMpsiParty;

    fn setup_parties(&self, n_parties: usize) -> Vec<Self::Party> {
        // Setup: Each pair of clients will share a secret value (seed)
        let mut party_seeds: Vec<Vec<[u8; 16]>> = (1..n_parties)
            .map(|_| vec![[0u8; 16]; n_parties - 1])
            .collect();
        for i in 1..n_parties {
            for j in (i + 1)..n_parties {
                let mut seed = [0u8; 16];
                OsRng.fill_bytes(&mut seed);

                party_seeds[i - 1][j - 1] = seed;
                party_seeds[j - 1][i - 1] = seed;
            }
        }
        for i in 1..n_parties {
            // Remove the ith seed for party i because it is not necessary
            party_seeds[i - 1].remove(i - 1);
        }
        // Add an empty list of seeds for the server
        party_seeds.insert(0, vec![]);

        party_seeds
            .into_iter()
            .map(|seeds| ApproximateMpsiParty {
                seeds,
                bin_count: self.bin_count,
                hash_count: self.hash_count,
            })
            .collect()
    }

    fn generate_inputs(&self, n_parties: usize) -> Vec<<Self::Party as Party>::Input> {
        [None]
            .into_iter()
            .chain(
                gen_sets_with_uniform_intersection(n_parties, self.set_size, self.domain_size)
                    .into_iter()
                    .map(Some),
            )
            .collect()
    }

    fn validate_outputs(
        &self,
        inputs: &[<Self::Party as Party>::Input],
        outputs: &[<Self::Party as Party>::Output],
    ) -> bool {
        // Compute the intersection of the input sets
        let expected_intersection = Set::intersection(
            &inputs[1..]
                .iter()
                .map(|set| set.as_ref().unwrap().clone())
                .collect::<Vec<_>>(),
        );

        // Extract the protocol's output from the querying party (id = 1)
        let actual_intersection = outputs[1].as_ref().unwrap().clone();

        expected_intersection == actual_intersection
    }
}
