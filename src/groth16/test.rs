use crate::groth16::verifier::Verifier;
use crate::{execute_script_as_chunks, execute_script_without_stack_limit};
use crate::groth16::chunk;
use crate::bn254::utils;
use crate::bn254::ell_coeffs::{G2Prepared, EllCoeff};
use ark_bn254::Bn254;
use ark_crypto_primitives::snark::{CircuitSpecificSetupSNARK, SNARK};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::{end_timer, start_timer, test_rng, UniformRand};
use bitcoin_script::script;
use rand::{RngCore, SeedableRng};

#[derive(Copy)]
struct DummyCircuit<F: PrimeField> {
    pub a: Option<F>,
    pub b: Option<F>,
    pub num_variables: usize,
    pub num_constraints: usize,
}

impl<F: PrimeField> Clone for DummyCircuit<F> {
    fn clone(&self) -> Self {
        DummyCircuit {
            a: self.a,
            b: self.b,
            num_variables: self.num_variables,
            num_constraints: self.num_constraints,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DummyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
            let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

            Ok(a * b)
        })?;

        for _ in 0..(self.num_variables - 3) {
            let _ = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        }

        for _ in 0..self.num_constraints - 1 {
            cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        }

        cs.enforce_constraint(lc!(), lc!(), lc!())?;

        Ok(())
    }
}

#[test]
fn test_groth16_verifier_native() {
    type E = Bn254;
    let k = 6;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
        a: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
        b: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };
    let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

    let c = circuit.a.unwrap() * circuit.b.unwrap();

    let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

    let start = start_timer!(|| "collect_script");
    let script = Verifier::verify_proof(&vec![c], &proof, &vk);
    end_timer!(start);

    println!("groth16::test_verify_proof = {} bytes", script.len());

    let start = start_timer!(|| "execute_script");
    let exec_result = execute_script_without_stack_limit(script);
    end_timer!(start);

    assert!(exec_result.success);
}

#[test]
fn test_hinted_groth16_verifier() {
    type E = Bn254;
    let k = 6;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
        a: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
        b: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };
    let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

    let c = circuit.a.unwrap() * circuit.b.unwrap();

    let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

    let (hinted_groth16_verifier, hints) = Verifier::hinted_verify(&vec![c], &proof, &vk);

    println!(
        "hinted_groth16_verifier: {:?} bytes",
        hinted_groth16_verifier.len()
    );

    let start = start_timer!(|| "collect_script");
    let script = script! {
        for hint in hints {
            { hint.push() }
        }
        { hinted_groth16_verifier }
    };
    end_timer!(start);

    println!("groth16::test_hinted_verify_proof = {} bytes", script.len());

    let start = start_timer!(|| "execute_script");
    let exec_result = execute_script_without_stack_limit(script);
    end_timer!(start);

    assert!(exec_result.success);
}

#[test]
fn test_groth16_verifier_as_chunks() {
    type E = Bn254;
    let k = 6;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
        a: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
        b: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };
    let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

    let c = circuit.a.unwrap() * circuit.b.unwrap();

    let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

    let start = start_timer!(|| "collect_script");
    let script = Verifier::verify_proof(&vec![c], &proof, &vk);
    end_timer!(start);

    println!("groth16::test_verify_proof = {} bytes", script.len());

    let interval = script.max_op_if_interval();
    println!(
        "Max if interval: {:?} difference: {}, debug info: {}, {}",
        interval,
        interval.1 - interval.0,
        script.debug_info(interval.0),
        script.debug_info(interval.1)
    );
    let start = start_timer!(|| "execute_script");
    let exec_result = execute_script_as_chunks(script, 3_000_000, 1000);
    end_timer!(start);

    assert!(exec_result.success);
}

#[test]
fn test_chunks() {
    type E = Bn254;
    let k = 6;
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let circuit = DummyCircuit::<<E as Pairing>::ScalarField> {
        a: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
        b: Some(<E as Pairing>::ScalarField::rand(&mut rng)),
        num_variables: 10,
        num_constraints: 1 << k,
    };
    let (pk, vk) = Groth16::<E>::setup(circuit, &mut rng).unwrap();

    let c = circuit.a.unwrap() * circuit.b.unwrap();

    let proof = Groth16::<E>::prove(&pk, circuit, &mut rng).unwrap();

    let (p1,
        p2,
        p3,
        p4,
        q4,
        c,
        c_inv,
        wi,
        hint,
        q_prepared,
    ) = chunk::prepare_stack_elements(&vec![c], &proof, &vk);

    let line_coeffs = utils::collect_line_coeffs(q_prepared);
    let num_lines = line_coeffs.len();

    let f = c_inv;
    let t4 = q4;

    let mut script;
    let mut script_len;

    script = script!{
        { chunk::push_f(f) }
        { chunk::sub_script_0_0() }
    };
    script_len  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("\n\n\n0_0: script len {:?} stack len {:?}", script_len, exec_result.stats.max_nb_stack_items);

    script = script!{
        { chunk::push_f(f) }
        { chunk::push_c(c) }
        { chunk::sub_script_0_1() }
    };
    script_len  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("0_1: script len {:?} stack len {:?}", script_len, exec_result.stats.max_nb_stack_items);

    script = script!{
        { chunk::push_f(f) }
        { chunk::push_p1_prime(p1) }
        { chunk::sub_script_0_2_0(1,0,&line_coeffs) }
    };
    script_len  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("0_2_0: script len {:?} stack len {:?}", script_len, exec_result.stats.max_nb_stack_items);

    script = script!{
        { chunk::push_t4(t4) }
        { chunk::sub_script_0_2_1(1,0,&line_coeffs) }
    };
    script_len  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("0_2_1: script len {:?} stack len {:?}", script_len, exec_result.stats.max_nb_stack_items);

    script = script!{
        { chunk::push_f(f) }
        { chunk::push_p2_prime(p2) }
        { chunk::sub_script_0_3_0(4,1,&line_coeffs) }
    };
    script_len  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("0_3_0: script len {:?} stack len {:?}", script_len, exec_result.stats.max_nb_stack_items);

    script = script!{
        { chunk::push_t4(t4) }
        { chunk::push_q4(q4) }
        { chunk::sub_script_0_3_1(4,1,&line_coeffs) }
    };
    script_len  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("0_3_1: script len {:?} stack len {:?}", script_len, exec_result.stats.max_nb_stack_items);

    script = script!{
        { chunk::push_f(f) }
        { chunk::push_c_inv(c_inv) }
        { chunk::sub_script_1_0() }
    };
    script_len  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("1_0: script len {:?} stack len {:?}", script_len, exec_result.stats.max_nb_stack_items);

    script = script!{
        { chunk::push_f(f) }
        { chunk::push_c(c) }
        { chunk::sub_script_1_1() }
    };
    script_len  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("1_1: script len {:?} stack len {:?}", script_len, exec_result.stats.max_nb_stack_items);

    script = script!{
        { chunk::push_f(f) }
        { chunk::push_wi(wi) }
        { chunk::sub_script_1_2() }
    };
    script_len  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("1_2: script len {:?} stack len {:?}", script_len, exec_result.stats.max_nb_stack_items);

    script = script!{
        { chunk::push_f(f) }
        { chunk::push_p3_prime(p3) }
        { chunk::sub_script_2_0(2,&line_coeffs) }
    };
    script_len  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("2_0: script len {:?} stack len {:?}", script_len, exec_result.stats.max_nb_stack_items);


    script = script!{
        { chunk::push_beta_13() }
        { chunk::push_beta_12() }
        { chunk::push_q4(q4) }
        { chunk::sub_script_2_1_0() }
    };
    script_len  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("2_1_0: script len {:?} stack len {:?}", script_len, exec_result.stats.max_nb_stack_items);


    script = script!{
        { chunk::push_t4(t4) }
        { chunk::push_q4(q4) } // phiQ4(4)
        { chunk::sub_script_2_1_1(2,&line_coeffs) }
    };
    script_len  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("2_1_1: script len {:?} stack len {:?}", script_len, exec_result.stats.max_nb_stack_items);


    script = script!{
        { chunk::push_f(f) }
        { chunk::push_p4_prime(p4) }
        { chunk::sub_script_3_0(3,&line_coeffs) }
    };
    script_len  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("3_0: script len {:?} stack len {:?}", script_len, exec_result.stats.max_nb_stack_items);


    script = script!{
        { chunk::push_beta_22() }
        { chunk::push_q4(q4) }
        { chunk::push_t4(t4) }
        { chunk::sub_script_3_1(3,&line_coeffs) }
    };
    script_len  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("3_1: script len {:?} stack len {:?}", script_len, exec_result.stats.max_nb_stack_items);


    script = script!{
        { chunk::push_hint(hint) }
        { chunk::push_hint(hint) }
        { chunk::sub_script_4() }
    };
    script_len  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("4: script len {:?} stack len {:?}", script_len, exec_result.stats.max_nb_stack_items);

}

#[test]
fn test_mul() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let f = ark_bn254::Fq12::rand(&mut rng);
    let g = ark_bn254::Fq12::rand(&mut rng);

    let script = script! {
        { utils::fq12_push(f) }
        { utils::fq12_push(g) }
        { chunk::fq12_mul_0() }
    };
    let script_len_0  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("fq12_mul_0: script len {:?} stack len {:?}", script_len_0, exec_result.stats.max_nb_stack_items);

    let script = script! {
        { utils::fq12_push(f) }
        { utils::fq12_push(g) }
        { chunk::fq12_mul_0() }
        { chunk::fq12_mul_1() }
    };
    let script_len_1  = script.len() - script_len_0;
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("fq12_mul_1: script len {:?} stack len {:?}", script_len_1, exec_result.stats.max_nb_stack_items);

    let script = script! {
        { utils::fq12_push(f) }
        { utils::fq12_push(g) }
        { chunk::fq12_mul_0() }
        { chunk::fq12_mul_1() }
        { chunk::fq12_mul_2() }
    };
    let script_len_2  = script.len() - script_len_0 - script_len_1;
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("mul_2: script len {:?} stack len {:?}", script_len_2, exec_result.stats.max_nb_stack_items);

}

#[test]
fn test_square() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let f = ark_bn254::Fq12::rand(&mut rng);

    let script = script! {
        { utils::fq12_push(f) }
        { chunk::fq12_square_0() }
    };
    let script_len_0  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("fq12_square_0: script len {:?} stack len {:?}", script_len_0, exec_result.stats.max_nb_stack_items);

    let script = script! {
        { utils::fq12_push(f) }
        { chunk::fq12_square_0() }
        { chunk::fq12_square_1() }
    };
    let script_len_1  = script.len() - script_len_0;
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("fq12_square_1: script len {:?} stack len {:?}", script_len_1, exec_result.stats.max_nb_stack_items);
}

#[test]
fn test_frobenius_map() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let f = ark_bn254::Fq12::rand(&mut rng);

    let script = script! {
        { utils::fq12_push(f) }
        { chunk::fq12_frobenius_map_0(1) }
    };
    let script_len_0  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("frobenius_map_0: script len {:?} stack len {:?}", script_len_0, exec_result.stats.max_nb_stack_items);

    let script = script! {
        { utils::fq12_push(f) }
        { chunk::fq12_frobenius_map_0(1) }
        { chunk::fq12_frobenius_map_1(1) }
    };
    let script_len_1  = script.len() - script_len_0;
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("frobenius_map_1: script len {:?} stack len {:?}", script_len_1, exec_result.stats.max_nb_stack_items);
}

#[test]
fn test_ell_by_constant_affine() {
    let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(test_rng().next_u64());
    let f = ark_bn254::Fq12::rand(&mut rng);
    let x = ark_bn254::Fq2::rand(&mut rng);
    let q1 = ark_bn254::G2Affine::rand(&mut rng);
    let q2 = ark_bn254::G2Affine::rand(&mut rng);
    let q3 = ark_bn254::G2Affine::rand(&mut rng);
    let q4= ark_bn254::G2Affine::rand(&mut rng);
    let constants = vec![
        G2Prepared::from_affine(q1),
        G2Prepared::from_affine(q2),
        G2Prepared::from_affine(q3),
        G2Prepared::from_affine(q4),
    ];

    let line_coeffs = utils::collect_line_coeffs(constants);

    let script = script! {
        { utils::fq12_push(f) }
        { utils::fq2_push(x) }
        { chunk::ell_by_constant_affine_0(&line_coeffs[1][0][0]) }
    };
    let script_len_0  = script.len();
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("ell_by_constant_affine_0: script len {:?} stack len {:?}", script_len_0, exec_result.stats.max_nb_stack_items);

    let script = script! {
        { utils::fq12_push(f) }
        { utils::fq2_push(x) }
        { chunk::ell_by_constant_affine_0(&line_coeffs[1][0][0]) }
        { chunk::ell_by_constant_affine_1() }
    };
    let script_len_1  = script.len() - script_len_0;
    let exec_result = execute_script_without_stack_limit(script);
    assert!(!exec_result.success);
    println!("ell_by_constant_affine_1: script len {:?} stack len {:?}", script_len_1, exec_result.stats.max_nb_stack_items);
}
