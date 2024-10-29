use crate::bn254::ell_coeffs::{G2Prepared, EllCoeff};
use crate::bn254::fp254impl::Fp254Impl;
use crate::bn254::fq::Fq;
use crate::bn254::fq2::Fq2;
use crate::bn254::fq6::Fq6;
use crate::bn254::fq12::Fq12;
use crate::bn254::msm::{
    hinted_msm_with_constant_bases, msm_with_constant_bases, msm_with_constant_bases_affine,
};
use crate::bn254::pairing::Pairing;
use crate::bn254::utils::{
    fq12_push, fq12_push_not_montgomery, fq2_push, fq2_push_not_montgomery, from_eval_point,
    hinted_from_eval_point, Hint, ell_by_constant_affine, check_tangent_line, affine_double_line,
    check_chord_line, affine_add_line,
};
use crate::groth16::constants::{LAMBDA, P_POW3};
use crate::groth16::offchain_checker::compute_c_wi;
use crate::groth16::verifier::Verifier;
use crate::treepp::{script, Script};
use ark_bn254::{Bn254, G1Projective};
use ark_ec::pairing::Pairing as ark_Pairing;
use ark_ec::short_weierstrass::Projective;
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ec::bn::BnConfig;
use ark_ff::{Field, QuadExtField, Fp12Config};
use ark_groth16::{Proof, VerifyingKey};
use core::ops::Neg;
use rand_chacha::ChaCha20Rng;

type G1Affine = <Bn254 as ark_Pairing>::G1Affine;
type G2Affine = <Bn254 as ark_Pairing>::G2Affine;

// pre_stack:  [a(12) b(12)]
// post_stack: [tmp(30)]
pub fn fq12_mul_0() -> Script {
    script! {
        { Fq6::copy(18) }
        { Fq6::copy(12) }
        { Fq6::mul(6, 0) }
    }
}
// pre_stack:  [tmp(30)]
// post_stack: [tmp(36)]
pub fn fq12_mul_1() -> Script {
    script! {
        { Fq6::copy(18) }
        { Fq6::copy(12) }
        { Fq6::mul(6, 0) }
    }
}
// pre_stack:  [tmp[36]]
// post_stack: [c(12)]
pub fn fq12_mul_2() -> Script {
    script! {
        { Fq6::add(24, 30) }
        { Fq6::add(18, 24) }
        { Fq6::mul(6, 0) }
        { Fq6::copy(12) }
        { Fq6::copy(12) }
        { Fq12::mul_fq6_by_nonresidue() } 
        { Fq6::add(6, 0) }
        { Fq6::add(18, 12)}
        { Fq6::sub(12, 0) }
    }
}


// pre_stack:  [c(12)]
// post_stack: [tmp(18)]
pub fn fq12_square_0() -> Script {
    script! {
        // v0 = c0 + c1
        { Fq6::copy(6) }
        { Fq6::copy(6) }
        { Fq6::add(6, 0) }

        // v3 = c0 + beta * c1
        { Fq6::copy(6) }
        { Fq12::mul_fq6_by_nonresidue() }
        { Fq6::copy(18) }
        { Fq6::add(0, 6) }

        // v2 = c0 * c1
        { Fq6::mul(12, 18) }
    }
}
// pre_stack: [tmp(18)]
// pre_stack: [final_c(12)]
pub fn fq12_square_1() -> Script {
    script! {
        // v0 = v0 * v3
        { Fq6::mul(12, 6) }

        // final c0 = v0 - (beta + 1) * v2
        { Fq6::copy(6) }
        { Fq12::mul_fq6_by_nonresidue() }
        { Fq6::copy(12) }
        { Fq6::add(6, 0) }
        { Fq6::sub(6, 0) }

        // final c1 = 2 * v2
        { Fq6::double(6) }
    }
}


// pre_stack:  [c(12)]
// post_stack: [tmp(12)]
pub fn fq12_frobenius_map_0(i: usize) -> Script {
    script! {
        { Fq6::roll(6) }
        { Fq6::frobenius_map(i) }
    }
}
// pre_stack:  [tmp(12)]
// post_stack: [final_c(12)]
pub fn fq12_frobenius_map_1(i: usize) -> Script {
    script! {
        { Fq6::roll(6) }
        { Fq6::frobenius_map(i) }
        { Fq6::mul_by_fp2_constant(&ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1[i % ark_bn254::Fq12Config::FROBENIUS_COEFF_FP12_C1.len()]) }
    }
}



// pre_stack:  [f(12) x(1) y(1)]
// post_stack: [tmp(22)]
pub fn ell_by_constant_affine_0(constant: &EllCoeff) -> Script {
    script! {
        // [f, x', y']
        // update c1, c1' = x' * c1
        { Fq::copy(1) }
        { Fq::mul_by_constant(&constant.1.c0) }
        // [f, x', y', x' * c1.0]
        { Fq::roll(2) }
        { Fq::mul_by_constant(&constant.1.c1) }
        // [f, y', x' * c1.0, x' * c1.1]
        // [f, y', x' * c1]

        // update c2, c2' = -y' * c2
        { Fq::copy(2) }
        { Fq::mul_by_constant(&constant.2.c0) }
        // [f, y', x' * c1, y' * c2.0]
        { Fq::roll(3) }
        { Fq::mul_by_constant(&constant.2.c1) }
        // [f, x' * c1, y' * c2.0, y' * c2.1]
        // [f, x' * c1, y' * c2]
        // [f, c1', c2']

        // Fq12::mul_by_34
        // copy f.c1, c3(c1'), c4(c2')
        { Fq6::copy(4) }
        { Fq2::copy(8) }
        { Fq2::copy(8) }
        // [f, c3, c4, f.c1, c3, c4]

        // compute b = f.c1 * (c3, c4)
        { Fq6::mul_by_01() }
        // [f, c3, c4, b]
    }
}
// pre_stack:  [[tmp(22)]
// post_stack: [final_f(12)]
pub fn ell_by_constant_affine_1() -> Script {
    script! {
        // [f, c3, c4, b]

        // a = f.c0 * c0, where c0 = 1
        { Fq6::copy(16) }
        // [f, c3, c4, b, a]

        // compute beta * b
        { Fq6::copy(6) }
        { Fq12::mul_fq6_by_nonresidue() }
        // [f, c3, c4, b, a, beta * b]

        // compute final c0 = a + beta * b
        { Fq6::copy(6) }
        { Fq6::add(6, 0) }
        // [f, c3, c4, b, a, c0]

        // compute e = f.c0 + f.c1
        { Fq6::add(28, 22) }
        // [c3, c4, b, a, c0, e]

        // compute c0 + c3, where c0 = 1
        { Fq2::roll(26) }
        { Fq2::push_one() }
        { Fq2::add(2, 0) }
        // [c4, b, a, c0, e, 1 + c3]

        // update e = e * (c0 + c3, c4), where c0 = 1
        { Fq2::roll(26) }
        { Fq6::mul_by_01() }
        // [b, a, c0, e]

        // sum a and b
        { Fq6::add(18, 12) }
        // [c0, e, a + b]

        // compute final c1 = e - (a + b)
        { Fq6::sub(6, 0) }
    }
}





















pub fn prepare_stack_elements(
    public_inputs: &Vec<<Bn254 as ark_Pairing>::ScalarField>,
    proof: &Proof<Bn254>,
    vk: &VerifyingKey<Bn254>,
) -> (
    Script,    // p1 
    G1Affine,  // p2
    G1Affine,  // p3
    G1Affine,  // p4
    G2Affine,  // q4
    ark_bn254::Fq12,  // c
    ark_bn254::Fq12,  // c_inv
    ark_bn254::Fq12,  // wi
    ark_bn254::Fq12,  // hint
    Vec<G2Prepared>,  // q_prepared
)
{
    let (msm_script, msm_g1) = Verifier::prepare_inputs(public_inputs, vk);
        
    let (exp, sign) = if LAMBDA.gt(&P_POW3) {
        (&*LAMBDA - &*P_POW3, true)
    } else {
        (&*P_POW3 - &*LAMBDA, false)
    };

    // G1/G2 points for pairings
    let (p1, p2, p3, p4) = (msm_g1.into_affine(), proof.c, vk.alpha_g1, proof.a);
    let (q1, q2, q3, q4) = (
        vk.gamma_g2.into_group().neg().into_affine(),
        vk.delta_g2.into_group().neg().into_affine(),
        -vk.beta_g2,
        proof.b,
    );

    // hint from arkworks
    let f = Bn254::multi_miller_loop_affine([p1, p2, p3, p4], [q1, q2, q3, q4]).0;
    let (c, wi) = compute_c_wi(f);
    let c_inv = c.inverse().unwrap();
    let hint = if sign {
        f * wi * (c_inv.pow((exp).to_u64_digits()))
    } else {
        f * wi * (c_inv.pow((exp).to_u64_digits()).inverse().unwrap())
    };
    assert_eq!(hint, c.pow(P_POW3.to_u64_digits()), "hint isn't correct!");

    let q_prepared = vec![
        G2Prepared::from_affine(q1),
        G2Prepared::from_affine(q2),
        G2Prepared::from_affine(q3),
        G2Prepared::from_affine(q4),
    ];

    ( msm_script, p2, p3, p4, q4, c, c_inv, wi, hint, q_prepared )
}


/*
stack push functions for chunk
*/
pub fn push_beta_12() -> Script {
    script! {
        // beta_12
        { Fq::push_dec("21575463638280843010398324269430826099269044274347216827212613867836435027261") }
        { Fq::push_dec("10307601595873709700152284273816112264069230130616436755625194854815875713954") }
    }
}

pub fn push_beta_13() -> Script {
    script! {
         // beta_13
        { Fq::push_dec("2821565182194536844548159561693502659359617185244120367078079554186484126554") }
        { Fq::push_dec("3505843767911556378687030309984248845540243509899259641013678093033130930403") }
    }
}

pub fn push_beta_22() -> Script {
    script! {
        // beta_22
        { Fq::push_dec("21888242871839275220042445260109153167277707414472061641714758635765020556616") }
        { Fq::push_zero() }
    }
}

pub fn push_p1_prime(msm_script: Script) -> Script {
    script! {
        // variant of p1, say -p1.x / p1.y, 1 / p1.y
        { msm_script }
        { Fq::inv() }
        { Fq::copy(0) }
        { Fq::roll(2) }
        { Fq::neg(0) }
        { Fq::mul() }
        { Fq::roll(1) }
    }
}

pub fn push_p2_prime(p2: G1Affine) -> Script {
    script! {
        // variants of G1 points
        { from_eval_point(p2) }
    }
}

pub fn push_p3_prime(p3: G1Affine) -> Script {
    script! {
        // variants of G1 points
        { from_eval_point(p3) }
    }
}

pub fn push_p4_prime(p4: G1Affine) -> Script {
    script! {
        // variants of G1 points
        { from_eval_point(p4) }
    }
}

pub fn push_q4(q4: G2Affine) -> Script {
    script! {
        // the only non-fixed G2 point, say q4
        { fq2_push(q4.x) }
        { fq2_push(q4.y) }
    }
}

pub fn push_c(c: ark_bn254::Fq12) -> Script {
    script! {
        { fq12_push(c) }
    }
}

pub fn push_c_inv(c_inv: ark_bn254::Fq12) -> Script {
    script! {
        { fq12_push(c_inv) }
    }
}

pub fn push_wi(wi: ark_bn254::Fq12) -> Script {
    script! {
        { fq12_push(wi) }
    }
}

// initial t4 = q4
pub fn push_t4(t4: G2Affine) -> Script {
    script! {
        // accumulator of q4, say t4
        { fq2_push(t4.x) }
        { fq2_push(t4.y) }
    }
}

// initial f = c_inv
pub fn push_f(f: ark_bn254::Fq12) -> Script {
    script! {
        { fq12_push(f) }
    }
}

// hint = final_f
pub fn push_hint(hint: ark_bn254::Fq12) -> Script {
    script! {
        { fq12_push(hint) }
    }
}



/*
split verify_proof_script into several sub-scripts

    // ATE_LOOP_COUNT len: 65
    for i in (1..ark_bn254::Config::ATE_LOOP_COUNT.len()).rev() {
        sub_script_0_0();

        if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 {
            // f * c_inv
            sub_script_0_1();
        } else if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
            // f * c
            sub_script_0_1();
        }

        // num_line_groups: 4
        for j in 0..num_line_groups {
            sub_script_0_2_0(i, j ,line_coeffs);

            if j == 3 {
                sub_script_0_2_1(i, j, line_coeffs);
            }
        }

        if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == 1 || ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
            for j in 0..num_line_groups {
                sub_script_0_3_0(i, j ,line_coeffs);

                if j == 3 {
                    sub_script_0_3_1(i, j, line_coeffs);
                }
            }
        }
    }   

    sub_script_1_0();

    sub_script_1_1();

    sub_script_1_2();

    for j in 0..num_line_groups {
        sub_script_2_0(j, line_coeffs);
        
        if j == 3 {
            sub_script_2_1_0(j, line_coeffs);
            sub_script_2_1_1(j, line_coeffs);
        }
    }

    for j in 0..num_line_groups {
        sub_script_3_0(j, line_coeffs);
        
        if j == 3 {
            sub_script_3_1(j, line_coeffs);
        }
    }

    sub_script_4();
}

*/

// pre_stack:  [f(12)]
// post_stack: [f(12)]
pub fn sub_script_0_0() -> Script {
    script! {  
        // update f, squaring
        { Fq12::square() }
    }
}

// pre_stack:  [f(12), c_inv(12)] or [f(12), c(12)]
// post_stack: [f(12)]
pub fn sub_script_0_1() -> Script {
    script! {
        // f = f * c_inv || f = f * c
        { Fq12::mul(12, 0) }
    }
}

// pre_stack:  [f(12), P_{j+1}] (j = 0, 1, 2, 3)
// post_stack: [f(12)]
pub fn sub_script_0_2_0(i: usize, j: usize, line_coeffs: &Vec<Vec<Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)>>>) -> Script {
    let num_lines = line_coeffs.len();
    script! {
        // update f with double line evaluation
        { ell_by_constant_affine(&line_coeffs[num_lines - (i + 2)][j][0]) }
    }
}

// pre_stack:  [T4(4)]
// post_stack: [T4(4)]
pub fn sub_script_0_2_1(i: usize, j: usize, line_coeffs: &Vec<Vec<Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)>>>) -> Script {
    let num_lines = line_coeffs.len();
    script! {
        // copy T4 
        { Fq2::copy(2) }
        { Fq2::copy(2) }

        { check_tangent_line(line_coeffs[num_lines - (i + 2)][j][0].1, line_coeffs[num_lines - (i + 2)][j][0].2) }
        
        // update T4
        // drop T4.y, leave T4.x
        { Fq2::drop() }
        { affine_double_line(line_coeffs[num_lines - (i + 2)][j][0].1, line_coeffs[num_lines - (i + 2)][j][0].2) }                             
    }
}

// pre_stack:  [f(12), P_{j+1}] (j = 0, 1, 2, 3)
// post_stack: [f(12)]
pub fn sub_script_0_3_0(i: usize, j: usize, line_coeffs: &Vec<Vec<Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)>>>) -> Script {
    let num_lines = line_coeffs.len();
    script! {
        // update f with adding line evaluation
        { ell_by_constant_affine(&line_coeffs[num_lines - (i + 2)][j][1]) }
    }
}

// pre_stack:  [T4(4), Q4(4)]
// post_stack: [T4(4)]
pub fn sub_script_0_3_1(i: usize, j: usize, line_coeffs: &Vec<Vec<Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)>>>) -> Script {
    let num_lines = line_coeffs.len();
    script! {
        // copy T4
        { Fq2::copy(6) }
        { Fq2::copy(6) }
        // [T4(4), Q4(4), T4(4)]
        // copy Q4
        { Fq2::copy(6) }
        { Fq2::copy(6) }
        // [T4(4), Q4(4), T4(4), Q4(4)]
        if ark_bn254::Config::ATE_LOOP_COUNT[i - 1] == -1 {
            { Fq2::neg(0) }
        }
        { check_chord_line(line_coeffs[num_lines - (i + 2)][j][1].1, line_coeffs[num_lines - (i + 2)][j][1].2) }
        // [T4(4), Q4(4)]

        // update T4
        // drop Q4.y, leave Q4.x
        { Fq2::drop() }
        // [T4(4), Q4.x(2)]
        { Fq2::toaltstack() } 
        // [T4(4) | Q4.x(2)]
        // drop T4.y, leave T4.x
        { Fq2::drop() }
        // [T4.x(2) | Q4.x(2)]
        { Fq2::fromaltstack() } 
        // [T4.x(2), Q4.x(2)]
        { affine_add_line(line_coeffs[num_lines - (i + 2)][j][1].1, line_coeffs[num_lines - (i + 2)][j][1].2) }
        // [T4(4)]
    }
}

// pre_stack:  [f(12), c_inv(12)]
// post_stack: [f(12)]
pub fn sub_script_1_0() -> Script {
    script! {
        // c_inv^p
        { Fq12::frobenius_map(1) }
        // f = f * c_inv^p
        { Fq12::mul(12, 0) }
           
    }
}

// pre_stack:  [f(12), c(12)]
// post_stack: [f(12)]
pub fn sub_script_1_1() -> Script {
    script! {
        // c^{p^2}
        { Fq12::frobenius_map(2) }
        // f = f * c^{p^2}
        { Fq12::mul(12, 0) }
           
    }
}

// pre_stack:  [f(12), wi(12)]
// post_stack: [f(12)]
pub fn sub_script_1_2() -> Script {
    script! {
        // f = f * wi
        { Fq12::mul(12, 0) }
    }
}

// pre_stack:  [f(12), P_{j+1}] (j = 0, 1, 2, 3)
// post_stack: [f(12)]
pub fn sub_script_2_0(j: usize, line_coeffs: &Vec<Vec<Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)>>>) -> Script {
    let num_lines = line_coeffs.len();   
    script! {
        // update f with add line evaluation of one-time of frobenius map on Q4
        { ell_by_constant_affine(&line_coeffs[num_lines - 2][j][0]) }                
    }
}

// pre_stack:  [beta13(2), beta_12(2), Q4(4)]
// post_stack: [phi(Q4)(4)]
pub fn sub_script_2_1_0() -> Script {
    script! {
        // Qx' = Qx.conjugate * beta^{2 * (p - 1) / 6}
        { Fq2::roll(2) }
        // [beta13(2), beta_12(2), Q4.y(2), Q4.x(2)]
        { Fq::neg(0) }
        // [beta13(2), beta_12(2), Q4.y(2), -Q4.x(2)]
        { Fq2::roll(4) }
        // [beta13(2), Q4.y(2), -Q4.x(2), beta_12(2)]
        { Fq2::mul(2, 0) }
        // Q4.x' = -Q4.x * beta_12 
        // [beta13(2), Q4.y(2), Q4.x'(2)]

        // Qy' = Qy.conjugate * beta^{3 * (p - 1) / 6}
        { Fq2::roll(2) }
        // [beta13(2), Q4.x'(2), Q4.y(2)]
        { Fq::neg(0) }
        // [beta13(2), Q4.x'(2), -Q4.y(2)]
        { Fq2::roll(4) }
        // [Q4.x'(2), -Q4.y(2), beta13(2)]
        { Fq2::mul(2, 0) }
        // Q4.y' = -Q4.y * beta_13 (2)
        // [Q4.x'(2), Q4.y'(2)]
        // phi(Q4) = (Q4.x', Q4.y')
    }
}

// pre_stack:  [T4(4), phi(Q4)(4)]
// post_stack: [T4(4)]
pub fn sub_script_2_1_1(j: usize, line_coeffs: &Vec<Vec<Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)>>>) -> Script {
    let num_lines = line_coeffs.len();   
    script! {
        // check chord line
        { Fq2::copy(6) }
        { Fq2::copy(6) }
        // [T4(4), phi(Q4)(4), T4(4)]
        { Fq2::copy(6) }
        { Fq2::copy(6) }
        // [T4(4), phi(Q4)(4), T4(4), phi(Q4)(4)]
        { check_chord_line(line_coeffs[num_lines - 2][j][0].1, line_coeffs[num_lines - 2][j][0].2) } 
        // [T4(4), phi(Q4)(4)]

        // update T4
        { Fq2::drop() }
        // [T4(4), phi(Q4).x(2)]
        { Fq2::toaltstack() }
        // [T4(4) | phi(Q4).x(2)]
        { Fq2::drop() }
        // [T4.x(2) | phi(Q4).x(2)]
        { Fq2::fromaltstack() }
        // [T4.x(2), phi(Q4).x(2)]
        { affine_add_line(line_coeffs[num_lines - 2][j][0].1, line_coeffs[num_lines - 2][j][0].2) }
        // [T4(4)]
    }
}

// pre_stack:  [f(12), P_{j+1}] (j = 0, 1, 2, 3)
// post_stack: [f(12)]
pub fn sub_script_3_0(j: usize, line_coeffs: &Vec<Vec<Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)>>>) -> Script {
    let num_lines = line_coeffs.len();   
    script! {
        { ell_by_constant_affine(&line_coeffs[num_lines - 1][j][0]) }
    }
}

// pre_stack:  [beta_22(2), Q4(4), T4(4)]
// post_stack: []
pub fn sub_script_3_1(j: usize, line_coeffs: &Vec<Vec<Vec<(ark_bn254::Fq2, ark_bn254::Fq2, ark_bn254::Fq2)>>>) -> Script {
    let num_lines = line_coeffs.len();   
    script! {
        { Fq2::roll(8) }
        // [Q4(4), T4(4), beta_22(2)]
        { Fq2::roll(8) }
        // [Q4.y(2), T4(4), beta_22(2), Q4.x(2)]
        { Fq2::mul(2, 0) }
        // [Q4.y(2), T4(4), beta_22(2) * Q4.x(2)]
        // Q4.x' = Q4.x * beta^{2 * (p^2 - 1) / 6}
        // [Q4.y(2), T4(4), Q4.x'(2)]
        { Fq2::roll(6) }
        // [T4(4), Q4.x'(2), Q4.y(2)]
        // phi(Q4)^2 = (Q4.x', Qy)
        // [T4(4), phi(Q4)^2(4)]

        // check whether the chord line through T4 and phi(Q4)^2
        { check_chord_line(line_coeffs[num_lines - 1][j][0].1, line_coeffs[num_lines - 1][j][0].2) }
        // []
    }
}

// pre_stack:  [f(12), hint(12)]
// post_stack: [OP_TRUE]
pub fn sub_script_4() -> Script {
    script! {
        { Fq12::equalverify() }
        // OP_TRUE
    }
}
