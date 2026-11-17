// Integration test for SigmaOS-vpn-pia
// Verifies the crate builds and links as a dependency.
#![allow(unused_imports)]

use sigmaos_vpn_pia as _;

#[test]
fn crate_links_and_runs() {
    assert_eq!(2 + 2, 4);
}
