use onyx_core::process::DbkDriver;

#[test]
fn test_kernel_security_profile_evaluation() {
    let profile = DbkDriver::evaluate_security_profile();
    println!("Evaluated Kernel Security Profile: {:?}", profile);

    // CR3 risk must match VBS active status
    assert_eq!(profile.cr3_interception_risk, profile.vbs_active);

    // If VBS is active, check_cr3_intercept_advisory must return Some advisory
    let advisory = DbkDriver::check_cr3_intercept_advisory(1337);
    if profile.vbs_active {
        assert!(advisory.is_some());
        let msg = advisory.unwrap();
        assert!(msg.contains("1337"));
        assert!(msg.contains("VBS"));
    } else {
        assert!(advisory.is_none());
    }
}

#[test]
fn test_vbs_and_hvci_status_queries() {
    let vbs = DbkDriver::is_vbs_active();
    let hvci = DbkDriver::is_hvci_active();
    let risk = DbkDriver::is_cr3_interception_risk();

    println!(
        "VBS active: {}, HVCI active: {}, CR3 risk: {}",
        vbs, hvci, risk
    );
    assert_eq!(risk, vbs);
}

#[test]
fn test_canonical_virtual_address_validation() {
    // Valid canonical user-mode addresses
    assert!(DbkDriver::is_canonical_va(0x0000_0000_0040_0000));
    assert!(DbkDriver::is_canonical_va(0x0000_7FFF_FFFF_FFFF));
    assert!(DbkDriver::is_canonical_va(0x0));

    // Valid canonical kernel-mode addresses
    assert!(DbkDriver::is_canonical_va(0xFFFF_8000_0000_0000));
    assert!(DbkDriver::is_canonical_va(0xFFFF_F800_0000_0000));
    assert!(DbkDriver::is_canonical_va(0xFFFF_FFFF_FFFF_FFFF));

    // Non-canonical "hole" addresses (must be rejected)
    assert!(!DbkDriver::is_canonical_va(0x0000_8000_0000_0000));
    assert!(!DbkDriver::is_canonical_va(0x0001_0000_0000_0000));
    assert!(!DbkDriver::is_canonical_va(0xFFFF_7FFF_FFFF_FFFF));
    assert!(!DbkDriver::is_canonical_va(0xDEAD_BEEF_CAFE_BABE));
}
