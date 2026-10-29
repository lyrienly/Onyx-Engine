use onyx_freezer::{AtomicFreezer, FreezeMode};

#[test]
fn freeze_adiciona_entrada() {
    let f = AtomicFreezer::new();
    let v = 42i32.to_le_bytes().to_vec();
    let id = f.freeze(0x1000, v, FreezeMode::Normal);
    assert!(id >= 1);
    assert_eq!(f.len(), 1);
    let list = f.list();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].id, id);
    assert_eq!(list[0].address, 0x1000);
    f.stop();
}

#[test]
fn unfreeze_remove_entrada() {
    let f = AtomicFreezer::new();
    let id = f.freeze(0x2000, vec![1, 2, 3, 4], FreezeMode::Normal);
    assert_eq!(f.len(), 1);
    assert!(f.unfreeze(id));
    assert_eq!(f.len(), 0);
    assert!(!f.unfreeze(id));
    f.stop();
}

#[test]
fn unfreeze_all_zera_entradas() {
    let f = AtomicFreezer::new();
    for i in 0..5 {
        f.freeze(0x3000 + i, vec![0, 0, 0, 0], FreezeMode::Normal);
    }
    assert_eq!(f.len(), 5);
    f.unfreeze_all();
    assert_eq!(f.len(), 0);
    assert!(f.is_empty());
    f.stop();
}

#[test]
fn ids_sao_unicos_e_crescentes() {
    let f = AtomicFreezer::new();
    let a = f.freeze(0x4000, vec![0; 4], FreezeMode::Normal);
    let b = f.freeze(0x4004, vec![0; 4], FreezeMode::Normal);
    let c = f.freeze(0x4008, vec![0; 4], FreezeMode::Normal);
    assert!(a < b && b < c);
    f.stop();
}

#[test]
fn mode_increment_e_decrement_persistem_na_lista() {
    let f = AtomicFreezer::new();
    f.freeze(0x5000, vec![0; 4], FreezeMode::Increment(2));
    f.freeze(0x5004, vec![0; 4], FreezeMode::Decrement(1));
    let list = f.list();
    assert_eq!(list.len(), 2);
    assert!(matches!(list[0].mode, FreezeMode::Increment(2)));
    assert!(matches!(list[1].mode, FreezeMode::Decrement(1)));
    f.stop();
}

#[test]
fn stats_iniciam_zeradas() {
    let f = AtomicFreezer::new();
    let s = f.stats();
    assert_eq!(s.writes, 0);
    assert_eq!(s.reads, 0);
    assert_eq!(s.errors, 0);
    f.stop();
}

#[test]
fn drop_para_worker_sem_deadlock() {
    let f = AtomicFreezer::new();
    f.freeze(0x6000, vec![0; 4], FreezeMode::Normal);
    drop(f);
}
