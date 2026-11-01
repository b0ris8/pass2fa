//! Генератор паролей на системном CSPRNG (getrandom), без смещения по модулю.
pub struct GenOpts {
    pub len: usize,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
}

impl Default for GenOpts {
    fn default() -> Self {
        Self { len: 20, upper: true, digits: true, symbols: true }
    }
}

fn rand_below(n: u32) -> u32 {
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).expect("системный RNG недоступен");
        let x = u32::from_le_bytes(b);
        if x < zone {
            return x % n;
        }
    }
}

pub fn generate(o: &GenOpts) -> String {
    // без похожих символов l/I/O/0
    let lower = "abcdefghijkmnopqrstuvwxyz";
    let upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    let digits = "23456789";
    let symbols = "!#$%&*+-=?@^_";
    let mut sets: Vec<&str> = vec![lower];
    if o.upper { sets.push(upper); }
    if o.digits { sets.push(digits); }
    if o.symbols { sets.push(symbols); }
    let all: Vec<char> = sets.concat().chars().collect();
    let len = o.len.clamp(8, 128);
    loop {
        let p: String = (0..len).map(|_| all[rand_below(all.len() as u32) as usize]).collect();
        // гарантируем хотя бы один символ каждого выбранного класса
        if sets.iter().all(|s| p.chars().any(|c| s.contains(c))) {
            return p;
        }
    }
}
