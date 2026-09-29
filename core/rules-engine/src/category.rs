//! Gambling classification categories.
//!
//! Categories are data, not control flow: the matcher never branches on a
//! category, so new categories can be added without touching matching logic.
//! Unknown identifiers from newer blocklists are preserved as
//! [`Category::Other`] rather than rejected, so an older client can still
//! enforce a newer list.

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Category {
    SportsBetting,
    OnlineCasino,
    Slots,
    Poker,
    Bingo,
    Lotteries,
    BettingExchange,
    FantasyBetting,
    EsportsBetting,
    CryptoCasino,
    CrashGambling,
    SkinBetting,
    GamblingAffiliates,
    GamblingMirrors,
    /// User-added domain with no curated category.
    UserDefined,
    /// Category identifier not known to this client version.
    Other(String),
}

const KNOWN: &[(&str, Category)] = &[
    ("sports_betting", Category::SportsBetting),
    ("online_casino", Category::OnlineCasino),
    ("slots", Category::Slots),
    ("poker", Category::Poker),
    ("bingo", Category::Bingo),
    ("lotteries", Category::Lotteries),
    ("betting_exchange", Category::BettingExchange),
    ("fantasy_betting", Category::FantasyBetting),
    ("esports_betting", Category::EsportsBetting),
    ("crypto_casino", Category::CryptoCasino),
    ("crash_gambling", Category::CrashGambling),
    ("skin_betting", Category::SkinBetting),
    ("gambling_affiliates", Category::GamblingAffiliates),
    ("gambling_mirrors", Category::GamblingMirrors),
    ("user_defined", Category::UserDefined),
];

impl Category {
    pub fn id(&self) -> &str {
        match self {
            Category::Other(s) => s,
            known => KNOWN
                .iter()
                .find(|(_, c)| c == known)
                .map(|(id, _)| *id)
                .expect("every non-Other variant is listed in KNOWN"),
        }
    }
}

impl FromStr for Category {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key = s.trim().to_ascii_lowercase();
        Ok(KNOWN
            .iter()
            .find(|(id, _)| *id == key)
            .map(|(_, c)| c.clone())
            .unwrap_or(Category::Other(key)))
    }
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}
