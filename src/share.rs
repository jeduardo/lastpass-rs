#![forbid(unsafe_code)]

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ShareUser {
    pub uid: String,
    pub username: String,
    pub realname: Option<String>,
    pub cgid: Option<String>,
    pub read_only: bool,
    pub is_group: bool,
    pub hide_passwords: bool,
    pub admin: bool,
    pub outside_enterprise: bool,
    pub accepted: bool,
    pub sharing_key: Vec<u8>,
}

impl ShareUser {
    pub fn user_id(&self) -> String {
        if self.is_group {
            format!("group:{}", self.uid)
        } else {
            self.uid.clone()
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ShareLimitAid {
    pub aid: String,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct ShareLimit {
    pub whitelist: bool,
    pub aids: Vec<ShareLimitAid>,
}
