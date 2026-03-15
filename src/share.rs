#![forbid(unsafe_code)]

use crate::blob::{Account, Blob, Share};

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

#[derive(Debug, Clone, Eq, PartialEq)]
struct ShareRef {
    id: Option<String>,
    name: String,
    readonly: bool,
}

pub(crate) fn assign_account_share(account: &mut Account, blob: &Blob) -> Result<(), String> {
    account.share_name = None;
    account.share_id = None;
    account.share_readonly = false;

    let Some((share_name, remainder)) = split_share_path(&account.fullname) else {
        return Ok(());
    };

    let shares = collect_shares(blob);
    let Some(share) = find_share(&shares, share_name) else {
        if is_shared_folder_name(&account.fullname) {
            return Err(format!(
                "Unable to find shared folder for {} in blob",
                account.fullname
            ));
        }
        return Ok(());
    };

    let (group, name) = split_group(remainder);
    account.share_name = Some(share.name.clone());
    account.share_id = share.id.clone();
    account.share_readonly = share.readonly;
    account.group = group;
    account.name = name;
    Ok(())
}

fn collect_shares(blob: &Blob) -> Vec<ShareRef> {
    let mut out: Vec<ShareRef> = blob.shares.iter().map(share_ref_from_share).collect();

    for account in &blob.accounts {
        let Some(name) = account.share_name.as_ref() else {
            continue;
        };
        if out
            .iter()
            .any(|share| share.name.eq_ignore_ascii_case(name))
        {
            continue;
        }
        out.push(ShareRef {
            id: account.share_id.clone(),
            name: name.clone(),
            readonly: account.share_readonly,
        });
    }

    out
}

fn share_ref_from_share(share: &Share) -> ShareRef {
    ShareRef {
        id: Some(share.id.clone()),
        name: share.name.clone(),
        readonly: share.readonly,
    }
}

fn find_share<'a>(shares: &'a [ShareRef], name: &str) -> Option<&'a ShareRef> {
    shares
        .iter()
        .find(|share| share.name.eq_ignore_ascii_case(name))
}

fn split_share_path(fullname: &str) -> Option<(&str, &str)> {
    let slash = fullname.find('/')?;
    Some((&fullname[..slash], &fullname[slash + 1..]))
}

fn is_shared_folder_name(fullname: &str) -> bool {
    fullname.starts_with("Shared-") && fullname.contains('/')
}

fn split_group(fullname: &str) -> (String, String) {
    if let Some(pos) = fullname.rfind('/') {
        return (fullname[..pos].to_string(), fullname[pos + 1..].to_string());
    }
    (String::new(), fullname.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::KDF_HASH_LEN;

    fn account(fullname: &str) -> Account {
        let (group, name) = split_group(fullname);
        Account {
            id: "0".to_string(),
            name,
            group,
            fullname: fullname.to_string(),
            ..Account::default()
        }
    }

    fn share(id: &str, name: &str, readonly: bool) -> Share {
        Share {
            id: id.to_string(),
            name: name.to_string(),
            readonly,
            key: Some([7u8; KDF_HASH_LEN]),
        }
    }

    #[test]
    fn assign_account_share_sets_shared_folder_metadata() {
        let blob = Blob {
            version: 1,
            local_version: false,
            shares: vec![share("77", "Shared-Team", false)],
            accounts: Vec::new(),
            attachments: Vec::new(),
        };
        let mut account = account("Shared-Team/apps/entry");

        assign_account_share(&mut account, &blob).expect("assign");

        assert_eq!(account.share_name.as_deref(), Some("Shared-Team"));
        assert_eq!(account.share_id.as_deref(), Some("77"));
        assert!(!account.share_readonly);
        assert_eq!(account.group, "apps");
        assert_eq!(account.name, "entry");
        assert_eq!(account.fullname, "Shared-Team/apps/entry");
    }

    #[test]
    fn assign_account_share_uses_case_insensitive_share_lookup() {
        let blob = Blob {
            version: 1,
            local_version: false,
            shares: vec![share("77", "Shared-Team", false)],
            accounts: Vec::new(),
            attachments: Vec::new(),
        };
        let mut account = account("shared-team/entry");

        assign_account_share(&mut account, &blob).expect("assign");

        assert_eq!(account.share_name.as_deref(), Some("Shared-Team"));
        assert_eq!(account.share_id.as_deref(), Some("77"));
        assert_eq!(account.group, "");
        assert_eq!(account.name, "entry");
    }

    #[test]
    fn assign_account_share_falls_back_to_existing_account_metadata() {
        let mut existing = account("Shared-Team/legacy");
        existing.share_name = Some("Shared-Team".to_string());
        existing.share_id = Some("88".to_string());
        existing.share_readonly = true;
        let blob = Blob {
            version: 1,
            local_version: false,
            shares: Vec::new(),
            accounts: vec![existing],
            attachments: Vec::new(),
        };
        let mut account = account("Shared-Team/new-entry");

        assign_account_share(&mut account, &blob).expect("assign");

        assert_eq!(account.share_name.as_deref(), Some("Shared-Team"));
        assert_eq!(account.share_id.as_deref(), Some("88"));
        assert!(account.share_readonly);
    }

    #[test]
    fn assign_account_share_clears_stale_shared_folder_metadata() {
        let blob = Blob {
            version: 1,
            local_version: false,
            shares: vec![share("77", "Shared-Team", false)],
            accounts: Vec::new(),
            attachments: Vec::new(),
        };
        let mut account = account("plain/entry");
        account.share_name = Some("Shared-Team".to_string());
        account.share_id = Some("77".to_string());
        account.share_readonly = true;

        assign_account_share(&mut account, &blob).expect("assign");

        assert_eq!(account.share_name, None);
        assert_eq!(account.share_id, None);
        assert!(!account.share_readonly);
        assert_eq!(account.group, "plain");
        assert_eq!(account.name, "entry");
    }

    #[test]
    fn assign_account_share_rejects_missing_shared_folder_names() {
        let blob = Blob {
            version: 1,
            local_version: false,
            shares: Vec::new(),
            accounts: Vec::new(),
            attachments: Vec::new(),
        };
        let mut account = account("Shared-Missing/entry");

        let err = assign_account_share(&mut account, &blob).expect_err("missing share");

        assert!(err.contains("Unable to find shared folder"));
    }
}
