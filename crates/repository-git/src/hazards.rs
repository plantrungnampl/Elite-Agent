use std::path::Path;

use git2::{Config, ConfigLevel, Repository};
use local_agent_terminal_application::{RepositoryHazard, RepositoryHazardReason};

use crate::paths;

pub(crate) fn scan(repository: &Repository, config: &Config) -> Vec<RepositoryHazard> {
    let mut hazards = Vec::new();
    let mut entries = match config.entries(None) {
        Ok(entries) => entries,
        Err(_) => {
            hazards.push(hazard(
                RepositoryHazardReason::UnsafeConfiguration,
                "configuration could not be enumerated",
            ));
            return hazards;
        }
    };
    while let Some(entry) = entries.next() {
        let Ok(entry) = entry else {
            hazards.push(hazard(
                RepositoryHazardReason::UnsafeConfiguration,
                "configuration entry could not be decoded",
            ));
            continue;
        };
        let name = String::from_utf8_lossy(entry.name_bytes()).to_ascii_lowercase();
        let value = if entry.has_value() {
            String::from_utf8_lossy(entry.value_bytes()).to_ascii_lowercase()
        } else {
            String::new()
        };
        if entry.include_depth() > 0
            || !matches!(entry.level(), ConfigLevel::Local | ConfigLevel::Worktree)
        {
            hazards.push(hazard(
                RepositoryHazardReason::UnsafeConfiguration,
                "external or included configuration",
            ));
            continue;
        }
        if name == "core.hookspath" {
            hazards.push(hazard(
                RepositoryHazardReason::HooksConfigured,
                "hooks path configured",
            ));
        } else if name == "core.fsmonitor"
            || name == "credential.helper"
            || name == "core.sshcommand"
            || name.starts_with("include.")
            || name.starts_with("includeif.")
            || name.starts_with("url.")
            || name == "core.gitproxy"
            || name == "core.attributesfile"
            || name == "core.excludesfile"
            || name == "core.sparsecheckout"
            || name == "core.sparsecheckoutcone"
            || name == "remote.pushdefault"
        {
            hazards.push(hazard(
                RepositoryHazardReason::UnsafeConfiguration,
                "process, credential, or include configuration",
            ));
        } else if name.starts_with("remote.") {
            hazards.push(hazard(
                RepositoryHazardReason::UnsafeConfiguration,
                "remote configuration",
            ));
        } else if name.starts_with("filter.") {
            hazards.push(hazard(
                RepositoryHazardReason::FiltersConfigured,
                "checkout filter configured",
            ));
        } else if name.starts_with("submodule.") {
            hazards.push(hazard(
                RepositoryHazardReason::SubmodulesPresent,
                "submodule configuration",
            ));
        } else if name.starts_with("extensions.")
            && !(name == "extensions.objectformat" && matches!(value.as_str(), "sha1" | "sha256"))
        {
            hazards.push(hazard(
                RepositoryHazardReason::UnsupportedObjectFormat,
                "unsupported repository extension",
            ));
        } else if (name.starts_with("diff.") || name.starts_with("merge."))
            && (name.ends_with(".driver") || name.ends_with(".command") || name == "diff.external")
        {
            hazards.push(hazard(
                RepositoryHazardReason::UnsafeConfiguration,
                "custom diff or merge driver",
            ));
        }
    }

    let common_dir = repository.commondir();
    if common_dir.join("hooks").is_dir() {
        // A default hooks directory is inert; only an explicit core.hooksPath is hazardous.
    }
    if let Ok(tree) = repository.head().and_then(|head| head.peel_to_tree()) {
        if tree.get_path(Path::new(".gitmodules")).is_ok() {
            hazards.push(hazard(
                RepositoryHazardReason::SubmodulesPresent,
                "gitmodules file present in HEAD",
            ));
        }
        if tree.get_path(Path::new(".lfsconfig")).is_ok() {
            hazards.push(hazard(
                RepositoryHazardReason::LfsConfigured,
                "lfs configuration file present in HEAD",
            ));
        }
        if let Ok(entry) = tree.get_path(Path::new(".gitattributes")) {
            if repository
                .find_blob(entry.id())
                .map(|blob| {
                    blob.content()
                        .split(|byte| byte.is_ascii_whitespace())
                        .any(|token| token.eq_ignore_ascii_case(b"filter=lfs"))
                })
                .unwrap_or(false)
            {
                hazards.push(hazard(
                    RepositoryHazardReason::LfsConfigured,
                    "lfs attribute present in HEAD",
                ));
            }
        }
    }
    if repository.is_shallow() || repository.is_bare() || repository.is_worktree() {
        hazards.push(hazard(
            RepositoryHazardReason::UnsafeConfiguration,
            "unsupported repository layout",
        ));
    }
    if repository.state() != git2::RepositoryState::Clean {
        hazards.push(hazard(
            RepositoryHazardReason::UnsafeConfiguration,
            "repository operation is in progress",
        ));
    }
    deduplicate(&mut hazards);
    hazards
}

fn hazard(reason: RepositoryHazardReason, detail: &str) -> RepositoryHazard {
    RepositoryHazard {
        reason,
        detail: detail.to_owned(),
    }
}

fn deduplicate(hazards: &mut Vec<RepositoryHazard>) {
    let mut seen = Vec::new();
    hazards.retain(|hazard| {
        if seen.contains(&hazard.reason) {
            false
        } else {
            seen.push(hazard.reason);
            true
        }
    });
}

pub(crate) fn has_unsupported(hazards: &[RepositoryHazard]) -> bool {
    hazards.iter().any(|hazard| {
        matches!(
            hazard.reason,
            RepositoryHazardReason::UnsupportedObjectFormat
        )
    })
}

pub(crate) fn health(
    hazards: &[RepositoryHazard],
    dirty: bool,
) -> local_agent_terminal_application::RepositoryHealth {
    if has_unsupported(hazards) {
        local_agent_terminal_application::RepositoryHealth::Unsupported
    } else if !hazards.is_empty() {
        local_agent_terminal_application::RepositoryHealth::Unsafe
    } else if dirty {
        local_agent_terminal_application::RepositoryHealth::Dirty
    } else {
        local_agent_terminal_application::RepositoryHealth::Healthy
    }
}

pub(crate) fn config_worktree_matches(repository: &Repository) -> bool {
    let Some(workdir) = repository.workdir() else {
        return false;
    };
    let Ok(config) = repository.config() else {
        return true;
    };
    match config.get_str("core.worktree") {
        Ok(value) => {
            let configured = std::path::Path::new(value);
            paths::canonical_directory(configured)
                .map(|path| path == workdir)
                .unwrap_or(false)
        }
        Err(_) => true,
    }
}
