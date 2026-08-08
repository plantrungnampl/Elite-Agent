use std::ffi::{OsStr, OsString};
use std::fs::File as StdFile;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr;

use cap_fs_ext::{
    DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsMaybeDirExt, OsMetadataExt,
};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, File, OpenOptions};
use local_agent_terminal_application::{
    AuthorizedFileRead, AuthorizedFileWrite, CapabilityFileWriteSession,
    CapabilityFileWriteSessionFactory, CapabilityFilesystem, CapabilityRequest, CapabilityResolver,
    CapabilityRootIdentity, FileWritePostExpectation, FileWriteRecoveryRequest, ObservedFileImage,
    OpenFileWriteSession, PortError, RelativePathComponents, ResolvedCapability,
    ResolvedCapabilityTarget, Retryability, SafeErrorClassification, VerifiedBytes,
    VerifiedFileWriteCompensation, VerifiedWrite,
};
use local_agent_terminal_domain::{ArtifactId, CapabilityRef, Sha256Digest, TaskId};
use sha2::{Digest, Sha256};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FileDirectoryInformation, FileRenameInformation, NtCreateFile, NtQueryDirectoryFile,
    NtSetInformationFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DIRECTORY_INFORMATION,
    FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    HANDLE, OBJ_CASE_INSENSITIVE, STATUS_BUFFER_OVERFLOW, STATUS_NO_MORE_FILES,
    STATUS_NO_SUCH_FILE, STATUS_OBJECT_NAME_COLLISION, STATUS_SUCCESS, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileDispositionInfoEx, FileIdInfo, GetFileInformationByHandleEx, SetFileInformationByHandle,
    DELETE, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TRAVERSE, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const MAX_READ_BYTES: usize = 8 * 1024 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 4_096;
const MAX_TEMP_CREATE_ATTEMPTS: u32 = 16;
const MAX_EXACT_NAME_QUERY_BYTES: usize = 64 * 1024 + size_of::<FILE_DIRECTORY_INFORMATION>();

#[derive(Debug)]
pub struct CapabilityRegistration {
    root_identity: CapabilityRootIdentity,
    owner_task_id: TaskId,
    binding: RegistrationBinding,
    root_path: PathBuf,
    fixed_leaf: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RegistrationBinding {
    Source { revision: String },
    Artifact { artifact_id: ArtifactId },
    Worktree,
    Toolchain { name: String },
}

impl CapabilityRegistration {
    pub fn source(
        root_identity: CapabilityRootIdentity,
        owner_task_id: TaskId,
        revision: impl Into<String>,
        root_path: impl Into<PathBuf>,
    ) -> Result<Self, PortError> {
        let revision = revision.into();
        CapabilityRef::source(revision.clone(), "registered-root").map_err(|_| invalid_input())?;
        Ok(Self {
            root_identity,
            owner_task_id,
            binding: RegistrationBinding::Source { revision },
            root_path: root_path.into(),
            fixed_leaf: None,
        })
    }

    pub fn artifact(
        root_identity: CapabilityRootIdentity,
        owner_task_id: TaskId,
        artifact_id: ArtifactId,
        artifact_path: impl AsRef<Path>,
    ) -> Result<Self, PortError> {
        CapabilityRef::artifact(artifact_id.clone()).map_err(|_| invalid_input())?;
        Self::fixed_file(
            root_identity,
            owner_task_id,
            RegistrationBinding::Artifact { artifact_id },
            artifact_path.as_ref(),
        )
    }

    pub fn worktree(
        root_identity: CapabilityRootIdentity,
        task_id: TaskId,
        root_path: impl Into<PathBuf>,
    ) -> Result<Self, PortError> {
        Ok(Self {
            root_identity,
            owner_task_id: task_id,
            binding: RegistrationBinding::Worktree,
            root_path: root_path.into(),
            fixed_leaf: None,
        })
    }

    pub fn toolchain(
        root_identity: CapabilityRootIdentity,
        owner_task_id: TaskId,
        name: impl Into<String>,
        executable_path: impl AsRef<Path>,
    ) -> Result<Self, PortError> {
        let name = name.into();
        CapabilityRef::toolchain(name.clone()).map_err(|_| invalid_input())?;
        Self::fixed_file(
            root_identity,
            owner_task_id,
            RegistrationBinding::Toolchain { name },
            executable_path.as_ref(),
        )
    }

    fn fixed_file(
        root_identity: CapabilityRootIdentity,
        owner_task_id: TaskId,
        binding: RegistrationBinding,
        path: &Path,
    ) -> Result<Self, PortError> {
        let absolute = std::path::absolute(path).map_err(configuration_io_error)?;
        let leaf = absolute
            .file_name()
            .and_then(OsStr::to_str)
            .filter(|name| valid_windows_component(name))
            .ok_or_else(invalid_input)?
            .to_owned();
        let root_path = absolute.parent().ok_or_else(invalid_input)?.to_owned();
        Ok(Self {
            root_identity,
            owner_task_id,
            binding,
            root_path,
            fixed_leaf: Some(leaf),
        })
    }
}

#[derive(Debug)]
pub struct WindowsCapabilityAdapter {
    registrations: Vec<RegisteredCapability>,
}

#[derive(Debug)]
struct RegisteredCapability {
    root_identity: CapabilityRootIdentity,
    owner_task_id: TaskId,
    binding: RegistrationBinding,
    root_parent: Dir,
    root_name: OsString,
    retained_root: Dir,
    root_identity_on_disk: FileIdentity,
    fixed_leaf: Option<RegisteredLeaf>,
}

#[derive(Debug)]
struct RegisteredLeaf {
    name: String,
    identity: FileIdentity,
}

#[derive(Debug)]
struct OpenedFile {
    _directories: Vec<Dir>,
    file: File,
}

struct WindowsFileWriteSession {
    root_parent: Dir,
    directory_names: Vec<OsString>,
    directories: Vec<Dir>,
    directory_identities: Vec<FileIdentity>,
    leaf_name: String,
    pre_image: ObservedFileImage,
    pre_target: ExpectedTarget,
    applied_target: Option<ExpectedTarget>,
    temp_key: String,
    temp_generation: u32,
    #[cfg(feature = "test-seams")]
    post_stage_hook: Option<Box<dyn FnOnce() -> std::io::Result<()> + Send>>,
    #[cfg(feature = "test-seams")]
    compensation_post_stage_hook: Option<Box<dyn FnOnce() -> std::io::Result<()> + Send>>,
    #[cfg(feature = "test-seams")]
    post_rename_hook: Option<Box<dyn FnOnce() -> std::io::Result<()> + Send>>,
    #[cfg(feature = "test-seams")]
    pre_operation_hook: Option<Box<dyn FnOnce() -> std::io::Result<()> + Send>>,
    #[cfg(feature = "test-seams")]
    compensation_pre_operation_hook: Option<Box<dyn FnOnce() -> std::io::Result<()> + Send>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExpectedTarget {
    Absent,
    Present {
        identity: FileIdentity,
        verified: VerifiedWrite,
    },
}

enum RetainedTarget {
    Absent,
    Present(StdFile),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

impl WindowsCapabilityAdapter {
    pub fn new(registrations: Vec<CapabilityRegistration>) -> Result<Self, PortError> {
        let mut opened = Vec::with_capacity(registrations.len());
        for registration in registrations {
            if opened.iter().any(|existing: &RegisteredCapability| {
                existing.root_identity == registration.root_identity
                    || (existing.owner_task_id == registration.owner_task_id
                        && existing.binding == registration.binding)
            }) {
                return Err(invalid_input());
            }
            let (root_parent, root_name, retained_root) =
                open_registered_root(&registration.root_path)?;
            let root_identity_on_disk =
                file_identity(&retained_root).map_err(configuration_io_error)?;
            let fixed_leaf = registration
                .fixed_leaf
                .map(|name| {
                    let opened = open_file_nofollow(
                        retained_root.try_clone().map_err(configuration_io_error)?,
                        std::slice::from_ref(&name),
                    )
                    .map_err(|_| invalid_input())?;
                    Ok::<_, PortError>(RegisteredLeaf {
                        name,
                        identity: file_identity(&opened.file).map_err(configuration_io_error)?,
                    })
                })
                .transpose()?;
            opened.push(RegisteredCapability {
                root_identity: registration.root_identity,
                owner_task_id: registration.owner_task_id,
                binding: registration.binding,
                root_parent,
                root_name,
                retained_root,
                root_identity_on_disk,
                fixed_leaf,
            });
        }
        Ok(Self {
            registrations: opened,
        })
    }

    #[cfg(feature = "test-seams")]
    pub fn read_with_post_open_hook(
        &self,
        request: AuthorizedFileRead,
        hook: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<VerifiedBytes, PortError> {
        self.read_authorized_with_hook(request, hook)
            .map_err(|_| denied())
    }

    #[cfg(feature = "test-seams")]
    pub fn open_write_session_with_post_stage_hook(
        &self,
        request: OpenFileWriteSession,
        hook: Box<dyn FnOnce() -> std::io::Result<()> + Send>,
    ) -> Result<Box<dyn CapabilityFileWriteSession>, PortError> {
        let mut session = self.open_file_write_session(request)?;
        session.post_stage_hook = Some(hook);
        Ok(Box::new(session))
    }

    #[cfg(feature = "test-seams")]
    pub fn open_write_session_with_compensation_post_stage_hook(
        &self,
        request: OpenFileWriteSession,
        hook: Box<dyn FnOnce() -> std::io::Result<()> + Send>,
    ) -> Result<Box<dyn CapabilityFileWriteSession>, PortError> {
        let mut session = self.open_file_write_session(request)?;
        session.compensation_post_stage_hook = Some(hook);
        Ok(Box::new(session))
    }

    #[cfg(feature = "test-seams")]
    pub fn open_write_session_with_post_rename_hook(
        &self,
        request: OpenFileWriteSession,
        hook: Box<dyn FnOnce() -> std::io::Result<()> + Send>,
    ) -> Result<Box<dyn CapabilityFileWriteSession>, PortError> {
        let mut session = self.open_file_write_session(request)?;
        session.post_rename_hook = Some(hook);
        Ok(Box::new(session))
    }

    #[cfg(feature = "test-seams")]
    pub fn open_write_session_with_pre_operation_hook(
        &self,
        request: OpenFileWriteSession,
        hook: Box<dyn FnOnce() -> std::io::Result<()> + Send>,
    ) -> Result<Box<dyn CapabilityFileWriteSession>, PortError> {
        let mut session = self.open_file_write_session(request)?;
        session.pre_operation_hook = Some(hook);
        Ok(Box::new(session))
    }

    #[cfg(feature = "test-seams")]
    pub fn open_write_session_with_compensation_pre_operation_hook(
        &self,
        request: OpenFileWriteSession,
        hook: Box<dyn FnOnce() -> std::io::Result<()> + Send>,
    ) -> Result<Box<dyn CapabilityFileWriteSession>, PortError> {
        let mut session = self.open_file_write_session(request)?;
        session.compensation_pre_operation_hook = Some(hook);
        Ok(Box::new(session))
    }

    fn registration_by_root(
        &self,
        root_identity: &CapabilityRootIdentity,
        task_id: &TaskId,
    ) -> Result<&RegisteredCapability, PortError> {
        self.registrations
            .iter()
            .find(|registration| {
                &registration.root_identity == root_identity
                    && &registration.owner_task_id == task_id
            })
            .ok_or_else(denied)
    }

    fn read_authorized(&self, request: AuthorizedFileRead) -> Result<VerifiedBytes, PortError> {
        self.read_authorized_with_hook(request, || Ok(()))
    }

    fn read_authorized_with_hook(
        &self,
        request: AuthorizedFileRead,
        hook: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<VerifiedBytes, PortError> {
        let registration = self.registration_by_root(&request.root_identity, &request.task_id)?;
        registration.read(
            request.relative_components.as_slice(),
            request.expected_digest.as_ref(),
            hook,
        )
    }

    fn open_file_write_session(
        &self,
        request: OpenFileWriteSession,
    ) -> Result<WindowsFileWriteSession, PortError> {
        let registration = self.registration_by_root(request.root_identity(), request.task_id())?;
        if registration.binding != RegistrationBinding::Worktree {
            return Err(denied());
        }
        registration
            .open_write_session(request)
            .map_err(|_| denied())
    }
}

impl CapabilityResolver for WindowsCapabilityAdapter {
    fn resolve(&self, request: CapabilityRequest) -> Result<ResolvedCapability, PortError> {
        let registration = self
            .registrations
            .iter()
            .find(|registration| registration.matches(&request.task_id, &request.capability))
            .ok_or_else(denied)?;
        let target = registration.target_for(&request.capability)?;
        let content_digest = match &target {
            ResolvedCapabilityTarget::Root => None,
            ResolvedCapabilityTarget::Relative(relative_components)
                if registration.binding == RegistrationBinding::Worktree =>
            {
                registration
                    .read_optional(relative_components.as_slice(), || Ok(()))?
                    .map(|verified| verified.digest)
            }
            ResolvedCapabilityTarget::Relative(relative_components) => Some(
                registration
                    .read(relative_components.as_slice(), None, || Ok(()))?
                    .digest,
            ),
        };

        Ok(ResolvedCapability {
            capability: request.capability,
            content_digest,
            root_identity: registration.root_identity.clone(),
            target,
        })
    }
}

impl CapabilityFilesystem for WindowsCapabilityAdapter {
    fn read(&self, request: AuthorizedFileRead) -> Result<VerifiedBytes, PortError> {
        self.read_authorized(request).map_err(|_| denied())
    }

    fn write(&self, _request: AuthorizedFileWrite) -> Result<VerifiedWrite, PortError> {
        Err(denied())
    }
}

impl CapabilityFileWriteSessionFactory for WindowsCapabilityAdapter {
    fn open(
        &self,
        request: OpenFileWriteSession,
    ) -> Result<Box<dyn CapabilityFileWriteSession>, PortError> {
        self.open_file_write_session(request)
            .map(|session| Box::new(session) as Box<dyn CapabilityFileWriteSession>)
    }

    fn observe_recovery_target(
        &self,
        request: &FileWriteRecoveryRequest,
    ) -> Result<ObservedFileImage, PortError> {
        let registration = self
            .registrations
            .iter()
            .find(|registration| {
                registration.binding == RegistrationBinding::Worktree
                    && registration.owner_task_id == request.task_id
                    && registration.root_identity == request.root_identity
            })
            .ok_or_else(denied)?;
        registration
            .read_optional(request.relative_components.as_slice(), || Ok(()))
            .map(|observed| {
                observed.map_or_else(ObservedFileImage::absent, |verified| {
                    ObservedFileImage::present(verified.bytes)
                })
            })
    }
}

impl RegisteredCapability {
    fn matches(&self, task_id: &TaskId, capability: &CapabilityRef) -> bool {
        if &self.owner_task_id != task_id {
            return false;
        }
        match (&self.binding, capability) {
            (RegistrationBinding::Source { revision }, CapabilityRef::Source(source)) => {
                revision == source.revision()
            }
            (RegistrationBinding::Artifact { artifact_id }, CapabilityRef::Artifact(artifact)) => {
                artifact_id == artifact.artifact_id()
            }
            (RegistrationBinding::Worktree, CapabilityRef::Worktree(worktree)) => {
                worktree.task_id() == task_id
            }
            (RegistrationBinding::Toolchain { name }, CapabilityRef::Toolchain(toolchain)) => {
                name == toolchain.name()
            }
            _ => false,
        }
    }

    fn target_for(
        &self,
        capability: &CapabilityRef,
    ) -> Result<ResolvedCapabilityTarget, PortError> {
        match (&self.binding, capability, &self.fixed_leaf) {
            (RegistrationBinding::Source { .. }, CapabilityRef::Source(source), None) => {
                relative_components(source.path()).map(ResolvedCapabilityTarget::Relative)
            }
            (RegistrationBinding::Worktree, CapabilityRef::Worktree(worktree), None) => {
                if worktree.path() == "." {
                    Ok(ResolvedCapabilityTarget::Root)
                } else {
                    relative_components(worktree.path()).map(ResolvedCapabilityTarget::Relative)
                }
            }
            (RegistrationBinding::Artifact { .. }, CapabilityRef::Artifact(_), Some(leaf))
            | (RegistrationBinding::Toolchain { .. }, CapabilityRef::Toolchain(_), Some(leaf)) => {
                RelativePathComponents::new(vec![leaf.name.clone()])
                    .map(ResolvedCapabilityTarget::Relative)
                    .map_err(|_| denied())
            }
            _ => Err(denied()),
        }
    }

    fn reopen_root(&self) -> Result<Dir, PortError> {
        if file_identity(&self.retained_root).map_err(read_io_error)? != self.root_identity_on_disk
        {
            return Err(denied());
        }
        require_exact_registered_name(&self.root_parent, &self.root_name).map_err(read_io_error)?;
        let reopened = self
            .root_parent
            .open_dir_nofollow(&self.root_name)
            .map_err(read_io_error)?;
        reject_reparse_directory(&reopened).map_err(read_io_error)?;
        if file_identity(&reopened).map_err(read_io_error)? != self.root_identity_on_disk {
            return Err(denied());
        }
        Ok(reopened)
    }

    fn read(
        &self,
        components: &[String],
        expected_digest: Option<&local_agent_terminal_domain::Sha256Digest>,
        hook: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<VerifiedBytes, PortError> {
        let verified = self.read_optional(components, hook)?.ok_or_else(denied)?;
        if expected_digest.is_some_and(|expected| expected != &verified.digest) {
            return Err(denied());
        }
        Ok(verified)
    }

    fn read_optional(
        &self,
        components: &[String],
        hook: impl FnOnce() -> std::io::Result<()>,
    ) -> Result<Option<VerifiedBytes>, PortError> {
        if self
            .fixed_leaf
            .as_ref()
            .is_some_and(|leaf| components != [leaf.name.as_str()])
        {
            return Err(denied());
        }
        let root = self.reopen_root()?;
        let Some(mut opened) = open_optional_file_from_root(root, components)? else {
            return if self.fixed_leaf.is_none() {
                Ok(None)
            } else {
                Err(denied())
            };
        };
        if self.fixed_leaf.as_ref().is_some_and(|leaf| {
            file_identity(&opened.file).map_or(true, |identity| identity != leaf.identity)
        }) {
            return Err(denied());
        }
        hook().map_err(read_io_error)?;
        let bytes = read_bounded(&mut opened.file)?;
        let digest = local_agent_terminal_domain::Sha256Digest::new(format!(
            "sha256:{:x}",
            Sha256::digest(&bytes)
        ))
        .map_err(|_| denied())?;
        Ok(Some(VerifiedBytes { digest, bytes }))
    }

    fn open_write_session(
        &self,
        request: OpenFileWriteSession,
    ) -> Result<WindowsFileWriteSession, PortError> {
        if self.binding != RegistrationBinding::Worktree
            || &self.owner_task_id != request.task_id()
            || &self.root_identity != request.root_identity()
        {
            return Err(denied());
        }

        let components = request.relative_components().as_slice();
        for component in components {
            validate_windows_component(component)?;
        }
        let leaf_name = components.last().ok_or_else(denied)?.clone();
        let root = self.reopen_root()?;
        let mut directory_names = vec![self.root_name.clone()];
        let mut directory_identities = vec![self.root_identity_on_disk];
        let mut directories = vec![root];
        for component in &components[..components.len() - 1] {
            let parent = directories.last().expect("root directory is retained");
            require_exact_name(parent, OsStr::new(component)).map_err(read_io_error)?;
            let child = parent.open_dir_nofollow(component).map_err(read_io_error)?;
            reject_reparse_directory(&child).map_err(read_io_error)?;
            directory_names.push(OsString::from(component));
            directory_identities.push(file_identity(&child).map_err(read_io_error)?);
            directories.push(child);
        }

        let parent = directories.last().expect("root directory is retained");
        let (pre_image, pre_target) = match open_optional_file_nofollow(parent, &leaf_name)? {
            Some(mut file) => {
                let identity = file_identity(&file).map_err(read_io_error)?;
                let bytes = read_bounded(&mut file)?;
                let verified = verified_write(&bytes)?;
                (
                    ObservedFileImage::present(bytes),
                    ExpectedTarget::Present { identity, verified },
                )
            }
            None => (ObservedFileImage::absent(), ExpectedTarget::Absent),
        };
        if request.expected_pre_digest().is_some_and(|expected| {
            pre_image
                .present_bytes()
                .is_none_or(|observed| &observed.digest != expected)
        }) {
            return Err(denied());
        }

        Ok(WindowsFileWriteSession {
            root_parent: self.root_parent.try_clone().map_err(read_io_error)?,
            directory_names,
            directories,
            directory_identities,
            leaf_name,
            pre_image,
            pre_target,
            applied_target: None,
            temp_key: temp_key(request.execution_id().as_str()),
            temp_generation: 0,
            #[cfg(feature = "test-seams")]
            post_stage_hook: None,
            #[cfg(feature = "test-seams")]
            compensation_post_stage_hook: None,
            #[cfg(feature = "test-seams")]
            post_rename_hook: None,
            #[cfg(feature = "test-seams")]
            pre_operation_hook: None,
            #[cfg(feature = "test-seams")]
            compensation_pre_operation_hook: None,
        })
    }
}

impl CapabilityFileWriteSession for WindowsFileWriteSession {
    fn pre_image(&self) -> &ObservedFileImage {
        &self.pre_image
    }

    fn apply(&mut self, bytes: &[u8]) -> Result<(), PortError> {
        if self.applied_target.is_some() {
            return Err(denied());
        }
        let expected = self.pre_target.clone();
        self.replace_target(&expected, bytes).map(|_| ())
    }

    fn verify_post_image(
        &mut self,
        expected: &FileWritePostExpectation,
    ) -> Result<VerifiedWrite, PortError> {
        let applied = self.applied_target.clone().ok_or_else(denied)?;
        let parent = self.revalidate_parent()?;
        let verified = self.require_target(&parent, &applied)?.ok_or_else(denied)?;
        if &verified.digest != expected.digest() || verified.size_bytes != expected.size_bytes() {
            return Err(denied());
        }
        Ok(verified)
    }

    fn restore_pre_image_and_verify(&mut self) -> Result<VerifiedFileWriteCompensation, PortError> {
        let applied = self.applied_target.clone().ok_or_else(denied)?;
        let compensation = match self.pre_target.clone() {
            ExpectedTarget::Absent => {
                let parent = self.revalidate_parent()?;
                let RetainedTarget::Present(applied_file) =
                    retain_expected_target(&parent, &self.leaf_name, &applied)?
                else {
                    return Err(denied());
                };
                #[cfg(feature = "test-seams")]
                if self
                    .compensation_pre_operation_hook
                    .take()
                    .is_some_and(|hook| hook().is_err())
                {
                    return Err(denied());
                }
                mark_for_deletion(&applied_file)?;
                drop(applied_file);
                sync_directory_handle(&parent)?;
                let parent = self.revalidate_parent()?;
                drop(self.require_target(&parent, &ExpectedTarget::Absent)?);
                VerifiedFileWriteCompensation::Absent
            }
            ExpectedTarget::Present { .. } => {
                #[cfg(feature = "test-seams")]
                {
                    self.post_stage_hook = self.compensation_post_stage_hook.take();
                    self.pre_operation_hook = self.compensation_pre_operation_hook.take();
                }
                let bytes = self
                    .pre_image
                    .present_bytes()
                    .expect("present pre-image has retained bytes")
                    .bytes
                    .clone();
                let restored = self.replace_target(&applied, &bytes)?;
                let ExpectedTarget::Present { verified, .. } = restored else {
                    unreachable!("replacement always produces a present target");
                };
                VerifiedFileWriteCompensation::Restored(verified)
            }
        };
        self.applied_target = None;
        Ok(compensation)
    }
}

impl WindowsFileWriteSession {
    fn replace_target(
        &mut self,
        expected: &ExpectedTarget,
        bytes: &[u8],
    ) -> Result<ExpectedTarget, PortError> {
        if bytes.len() > MAX_READ_BYTES {
            return Err(denied());
        }

        let staged_parent = self.revalidate_parent()?;
        drop(self.require_target(&staged_parent, expected)?);
        let (temp_name, staged_file, staged_identity) =
            self.create_staged_file(&staged_parent, bytes)?;
        let staged_verified = verified_write(bytes)?;
        #[cfg(feature = "test-seams")]
        if let Some(hook) = self.post_stage_hook.take() {
            if hook().is_err() {
                drop(staged_file);
                remove_named_if_identity(&staged_parent, &temp_name, staged_identity);
                return Err(denied());
            }
        }
        let result = (|| {
            let destination_parent = self.revalidate_parent()?;
            let rename_parent = self.open_rename_parent(&destination_parent)?;
            require_named_identity(&staged_parent, &temp_name, staged_identity)?;
            let retained = retain_expected_target(&destination_parent, &self.leaf_name, expected)?;
            #[cfg(feature = "test-seams")]
            if self
                .pre_operation_hook
                .take()
                .is_some_and(|hook| hook().is_err())
            {
                return Err(denied());
            }
            match retained {
                RetainedTarget::Absent => {
                    rename_noreplace(&staged_file, &rename_parent, OsStr::new(&self.leaf_name))
                        .map_err(read_io_error)?
                }
                RetainedTarget::Present(target_file) => {
                    self.move_to_unique_backup(&target_file, &rename_parent)?;
                    if rename_noreplace(&staged_file, &rename_parent, OsStr::new(&self.leaf_name))
                        .is_err()
                    {
                        drop(rename_noreplace(
                            &target_file,
                            &rename_parent,
                            OsStr::new(&self.leaf_name),
                        ));
                        return Err(denied());
                    }
                    let applied = ExpectedTarget::Present {
                        identity: staged_identity,
                        verified: staged_verified.clone(),
                    };
                    self.applied_target = Some(applied);
                    mark_for_deletion(&target_file)?;
                }
            }
            let applied = ExpectedTarget::Present {
                identity: staged_identity,
                verified: staged_verified,
            };
            self.applied_target = Some(applied.clone());
            sync_directory_handle(&destination_parent)?;
            #[cfg(feature = "test-seams")]
            if self
                .post_rename_hook
                .take()
                .is_some_and(|hook| hook().is_err())
            {
                return Err(denied());
            }
            let reopened_parent = self.revalidate_parent()?;
            self.require_target(&reopened_parent, &applied)?
                .ok_or_else(denied)?;
            Ok(applied)
        })();
        drop(staged_file);
        if result.is_err() {
            remove_named_if_identity(&staged_parent, &temp_name, staged_identity);
        }
        result
    }

    fn create_staged_file(
        &mut self,
        parent: &Dir,
        bytes: &[u8],
    ) -> Result<(String, StdFile, FileIdentity), PortError> {
        let generation = self.temp_generation;
        self.temp_generation = self.temp_generation.checked_add(1).ok_or_else(denied)?;
        for attempt in 0..MAX_TEMP_CREATE_ATTEMPTS {
            let name = format!(".lat-write-{}-{generation}-{attempt}.tmp", self.temp_key);
            let mut file =
                match open_relative_for_update(parent, OsStr::new(&name), FILE_CREATE, true) {
                    Ok(file) => file,
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(read_io_error(error)),
                };
            let identity = file_identity(&file).map_err(read_io_error)?;
            if file
                .write_all(bytes)
                .and_then(|()| file.sync_all())
                .is_err()
            {
                drop(file);
                remove_named_if_identity(parent, &name, identity);
                return Err(denied());
            }
            return Ok((name, file, identity));
        }
        Err(denied())
    }

    fn move_to_unique_backup(&mut self, file: &StdFile, parent: &StdFile) -> Result<(), PortError> {
        let generation = self.temp_generation;
        self.temp_generation = self.temp_generation.checked_add(1).ok_or_else(denied)?;
        for attempt in 0..MAX_TEMP_CREATE_ATTEMPTS {
            let name = format!(".lat-write-{}-{generation}-{attempt}.bak", self.temp_key);
            match rename_noreplace(file, parent, OsStr::new(&name)) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(read_io_error(error)),
            }
        }
        Err(denied())
    }

    fn open_rename_parent(&self, expected: &Dir) -> Result<StdFile, PortError> {
        let (parent, name) = if self.directories.len() == 1 {
            (&self.root_parent, &self.directory_names[0])
        } else {
            (
                &self.directories[self.directories.len() - 2],
                self.directory_names
                    .last()
                    .expect("directory name retained"),
            )
        };
        open_rename_parent(parent, name, expected)
    }

    fn revalidate_parent(&self) -> Result<Dir, PortError> {
        let mut parent = self.root_parent.try_clone().map_err(read_io_error)?;
        for (index, ((name, retained), expected_identity)) in self
            .directory_names
            .iter()
            .zip(&self.directories)
            .zip(&self.directory_identities)
            .enumerate()
        {
            if file_identity(retained).map_err(read_io_error)? != *expected_identity {
                return Err(denied());
            }
            if index == 0 {
                require_exact_registered_name(&parent, name).map_err(read_io_error)?;
            } else {
                require_exact_name(&parent, name).map_err(read_io_error)?;
            }
            let reopened = parent.open_dir_nofollow(name).map_err(read_io_error)?;
            reject_reparse_directory(&reopened).map_err(read_io_error)?;
            if file_identity(&reopened).map_err(read_io_error)? != *expected_identity {
                return Err(denied());
            }
            parent = reopened;
        }
        Ok(parent)
    }

    fn require_target(
        &self,
        parent: &Dir,
        expected: &ExpectedTarget,
    ) -> Result<Option<VerifiedWrite>, PortError> {
        let observed = observe_target(parent, &self.leaf_name)?;
        if &observed != expected {
            return Err(denied());
        }
        match observed {
            ExpectedTarget::Absent => Ok(None),
            ExpectedTarget::Present { verified, .. } => Ok(Some(verified)),
        }
    }
}

fn open_relative_for_update(
    parent: &Dir,
    name: &OsStr,
    disposition: u32,
    writable: bool,
) -> std::io::Result<StdFile> {
    let desired_access = FILE_GENERIC_READ
        | FILE_READ_ATTRIBUTES
        | DELETE
        | SYNCHRONIZE
        | if writable { FILE_GENERIC_WRITE } else { 0 };
    open_relative_native(
        parent,
        name,
        disposition,
        desired_access,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_NON_DIRECTORY_FILE,
    )
}

fn open_rename_parent(parent: &Dir, name: &OsStr, expected: &Dir) -> Result<StdFile, PortError> {
    let opened = open_relative_native(
        parent,
        name,
        FILE_OPEN,
        FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_DIRECTORY_FILE,
    )
    .map_err(read_io_error)?;
    let metadata = opened.metadata().map_err(read_io_error)?;
    if !metadata.is_dir()
        || std::os::windows::fs::MetadataExt::file_attributes(&metadata)
            & FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        || file_identity(&opened).map_err(read_io_error)?
            != file_identity(expected).map_err(read_io_error)?
    {
        return Err(denied());
    }
    Ok(opened)
}

fn open_relative_native(
    parent: &Dir,
    name: &OsStr,
    disposition: u32,
    desired_access: u32,
    share_access: u32,
    kind: u32,
) -> std::io::Result<StdFile> {
    let mut name = name.encode_wide().collect::<Vec<_>>();
    let byte_length = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let unicode_name = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle() as HANDLE,
        ObjectName: &unicode_name,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: ptr::null(),
        SecurityQualityOfService: ptr::null(),
    };
    let mut handle: HANDLE = ptr::null_mut();
    let mut io_status = IO_STATUS_BLOCK::default();
    // SAFETY: all pointers reference initialized values for this synchronous
    // call, and a successful uniquely owned handle is converted exactly once.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            desired_access,
            &attributes,
            &mut io_status,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share_access,
            disposition,
            kind | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            ptr::null(),
            0,
        )
    };
    if status == STATUS_OBJECT_NAME_COLLISION {
        return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
    }
    if status != STATUS_SUCCESS || handle.is_null() {
        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    // SAFETY: successful `NtCreateFile` returned one uniquely owned handle.
    Ok(unsafe { StdFile::from_raw_handle(handle) })
}

fn retain_expected_target(
    parent: &Dir,
    name: &str,
    expected: &ExpectedTarget,
) -> Result<RetainedTarget, PortError> {
    match expected {
        ExpectedTarget::Absent => {
            if bounded_exact_name_exists(parent, OsStr::new(name)).map_err(read_io_error)? {
                return Err(denied());
            }
            Ok(RetainedTarget::Absent)
        }
        ExpectedTarget::Present { .. } => {
            require_exact_name(parent, OsStr::new(name)).map_err(read_io_error)?;
            let mut file = open_relative_for_update(parent, OsStr::new(name), FILE_OPEN, false)
                .map_err(read_io_error)?;
            let metadata = file.metadata().map_err(read_io_error)?;
            if metadata.is_dir()
                || std::os::windows::fs::MetadataExt::file_attributes(&metadata)
                    & FILE_ATTRIBUTE_REPARSE_POINT
                    != 0
            {
                return Err(denied());
            }
            let observed = ExpectedTarget::Present {
                identity: file_identity(&file).map_err(read_io_error)?,
                verified: verified_write(&read_bounded(&mut file)?)?,
            };
            if &observed != expected {
                return Err(denied());
            }
            Ok(RetainedTarget::Present(file))
        }
    }
}

fn rename_noreplace(file: &StdFile, parent: &StdFile, name: &OsStr) -> std::io::Result<()> {
    let name = name.encode_wide().collect::<Vec<_>>();
    let name_bytes = name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u32::try_from(length).ok())
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let buffer_bytes = size_of::<FILE_RENAME_INFORMATION>()
        .checked_add(name_bytes as usize)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let words = buffer_bytes
        .checked_add(size_of::<usize>() - 1)
        .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?
        / size_of::<usize>();
    let mut buffer = vec![0_usize; words];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    let mut io_status = IO_STATUS_BLOCK::default();
    // SAFETY: the aligned buffer holds the fixed structure and exact UTF-16
    // name. Both retained handles stay valid for the synchronous call.
    let status = unsafe {
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = parent.as_raw_handle() as HANDLE;
        (*info).FileNameLength = name_bytes;
        ptr::copy_nonoverlapping(
            name.as_ptr(),
            ptr::addr_of_mut!((*info).FileName).cast::<u16>(),
            name.len(),
        );
        NtSetInformationFile(
            file.as_raw_handle() as HANDLE,
            &mut io_status,
            info.cast(),
            buffer_bytes as u32,
            FileRenameInformation,
        )
    };
    if status == STATUS_OBJECT_NAME_COLLISION {
        return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
    }
    if status != STATUS_SUCCESS {
        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    Ok(())
}

fn mark_for_deletion(file: &StdFile) -> Result<(), PortError> {
    let mut disposition = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: `disposition` is the exact buffer required by the API and the
    // retained file handle was opened with DELETE access.
    let success = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            FileDispositionInfoEx,
            ptr::from_mut(&mut disposition).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if success == 0 {
        return Err(denied());
    }
    Ok(())
}

fn open_registered_root(path: &Path) -> Result<(Dir, OsString, Dir), PortError> {
    let absolute = std::path::absolute(path).map_err(configuration_io_error)?;
    let (anchor, mut components) = anchored_components(&absolute)?;
    let root_name = components.pop().ok_or_else(invalid_input)?;
    let mut parent =
        Dir::open_ambient_dir(anchor, ambient_authority()).map_err(configuration_io_error)?;
    for component in components {
        require_exact_registered_name(&parent, &component).map_err(configuration_io_error)?;
        parent = parent
            .open_dir_nofollow(&component)
            .map_err(configuration_io_error)?;
        reject_reparse_directory(&parent).map_err(configuration_io_error)?;
    }
    require_exact_registered_name(&parent, &root_name).map_err(configuration_io_error)?;
    let root = parent
        .open_dir_nofollow(&root_name)
        .map_err(configuration_io_error)?;
    reject_reparse_directory(&root).map_err(configuration_io_error)?;
    Ok((parent, root_name, root))
}

fn anchored_components(path: &Path) -> Result<(PathBuf, Vec<OsString>), PortError> {
    let mut anchor = PathBuf::new();
    let mut components = Vec::new();
    let mut saw_normal = false;
    for component in path.components() {
        match component {
            Component::Prefix(prefix) if !saw_normal => match prefix.kind() {
                Prefix::Disk(_) => anchor.push(component),
                _ => return Err(invalid_input()),
            },
            Component::RootDir if !saw_normal => anchor.push(component),
            Component::Normal(name) => {
                saw_normal = true;
                components.push(name.to_owned());
            }
            Component::CurDir => {}
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => {
                return Err(invalid_input())
            }
        }
    }
    if anchor.as_os_str().is_empty() {
        return Err(invalid_input());
    }
    Ok((anchor, components))
}

fn open_file_nofollow(root: Dir, components: &[String]) -> Result<OpenedFile, PortError> {
    open_optional_file_from_root(root, components)?.ok_or_else(denied)
}

fn open_optional_file_from_root(
    root: Dir,
    components: &[String],
) -> Result<Option<OpenedFile>, PortError> {
    if components.is_empty() {
        return Err(denied());
    }
    let mut directories = vec![root];
    for component in &components[..components.len() - 1] {
        validate_windows_component(component)?;
        let parent = directories.last().expect("root directory is retained");
        require_exact_name(parent, OsStr::new(component)).map_err(read_io_error)?;
        let child = parent.open_dir_nofollow(component).map_err(read_io_error)?;
        reject_reparse_directory(&child).map_err(read_io_error)?;
        directories.push(child);
    }
    let leaf = components.last().expect("non-empty components");
    let parent = directories.last().expect("root directory is retained");
    let Some(file) = open_optional_file_nofollow(parent, leaf)? else {
        return Ok(None);
    };
    Ok(Some(OpenedFile {
        _directories: directories,
        file,
    }))
}

fn open_optional_file_nofollow(parent: &Dir, name: &str) -> Result<Option<File>, PortError> {
    validate_windows_component(name)?;
    if !bounded_exact_name_exists(parent, OsStr::new(name)).map_err(read_io_error)? {
        return Ok(None);
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = parent.open_with(name, &options).map_err(read_io_error)?;
    let metadata = file.metadata().map_err(read_io_error)?;
    if metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(denied());
    }
    Ok(Some(file))
}

fn observe_target(parent: &Dir, name: &str) -> Result<ExpectedTarget, PortError> {
    let Some(mut file) = open_optional_file_nofollow(parent, name)? else {
        return Ok(ExpectedTarget::Absent);
    };
    let identity = file_identity(&file).map_err(read_io_error)?;
    let bytes = read_bounded(&mut file)?;
    Ok(ExpectedTarget::Present {
        identity,
        verified: verified_write(&bytes)?,
    })
}

fn verified_write(bytes: &[u8]) -> Result<VerifiedWrite, PortError> {
    Ok(VerifiedWrite {
        digest: Sha256Digest::new(format!("sha256:{:x}", Sha256::digest(bytes)))
            .map_err(|_| denied())?,
        size_bytes: u64::try_from(bytes.len()).map_err(|_| denied())?,
    })
}

fn temp_key(execution_id: &str) -> String {
    format!("{:x}", Sha256::digest(execution_id.as_bytes()))
}

fn require_named_identity(
    parent: &Dir,
    name: &str,
    expected: FileIdentity,
) -> Result<(), PortError> {
    let file = open_optional_file_nofollow(parent, name)?.ok_or_else(denied)?;
    if file_identity(&file).map_err(read_io_error)? != expected {
        return Err(denied());
    }
    Ok(())
}

fn remove_named_if_identity(parent: &Dir, name: &str, expected: FileIdentity) {
    let matching = open_optional_file_nofollow(parent, name)
        .ok()
        .flatten()
        .and_then(|file| file_identity(&file).ok())
        == Some(expected);
    if matching && parent.remove_file(name).is_ok() {
        drop(sync_directory_handle(parent));
    }
}

fn sync_directory_handle(directory: &Dir) -> Result<(), PortError> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .maybe_dir(true)
        .follow(FollowSymlinks::No);
    directory
        .open_with(".", &options)
        .map_err(read_io_error)?
        .sync_all()
        .map_err(read_io_error)
}

fn read_bounded(file: &mut (impl Read + Seek)) -> Result<Vec<u8>, PortError> {
    file.seek(SeekFrom::Start(0)).map_err(read_io_error)?;
    let mut bytes = Vec::new();
    file.take((MAX_READ_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(read_io_error)?;
    if bytes.len() > MAX_READ_BYTES {
        return Err(denied());
    }
    Ok(bytes)
}

fn require_exact_registered_name(directory: &Dir, expected: &OsStr) -> std::io::Result<()> {
    if exact_name_exists(directory, expected)? {
        Ok(())
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::NotFound))
    }
}

fn require_exact_name(directory: &Dir, expected: &OsStr) -> std::io::Result<()> {
    if bounded_exact_name_exists(directory, expected)? {
        Ok(())
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::NotFound))
    }
}

fn exact_name_exists(directory: &Dir, expected: &OsStr) -> std::io::Result<bool> {
    let mut expected_name = expected.encode_wide().collect::<Vec<_>>();
    if !is_queryable_exact_name(&expected_name) {
        return Ok(false);
    }
    let byte_length = expected_name
        .len()
        .checked_mul(size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(invalid_directory_query)?;
    let unicode_name = UNICODE_STRING {
        Length: byte_length,
        MaximumLength: byte_length,
        Buffer: expected_name.as_mut_ptr(),
    };
    let mut options = OpenOptions::new();
    options
        .read(true)
        .maybe_dir(true)
        .follow(FollowSymlinks::No);
    // Directory queries retain their first filter on a file object. Open a
    // fresh nofollow handle relative to the retained capability directory so
    // this lookup cannot affect later exact-name queries.
    let query_directory = directory.open_with(".", &options)?;
    let mut buffer = vec![0_u8; MAX_EXACT_NAME_QUERY_BYTES];
    let buffer_length = u32::try_from(buffer.len()).map_err(|_| invalid_directory_query())?;
    let mut io_status = IO_STATUS_BLOCK::default();
    // SAFETY: `query_directory` is a live directory handle opened relative to
    // `directory`; `unicode_name` points to the nonempty, bounded UTF-16
    // storage in `expected_name`; and `io_status` plus `buffer` are writable
    // for the synchronous call and remain alive until it returns.
    let status = unsafe {
        NtQueryDirectoryFile(
            query_directory.as_raw_handle() as HANDLE,
            ptr::null_mut(),
            None,
            ptr::null(),
            &mut io_status,
            buffer.as_mut_ptr().cast(),
            buffer_length,
            FileDirectoryInformation,
            true,
            &unicode_name,
            true,
        )
    };
    if status == STATUS_NO_SUCH_FILE || status == STATUS_NO_MORE_FILES {
        return Ok(false);
    }
    if status != STATUS_SUCCESS && status != STATUS_BUFFER_OVERFLOW {
        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    exact_name_from_directory_query(&buffer, io_status.Information, &expected_name)
}

fn bounded_exact_name_exists(directory: &Dir, expected: &OsStr) -> std::io::Result<bool> {
    let expected_folded = expected.to_string_lossy().to_lowercase();
    let mut exact = false;
    let mut count = 0_usize;
    for entry in directory.entries()? {
        count = count
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("directory bound"))?;
        if count > MAX_DIRECTORY_ENTRIES {
            return Err(std::io::Error::other("directory bound"));
        }
        let name = entry?.file_name();
        if name == expected {
            exact = true;
        } else if name.to_string_lossy().to_lowercase() == expected_folded {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "case mismatch",
            ));
        }
    }
    Ok(exact)
}

fn is_queryable_exact_name(name: &[u16]) -> bool {
    !name.is_empty()
        && !name
            .iter()
            .any(|unit| *unit == u16::from(b'*') || *unit == u16::from(b'?'))
        && !matches!(
            name.last(),
            Some(unit) if *unit == u16::from(b'.') || *unit == u16::from(b' ')
        )
}

fn exact_name_from_directory_query(
    buffer: &[u8],
    returned: usize,
    expected: &[u16],
) -> std::io::Result<bool> {
    let name_offset = std::mem::offset_of!(FILE_DIRECTORY_INFORMATION, FileName);
    if returned < name_offset || returned > buffer.len() || name_offset % size_of::<u16>() != 0 {
        return Err(invalid_directory_query());
    }

    let mut offset = 0_usize;
    while offset < returned {
        let entry = buffer
            .get(offset..returned)
            .ok_or_else(invalid_directory_query)?;
        if entry.len() < name_offset {
            return Err(invalid_directory_query());
        }
        let next_offset = usize::try_from(directory_query_u32(
            entry,
            std::mem::offset_of!(FILE_DIRECTORY_INFORMATION, NextEntryOffset),
        )?)
        .map_err(|_| invalid_directory_query())?;
        let name_bytes = usize::try_from(directory_query_u32(
            entry,
            std::mem::offset_of!(FILE_DIRECTORY_INFORMATION, FileNameLength),
        )?)
        .map_err(|_| invalid_directory_query())?;
        let name_end = name_offset
            .checked_add(name_bytes)
            .ok_or_else(invalid_directory_query)?;
        if name_bytes == 0 || name_bytes % size_of::<u16>() != 0 || name_end > entry.len() {
            return Err(invalid_directory_query());
        }
        if !matches_exact_utf16_name(&entry[name_offset..name_end], expected) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "case mismatch",
            ));
        }
        if next_offset == 0 {
            return Ok(true);
        }
        if next_offset < name_end
            || next_offset % size_of::<u16>() != 0
            || next_offset > entry.len()
        {
            return Err(invalid_directory_query());
        }
        offset = offset
            .checked_add(next_offset)
            .ok_or_else(invalid_directory_query)?;
    }
    Err(invalid_directory_query())
}

fn directory_query_u32(entry: &[u8], offset: usize) -> std::io::Result<u32> {
    let end = offset
        .checked_add(size_of::<u32>())
        .ok_or_else(invalid_directory_query)?;
    let bytes: [u8; size_of::<u32>()] = entry
        .get(offset..end)
        .ok_or_else(invalid_directory_query)?
        .try_into()
        .map_err(|_| invalid_directory_query())?;
    Ok(u32::from_le_bytes(bytes))
}

fn matches_exact_utf16_name(name: &[u8], expected: &[u16]) -> bool {
    name.chunks_exact(size_of::<u16>())
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
        .eq(expected.iter().copied())
}

fn invalid_directory_query() -> std::io::Error {
    std::io::Error::from(std::io::ErrorKind::InvalidData)
}

fn reject_reparse_directory(directory: &Dir) -> std::io::Result<()> {
    if directory.dir_metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "reparse directory",
        ));
    }
    Ok(())
}

fn relative_components(path: &str) -> Result<RelativePathComponents, PortError> {
    if path == "." {
        return Err(denied());
    }
    let components = path
        .split(['/', '\\'])
        .map(str::to_owned)
        .collect::<Vec<_>>();
    for component in &components {
        validate_windows_component(component)?;
    }
    RelativePathComponents::new(components).map_err(|_| denied())
}

fn validate_windows_component(component: &str) -> Result<(), PortError> {
    if valid_windows_component(component) {
        Ok(())
    } else {
        Err(denied())
    }
}

fn valid_windows_component(component: &str) -> bool {
    !component.is_empty()
        && component.encode_utf16().count() <= 255
        && !component.ends_with(['.', ' '])
        && !component
            .chars()
            .any(|character| character <= '\u{1f}' || r#"<>:"/\|?*"#.contains(character))
}

fn file_identity(handle: &impl AsRawHandle) -> std::io::Result<FileIdentity> {
    let mut information = FILE_ID_INFO::default();
    // SAFETY: `handle` owns a live Windows handle, `information` is writable for
    // exactly `FILE_ID_INFO` bytes, and the value is read only after API success.
    let succeeded = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle(),
            FileIdInfo,
            (&raw mut information).cast(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>())
                .expect("FILE_ID_INFO size fits in u32"),
        )
    };
    if succeeded == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(FileIdentity {
        volume_serial_number: information.VolumeSerialNumber,
        file_id: information.FileId.Identifier,
    })
}

fn invalid_input() -> PortError {
    PortError::failure(
        SafeErrorClassification::InvalidInput,
        Retryability::NonRetryable,
    )
}

fn denied() -> PortError {
    PortError::failure(
        SafeErrorClassification::PermissionDenied,
        Retryability::NonRetryable,
    )
}

fn configuration_io_error(_error: std::io::Error) -> PortError {
    PortError::failure(
        SafeErrorClassification::Internal,
        Retryability::NonRetryable,
    )
}

fn read_io_error(_error: std::io::Error) -> PortError {
    denied()
}
