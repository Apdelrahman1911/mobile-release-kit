//! Memory/correlation tests only. No Session, native receipt or join is faked.
use super::*;
fn id(n: char) -> Id {
    Id::parse(&n.to_string().repeat(32)).unwrap()
}
fn input(n: char) -> p::Read {
    p::Read {
        origin: p::Query {
            service_instance: id('1'),
            project_id: id('2'),
            request_id: id(n),
        },
        expected_observation_revision: 7,
    }
}
fn source() -> Source {
    Source {
        runtime_id: "runtime-1".into(),
        root: PathBuf::from("/not-opened/configuration-data"),
        device: 1,
        inode: 2,
        observation_revision: 7,
    }
}
fn setup() -> (Inbox, Arc<ReadPermission>) {
    (
        Inbox::new(id('1')),
        Arc::new(ReadPermission::new(
            Instant::now() + Duration::from_secs(300),
        )),
    )
}
#[test]
fn duplicate_read_is_same_data_and_other_request_cannot_replace_live_or_unknown_original() {
    let (book, read) = setup();
    let a = input('3');
    let first = book.read(a.clone(), source(), read.clone()).unwrap();
    assert_eq!(book.read(a.clone(), source(), read.clone()).unwrap(), first);
    let mut drift = a.clone();
    drift.expected_observation_revision = 8;
    assert_eq!(
        book.read(drift, source(), read.clone()).unwrap_err(),
        Error::Conflict
    );
    assert_eq!(
        book.read(input('4'), source(), read.clone()).unwrap_err(),
        Error::Busy
    );
    let entry = book.entry(&a.origin).unwrap();
    assert!(entry.dispatch(Kind::Read).unwrap());
    entry.claim_open().unwrap();
    assert!(entry.claim_open().is_err());
    entry.dispatch_failed();
    assert_eq!(entry.status().unwrap().phase, p::Phase::Unknown);
    entry.cancel(Instant::now()).unwrap();
    assert_eq!(entry.status().unwrap().phase, p::Phase::Unknown);
    assert_eq!(
        book.read(input('4'), source(), read).unwrap_err(),
        Error::Busy
    );
}
#[test]
fn read_permission_never_supplies_an_original_preview_or_apply_grant() {
    let (book, read) = setup();
    let a = input('3');
    book.read(a.clone(), source(), read).unwrap();
    let e = book.entry(&a.origin).unwrap();
    let original = p::Original {
        session_id: id('4'),
        owner_generation: id('5'),
        revision: id('6'),
    };
    assert_eq!(
        e.prepare(p::Prepare {
            origin: a.origin.clone(),
            original: original.clone(),
            change: p::Change::Source {
                candidate_branch: "next".into(),
                production_branch: "production".into()
            }
        })
        .unwrap_err(),
        Error::Conflict
    );
    assert_eq!(
        e.apply(p::Apply {
            origin: a.origin.clone(),
            original: original.clone(),
            plan_token: id('7'),
            reviewed: true
        })
        .unwrap_err(),
        Error::AccessDenied
    );
    assert_eq!(
        e.allow(
            &p::Allow {
                origin: a.origin,
                original,
                plan_token: id('7'),
                expected_native_status_revision: 1,
                consent_version: p::CONSENT.into()
            },
            Instant::now() + Duration::from_secs(60)
        )
        .unwrap_err(),
        Error::Conflict
    );
    assert!(e.history().unwrap().is_none());
    assert!(!e.bound(id('4').as_str(), id('5').as_str()));
}
#[test]
fn native_poll_retains_the_earliest_read_or_explicit_stop_without_a_renderer() {
    let (book, read) = setup();
    let a = input('3');
    book.read(a.clone(), source(), read.clone()).unwrap();
    let e = book.entry(&a.origin).unwrap();
    let first = Instant::now();
    read.revoke(first);
    e.cancel(first + Duration::from_secs(1)).unwrap();
    assert_eq!(
        e.stop_at(first + Duration::from_secs(5)).unwrap(),
        Some(first)
    );
    assert!(!e.live(first));
    assert_eq!(e.status().unwrap().phase, p::Phase::Refused);
    assert!(e.dispatch(Kind::Read).is_ok_and(|b| !b));
    let expiry = Instant::now() - Duration::from_secs(1);
    let expired = Arc::new(ReadPermission::new(expiry));
    assert!(book.read(input('4'), source(), expired).is_err());
}
#[test]
fn exactly_thirty_two_cancelled_metadata_rows_stay_discoverable_without_history_eviction() {
    let (book, read) = setup();
    for n in 1..=p::REQUEST_LIMIT {
        let mut a = input('3');
        a.origin.request_id = Id::parse(&format!("{n:032x}")).unwrap();
        book.read(a.clone(), source(), read.clone()).unwrap();
        book.entry(&a.origin)
            .unwrap()
            .cancel(Instant::now())
            .unwrap();
    }
    assert_eq!(book.catalogue(&id('2')).unwrap().len(), 32);
    assert_eq!(
        book.read(input('f'), source(), read).unwrap_err(),
        Error::Busy
    );
    assert_eq!(book.entries().unwrap().len(), 32);
    for e in book.entries().unwrap() {
        assert!(e.history().unwrap().is_none());
    }
}
#[test]
fn exact_desktop_query_keeps_old_refusal_after_latest_row_without_fallback() {
    let (book, read) = setup();
    let old = input('3');
    book.read(old.clone(), source(), read.clone()).unwrap();
    let entry = book.entry(&old.origin).unwrap();
    entry.cancel(Instant::now()).unwrap(); // Actually unclaimed: no native receipt.
    let refused = entry.status().unwrap();
    assert_eq!(refused.phase, p::Phase::Refused);
    assert!(refused.original.is_none() && refused.result.is_none());

    let next = input('4');
    book.read(next.clone(), source(), read).unwrap();
    let latest = book.desktop().unwrap();
    assert_eq!(latest.request.as_ref().unwrap().origin, next.origin);
    let selected = book.desktop_request(&old.origin).unwrap();
    assert_eq!(selected.request, Some(refused));
    assert_eq!(selected.revision, latest.revision);
    assert_eq!(book.desktop().unwrap(), latest);
    for field in 0..3 {
        let mut wrong = old.origin.clone();
        match field {
            0 => wrong.service_instance = id('f'),
            1 => wrong.project_id = id('f'),
            _ => wrong.request_id = id('f'),
        }
        assert_eq!(book.desktop_request(&wrong).unwrap_err(), Error::Conflict);
    }

    let pending = book.entry(&next.origin).unwrap();
    assert!(pending.dispatch(Kind::Read).unwrap());
    pending.claim_open().unwrap();
    pending.dispatch_failed(); // A failed claimed dispatch is not known retirement.
    assert_eq!(
        book.desktop_request(&next.origin)
            .unwrap()
            .request
            .unwrap()
            .phase,
        p::Phase::Unknown
    );
    assert_eq!(
        book.desktop_request(&old.origin)
            .unwrap()
            .request
            .unwrap()
            .phase,
        p::Phase::Refused
    );
    assert!(pending.occupied().unwrap());
}
#[test]
fn wrong_origin_close_and_poison_cannot_rearm_a_prior_request() {
    let (book, read) = setup();
    let a = input('3');
    book.read(a.clone(), source(), read.clone()).unwrap();
    let mut bad = a.origin.clone();
    bad.project_id = id('f');
    assert!(book.entry(&bad).is_err());
    book.close(Instant::now());
    assert_eq!(
        book.read(a.clone(), source(), read.clone()).unwrap().phase,
        p::Phase::Refused
    );
    assert_eq!(
        book.read(input('4'), source(), read.clone()).unwrap_err(),
        Error::Unavailable
    );
    book.fence();
    assert_eq!(
        book.entry(&a.origin).unwrap().status().unwrap_err(),
        Error::StateUnknown
    );
}
#[test]
fn exhausted_original_status_or_publication_counter_fences_the_same_inbox() {
    for publication in [false, true] {
        let (book, read) = setup();
        let a = input('3');
        book.read(a.clone(), source(), read.clone()).unwrap();
        let entry = book.entry(&a.origin).unwrap();
        if publication {
            book.changes.send_replace(u32::MAX);
        } else {
            entry.row.lock().unwrap().status.revision = u32::MAX;
        }
        assert_eq!(entry.cancel(Instant::now()), Err(Error::StateUnknown));
        assert!(!entry.live(Instant::now()));
        assert_eq!(entry.status().unwrap_err(), Error::StateUnknown);
        assert_eq!(
            book.read(input('4'), source(), read).unwrap_err(),
            Error::Unavailable
        );
    }
}

#[test]
fn metadata_five_retained_copies_and_max_width_rows_fit_the_unchanged_cell() {
    use std::mem::size_of;
    // Count actual owned capacities, not encoded bytes. Fixed Row/Entry cells
    // already contain each Option/enum/Box header. The original shared watch,
    // READ, native/GUI and IPC controls keep their existing separate debits.
    fn q(v: &p::Query) -> usize {
        v.service_instance.retained_bytes()
            + v.project_id.retained_bytes()
            + v.request_id.retained_bytes()
    }
    fn original(v: &p::Original) -> usize {
        v.session_id.retained_bytes()
            + v.owner_generation.retained_bytes()
            + v.revision.retained_bytes()
    }
    fn metadata(v: &p::Metadata) -> usize {
        v.root.len()
            + [&v.android_locales, &v.ios_locales]
                .into_iter()
                .map(|a| a.len() * size_of::<Box<str>>() + a.iter().map(|s| s.len()).sum::<usize>())
                .sum::<usize>()
    }
    fn container(v: &p::Container) -> usize {
        match v {
            p::Container::Project(s) | p::Container::Workspace(s) => s.capacity(),
        }
    }
    fn settings(v: &p::Settings) -> usize {
        v.source.candidate_branch.capacity()
            + v.source.production_branch.capacity()
            + v.android.as_ref().map_or(0, |a| {
                a.module.as_ref().map_or(0, String::capacity)
                    + a.variant.as_ref().map_or(0, String::capacity)
            })
            + v.ios.as_ref().map_or(0, |i| {
                i.container.as_ref().map_or(0, container)
                    + i.scheme.as_ref().map_or(0, String::capacity)
                    + i.archive_configuration.as_ref().map_or(0, String::capacity)
            })
            + v.metadata.as_ref().map_or(0, metadata)
    }
    fn change(v: &p::Change) -> usize {
        match v {
            p::Change::Source {
                candidate_branch,
                production_branch,
            } => candidate_branch.capacity() + production_branch.capacity(),
            p::Change::Android { module, variant } => module.capacity() + variant.capacity(),
            p::Change::Ios {
                container: c,
                scheme,
                archive_configuration,
            } => container(c) + scheme.capacity() + archive_configuration.capacity(),
            p::Change::Metadata(m) => metadata(m),
        }
    }
    fn row_heap(v: &Row) -> usize {
        let s = &v.status;
        q(&s.origin)
            + s.runtime_project_id.capacity()
            + [&s.operation_id, &s.owner_generation]
                .into_iter()
                .map(|v| v.as_ref().map_or(0, Id::retained_bytes))
                .sum::<usize>()
            + s.original.as_ref().map_or(0, original)
            + s.settings.as_ref().map_or(0, settings)
            + s.change.as_ref().map_or(0, change)
            + s.review.as_ref().map_or(0, |r| {
                r.plan_token.retained_bytes()
                    + settings(&r.before)
                    + settings(&r.after)
                    + r.files.capacity() * size_of::<p::File>()
                    + r.files
                        .iter()
                        .map(|f| f.path.capacity() + f.action.capacity())
                        .sum::<usize>()
                    + r.ignore_additions.capacity() * size_of::<String>()
                    + r.ignore_additions
                        .iter()
                        .map(String::capacity)
                        .sum::<usize>()
            })
            + v.binding
                .as_ref()
                .map_or(0, |(s, g, _)| s.retained_bytes() + g.retained_bytes())
            + v.prepare.as_ref().map_or(0, |v| {
                q(&v.origin) + original(&v.original) + change(&v.change)
            })
            + v.apply.as_ref().map_or(0, |v| {
                q(&v.origin) + original(&v.original) + v.plan_token.retained_bytes()
            })
    }
    fn wide(
        m: &p::Metadata,
        mut trim: usize,
        ignored: usize,
        final_data: bool,
    ) -> Option<p::Status> {
        let mut width = |max: usize, min: usize| {
            let n = trim.min(max - min);
            trim -= n;
            max - n
        };
        let base = serde_json::json!({"schemaVersion":1,
            "source":{"candidateBranch":"a".repeat(width(255,1)),"productionBranch":"p".repeat(width(255,1))},
            "android":{"enabled":true,"module":format!(":{}", "m".repeat(width(512,2)-1)),"variant":"R".repeat(width(128,1))},
            "ios":{"enabled":true,"project":format!("{}.xcodeproj", "p".repeat(width(512,11)-10)),"scheme":"s".repeat(width(255,1)),"archiveConfiguration":"c".repeat(width(255,1))},
            "metadata":m,
        });
        let settings = p::Settings::from_base(&base).ok()?;
        settings.metadata.as_ref()?; // An omitted projection is not a default.
        let mut after = settings.clone();
        after.metadata.as_mut().unwrap().root = format!("b{}", &m.root[1..]).into_boxed_str();
        let change = p::Change::Metadata(after.metadata.clone().unwrap());
        Some(p::Status {
            schema_version: 1,
            origin: input('3').origin,
            revision: 1,
            runtime_project_id: "r".repeat(64),
            phase: if final_data {
                p::Phase::Final
            } else {
                p::Phase::Unknown
            },
            operation_id: Some(id('4')),
            owner_generation: Some(id('5')),
            original: Some(p::Original {
                session_id: id('4'),
                owner_generation: id('5'),
                revision: id('6'),
            }),
            settings: Some(settings.clone()),
            change: Some(change),
            review: Some(p::Review {
                plan_token: id('7'),
                native_status_revision: 1,
                before: settings,
                after,
                files: vec![
                    p::File {
                        path: "release/mobile-release.json".into(),
                        action: "replace".into(),
                        before_bytes: None,
                        after_bytes: 0,
                    },
                    p::File {
                        path: ".gitignore".into(),
                        action: "preserve".into(),
                        before_bytes: None,
                        after_bytes: 0,
                    },
                ],
                create_release_directory: false,
                rewrites_config_formatting: true,
                ignore_additions: (0..ignored).map(|_| "i".repeat(128)).collect(),
            }),
            permission_live: false,
            remaining_ms: 0,
            apply_consumed: true,
            cancel_requested: false,
            result: final_data.then_some(p::Final {
                effect: p::Effect::Committed,
                journal: p::Journal::Clean,
                cancelled: false,
                apply_submitted: true,
            }),
            do_not_replay: true,
        })
    }
    let locales = (0..32)
        .map(|n| format!("abc-Latn-{n:03}").into_boxed_str())
        .collect::<Vec<_>>();
    // Largest admitted UTF-8 root with the maximum TOTAL locale count, not a
    // guessed ASCII margin. The fixed 2KiB Change cap remains in force.
    let maximum = (0..512)
        .rev()
        .find_map(|n| {
            let m = p::Metadata {
                root: format!("a{}", "😀".repeat(n)).into_boxed_str(),
                android_locales: locales[..16].to_vec().into_boxed_slice(),
                ios_locales: locales[16..].to_vec().into_boxed_slice(),
            };
            p::Change::Metadata(m.clone())
                .validate()
                .is_ok()
                .then_some(m)
        })
        .unwrap();
    let cell = p::STATUS_BYTES + 8192 + size_of::<Entry>();
    let mut peak = 0;
    for ignored in [0, 8, 16] {
        for final_data in [false, true] {
            // Find the largest remaining legacy projection that fits ALL existing
            // 4/12/16KiB boundaries alongside that maximal new metadata value.
            let (mut lo, mut hi) = (0, 2200);
            let admitted = |trim| {
                wide(&maximum, trim, ignored, final_data).is_some_and(|s| s.validate().is_ok())
            };
            assert!(admitted(hi));
            while lo < hi {
                let mid = (lo + hi) / 2;
                if admitted(mid) {
                    hi = mid
                } else {
                    lo = mid + 1
                }
            }
            let status = wide(&maximum, lo, ignored, final_data).unwrap();
            status.validate().unwrap();
            if lo > 0 {
                assert!(!admitted(lo - 1));
            }
            let input = input('3');
            let original = status.original.clone().unwrap();
            let prepared = p::Prepare {
                origin: input.origin.clone(),
                original: original.clone(),
                change: status.change.clone().unwrap(),
            };
            let apply = p::Apply {
                origin: input.origin.clone(),
                original,
                plan_token: id('7'),
                reviewed: true,
            };
            // Layout DATA only: no bind(), native callback or fabricated retirement.
            let row = Row {
                status,
                dispatch: None,
                claimed: false,
                retired: false,
                binding: Some((id('4'), id('5'), Weak::new())),
                prepare: Some(prepared),
                apply: Some(apply),
                permission_end: None,
                apply_end: None,
                apply_entered: false,
                stop: None,
                history_claimed: false,
            };
            assert_eq!(
                row.status
                    .settings
                    .as_ref()
                    .unwrap()
                    .metadata
                    .as_ref()
                    .unwrap()
                    .android_locales
                    .len(),
                16
            );
            let clones = [
                row.status
                    .settings
                    .as_ref()
                    .unwrap()
                    .metadata
                    .as_ref()
                    .unwrap(),
                row.status
                    .review
                    .as_ref()
                    .unwrap()
                    .before
                    .metadata
                    .as_ref()
                    .unwrap(),
                row.status
                    .review
                    .as_ref()
                    .unwrap()
                    .after
                    .metadata
                    .as_ref()
                    .unwrap(),
            ];
            assert_eq!(
                clones.iter().map(|m| metadata(m)).sum::<usize>(),
                3 * metadata(&maximum)
            );
            assert_eq!(
                change(row.status.change.as_ref().unwrap()),
                metadata(&maximum)
            );
            assert_eq!(
                change(&row.prepare.as_ref().unwrap().change),
                metadata(&maximum)
            );
            let source = Source {
                runtime_id: "r".repeat(64),
                root: PathBuf::from(
                    format!("/{}", "r".repeat(4095))
                        .into_boxed_str()
                        .into_string(),
                ),
                device: 1,
                inode: 2,
                observation_revision: 7,
            };
            let retained = size_of::<Entry>()
                + q(&input.origin)
                + source.runtime_id.capacity()
                + source.root.capacity()
                + row_heap(&row);
            assert!(
                retained <= cell,
                "actual typed row {retained} exceeds original cell {cell}"
            );
            assert!(serde_json::to_vec(&row.status).unwrap().len() <= p::STATUS_BYTES);
            peak = peak.max(retained);
        }
    }
    assert_eq!(DOCUMENT_BACKING, (p::REQUEST_LIMIT + 18) * cell);
    assert!(p::REQUEST_LIMIT * peak + 18 * cell <= DOCUMENT_BACKING);
    assert_eq!(IPC_WORKER_BACKING, crate::service_protocol::REQUEST_BYTES);
    assert!(crate::service_metadata_images_requests::ROW_BYTES <= cell);
    assert!(crate::service_metadata_images_prepare_requests::ROW_BYTES <= cell);
}

#[test]
fn metadata_configuration_still_uses_the_same_joint_thirty_two_editor_slots() {
    use crate::{service_initialization_protocol as init, service_metadata_text_protocol as text};
    let (book, read) = setup();
    let mut originals = Vec::new();
    for n in 1..=p::REQUEST_LIMIT {
        let mut r = input('3');
        r.origin.request_id = Id::parse(&format!("{n:032x}")).unwrap();
        match n % 3 {
            0 => {
                book.read(r.clone(), source(), read.clone()).unwrap();
                book.entry(&r.origin)
                    .unwrap()
                    .cancel(Instant::now())
                    .unwrap();
            }
            1 => {
                book.metadata_read(
                    text::Read {
                        origin: r.origin.clone(),
                        expected_observation_revision: 7,
                        platform: text::Platform::Android,
                        locale: "en-US".into(),
                    },
                    source(),
                    read.clone(),
                )
                .unwrap();
                book.metadata_entry(&r.origin)
                    .unwrap()
                    .cancel(Instant::now())
                    .unwrap();
            }
            _ => {
                book.initialization_prepare(
                    init::Prepare {
                        origin: r.origin.clone(),
                        expected_observation_revision: 7,
                    },
                    source(),
                    read.clone(),
                )
                .unwrap();
                book.initialization_entry(&r.origin)
                    .unwrap()
                    .cancel(Instant::now())
                    .unwrap();
            }
        }
        originals.push(r);
    }
    assert_eq!(book.lock().unwrap().rows.len(), p::REQUEST_LIMIT);
    assert_eq!(book.catalogue(&id('2')).unwrap().len(), p::REQUEST_LIMIT);
    assert_eq!(
        book.read(input('f'), source(), read.clone()).unwrap_err(),
        Error::Busy
    );
    assert_eq!(
        book.metadata_read(
            text::Read {
                origin: input('f').origin,
                expected_observation_revision: 7,
                platform: text::Platform::Android,
                locale: "en-US".into()
            },
            source(),
            read
        )
        .unwrap_err(),
        Error::Busy
    );
    // No original was claimed, so cancellation is genuine pre-admission DATA,
    // not a synthetic native join. A different family cannot adopt its ID.
    let first = &originals[0];
    assert!(book.entry(&first.origin).is_err());
    assert_eq!(
        book.metadata_entry(&first.origin)
            .unwrap()
            .status()
            .unwrap()
            .phase,
        text::Phase::Refused
    );
    assert!(book
        .entries()
        .unwrap()
        .iter()
        .all(|e| e.history().unwrap().is_none()));
}
