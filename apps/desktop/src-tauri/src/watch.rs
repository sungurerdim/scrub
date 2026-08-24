//! Turning a stage's progress into something the window can draw.
//!
//! A scan walks tens of thousands of directories a second and an analysis reads
//! thousands of files. Sending an event for each would flood the channel between
//! the two sides and leave the window spending its time on messages rather than
//! on drawing them, so this throttles to a few a second — often enough that the
//! numbers move, rarely enough that nothing queues up.

use std::path::Path;
use std::time::{Duration, Instant};

use scrub_run::{Pass, Watch};
use serde::Serialize;
use tauri::{AppHandle, Emitter as _, Runtime};

/// How often progress is sent at most.
const AT_MOST_EVERY: Duration = Duration::from_millis(120);

/// The name the window listens for.
pub const PROGRESS: &str = "scrub://progress";

/// What the window is told while a stage runs.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Which stage: `walking`, `sampling`, `reading`, or `operating`.
    pub phase: &'static str,
    /// What is being worked on, where there is something to name.
    pub subject: String,
    /// How far along, in whatever the phase counts.
    pub done: usize,
    /// How far there is to go, where that is known.
    ///
    /// A walk does not know: it discovers directories as it goes, and a bar
    /// that invented a total would be a bar that lies. The window shows a count
    /// rather than a proportion when this is absent (DR-15).
    pub total: Option<usize>,
    /// How many places could not be read so far, during a walk.
    pub unread: usize,
}

/// Sends progress to the window, no faster than it can use it.
///
/// Generic over the runtime so the same reporter runs under the real window and
/// under the one the tests build, which is what lets the tests cover the
/// commands rather than a copy of them.
pub struct Reporting<R: Runtime> {
    app: AppHandle<R>,
    /// When the last report went out; absent until the first one does.
    ///
    /// Absent rather than a time in the past: subtracting an interval from the
    /// current instant is not something every platform can do, because the
    /// clock's origin may be more recent than the interval.
    last_sent: Option<Instant>,
    total: Option<usize>,
}

impl<R: Runtime> Reporting<R> {
    /// Starts reporting to this window.
    #[must_use]
    pub fn new(app: AppHandle<R>) -> Self {
        Self {
            app,
            last_sent: None,
            total: None,
        }
    }

    /// Whether enough time has passed to be worth telling the window again.
    ///
    /// The first call is always due, so the window shows something the moment
    /// work starts rather than after the first interval has elapsed.
    fn due(&mut self) -> bool {
        if self
            .last_sent
            .is_some_and(|last| last.elapsed() < AT_MOST_EVERY)
        {
            return false;
        }
        self.last_sent = Some(Instant::now());
        true
    }

    /// Sends whatever happens, for the moments that must not be dropped.
    fn send(&mut self, report: &Report) {
        self.last_sent = Some(Instant::now());
        // A window that has gone away is not an error worth stopping work for:
        // the artifact is still being written, and it is still what matters.
        let _ = self.app.emit(PROGRESS, report);
    }
}

impl<R: Runtime> Watch for Reporting<R> {
    fn walking(&mut self, _root: &Path, state: &scrub_platform::walk::Progress<'_>) {
        if self.due() {
            let report = Report {
                phase: "walking",
                subject: state.directory.to_string_lossy().into_owned(),
                done: state.found,
                total: None,
                unread: state.unread,
            };
            self.send(&report);
        }
    }

    fn pass_begins(&mut self, pass: Pass, total: usize) {
        self.total = Some(total);
        let report = Report {
            phase: phase_of(pass),
            subject: String::new(),
            done: 0,
            total: Some(total),
            unread: 0,
        };
        self.send(&report);
    }

    fn reading(&mut self, pass: Pass, done: usize, _bytes: u64) {
        let total = self.total;
        if self.due() {
            let report = Report {
                phase: phase_of(pass),
                subject: String::new(),
                done,
                total,
                unread: 0,
            };
            self.send(&report);
        }
    }

    fn operating(&mut self, done: usize, total: usize) {
        // Never throttled. There are tens of these, not thousands, and each one
        // is a change to somebody's files: a person watching should see every
        // one of them go by.
        let report = Report {
            phase: "operating",
            subject: String::new(),
            done,
            total: Some(total),
            unread: 0,
        };
        self.send(&report);
    }
}

fn phase_of(pass: Pass) -> &'static str {
    match pass {
        Pass::Sampling => "sampling",
        Pass::Reading => "reading",
    }
}
