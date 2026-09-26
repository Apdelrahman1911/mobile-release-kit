//! Original-STA Project/Quit dialogs. The cross-thread control transports only
//! one fixed close message; COM interfaces never cross the apartment boundary.
use super::*;
use std::{cell::{OnceCell, RefCell}, sync::{OnceLock, Mutex, atomic::{AtomicBool, Ordering}}};
use windows::{core::{implement, Ref, HRESULT}, Win32::{System::Ole::IOleWindow, UI::Shell::*}};
use windows_sys::Win32::{System::LibraryLoader as L, UI::Controls as C};

const CLOSE_MESSAGE: u32 = W::WM_APP + 0x4a1;
const TIMER: usize = 1;
const CANCEL: HRESULT = HRESULT(0x800704c7u32 as i32); // HRESULT_FROM_WIN32(ERROR_CANCELLED)
const CLASS: &[u16] = &[77,82,75,46,79,114,105,103,105,110,97,108,68,105,97,108,111,103,46,118,49,0];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialogResponse { Accept, Decline }
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DialogEvent { Created, ShowEntered, Presented, Response(DialogResponse), ShowReturned, Releasing, Settled, Unknown,
    #[cfg(feature = "windows-installed-observation")]
    ObservationTurn,
}
pub struct DialogResult { pub created: bool, pub response: Option<DialogResponse>, pub selected: Option<PathBuf> }
#[cfg(feature = "windows-installed-observation")]
#[derive(Clone, Copy)]
pub enum DialogAction<'a> { ChooseFolder(&'a Path), Accept, Decline }
#[cfg(feature = "windows-installed-observation")]
#[derive(Clone, Debug)]
pub struct DialogObservation {
    pub kind: DialogKind, pub created: bool, pub showing: bool, pub visible: bool, pub presented: bool,
    pub response: Option<DialogResponse>, pub show_returned: bool, pub callbacks_active: bool, pub observation_turn: bool,
    pub stopped: bool, pub close_entered: bool, pub settled: bool, pub folder_ready: bool,
}
#[cfg(feature = "windows-installed-observation")]
struct FolderAction {
    requested: Cell<bool>, ready: Cell<bool>, input: OnceCell<Vec<u16>>,
    item_output: UnsafeCell<*mut std::ffi::c_void>, item: OnceCell<ComOriginal<IShellItem>>,
    readback_outputs: [UnsafeCell<*mut std::ffi::c_void>; 2],
    readbacks: [OnceCell<ComOriginal<IShellItem>>; 2], comparisons: [UnsafeCell<i32>; 2],
}
#[cfg(feature = "windows-installed-observation")]
impl FolderAction {
    fn new() -> Self { Self { requested: Cell::new(false), ready: Cell::new(false), input: OnceCell::new(),
        item_output: UnsafeCell::new(null_mut()), item: OnceCell::new(),
        readback_outputs: std::array::from_fn(|_| UnsafeCell::new(null_mut())),
        readbacks: std::array::from_fn(|_| OnceCell::new()), comparisons: std::array::from_fn(|_| UnsafeCell::new(i32::MIN)) } }
    fn release(&self) {
        for readback in &self.readbacks { if let Some(original) = readback.get() { original.release(); } }
        if let Some(original) = self.item.get() { original.release(); }
    }
}
#[derive(Default)]
struct Route { window: usize, bound: bool, retired: bool, posted: bool, unknown: bool }
/// This is DATA/message routing, not an HWND/COM capability for arbitrary calls.
pub struct DialogControl { stopped: AtomicBool, route: Mutex<Route> }
impl Default for DialogControl { fn default() -> Self { Self::new() } }
impl DialogControl {
    pub fn new() -> Self { Self { stopped: AtomicBool::new(false), route: Mutex::new(Route::default()) } }
    pub fn request_stop(&self) -> UiResult<()> {
        self.stopped.store(true, Ordering::SeqCst);
        let mut route = self.route.lock().map_err(|_| UiError::CleanupUnknown)?;
        if route.unknown { return Err(UiError::CleanupUnknown); }
        if route.retired || !route.bound || route.posted { return Ok(()); }
        // Serialized with retiring/destroying THIS original window. At most one
        // queued message exists; no stale post can target a reused HWND later.
        route.posted = true;
        if unsafe { W::PostMessageW(route.window as F::HWND, CLOSE_MESSAGE, 0, 0) } == 0 {
            route.unknown = true; return Err(UiError::CleanupUnknown);
        }
        Ok(())
    }
}

pub struct Dialog {
    kind: DialogKind, control: Arc<DialogControl>, on_event: Box<dyn Fn(DialogEvent)>,
    thread: Cell<u32>, begun: Cell<bool>, created: Cell<bool>, presented: Cell<bool>,
    depth: Cell<usize>, showing: Cell<bool>, show_returned: Cell<bool>, response: Cell<Option<DialogResponse>>,
    task_destroyed: Cell<bool>, settled: Cell<bool>, unknown: Cell<bool>, close_entered: Cell<bool>,
    window: Cell<F::HWND>, task: Cell<F::HWND>, timer: Cell<bool>,
    file: OnceCell<ComOriginal<IFileOpenDialog>>, ole: OnceCell<ComOriginal<IOleWindow>>,
    file_output: ComOutput, ole_output: ComOutput, item_output: ComOutput,
    window_output: UnsafeCell<HWND>, window_query_entered: Cell<bool>, project_window: Cell<F::HWND>,
    events: OnceCell<ComOriginal<IFileDialogEvents>>, cookie: Cell<Option<u32>>, cookie_output: UnsafeCell<u32>, unadvise_entered: Cell<bool>,
    item: OnceCell<ComOriginal<IShellItem>>, path_text: RefCell<NativeText>,
    task_config: UnsafeCell<C::TASKDIALOGCONFIG>, task_button: UnsafeCell<i32>,
    title: Vec<u16>, instruction: Vec<u16>, content: Vec<u16>,
    #[cfg(feature = "windows-installed-observation")]
    folder: FolderAction,
    #[cfg(feature = "windows-installed-observation")]
    quit_action: QuitAction,
    #[cfg(feature = "windows-installed-observation")]
    observation_entered: Cell<bool>,
}
impl Dialog {
    pub fn new(kind: DialogKind, control: Arc<DialogControl>, on_event: Box<dyn Fn(DialogEvent)>) -> Self {
        Self { kind, control, on_event, thread: Cell::new(0), begun: Cell::new(false), created: Cell::new(false),
            presented: Cell::new(false), depth: Cell::new(0), showing: Cell::new(false), show_returned: Cell::new(false),
            response: Cell::new(None), task_destroyed: Cell::new(false), settled: Cell::new(false), unknown: Cell::new(false), close_entered: Cell::new(false),
            window: Cell::new(null_mut()), task: Cell::new(null_mut()), timer: Cell::new(false),
            file: OnceCell::new(), ole: OnceCell::new(), events: OnceCell::new(), cookie: Cell::new(None), cookie_output: UnsafeCell::new(0), unadvise_entered: Cell::new(false),
            file_output: ComOutput::new(), ole_output: ComOutput::new(), item_output: ComOutput::new(),
            window_output: UnsafeCell::new(HWND::default()), window_query_entered: Cell::new(false), project_window: Cell::new(null_mut()),
            item: OnceCell::new(), path_text: RefCell::new(NativeText::new()),
            task_config: UnsafeCell::new(C::TASKDIALOGCONFIG::default()), task_button: UnsafeCell::new(0),
            title: wide(if kind == DialogKind::Project { "Choose a mobile project folder" } else { "Quit Mobile Release Kit?" }),
            instruction: wide("Quit and discard unsaved drafts?"),
            content: wide("Unsaved in-memory changes will be lost. Choose Cancel to keep working, or OK to stop this application's operations and wait for cleanup before quitting. Quitting does not undo completed file changes."),
            #[cfg(feature = "windows-installed-observation")]
            folder: FolderAction::new(),
            #[cfg(feature = "windows-installed-observation")]
            quit_action: QuitAction::new(),
            #[cfg(feature = "windows-installed-observation")]
            observation_entered: Cell::new(false),
        }
    }
    fn event(&self, event: DialogEvent) {
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (self.on_event)(event))).is_err() { self.unknown.set(true); }
    }
    fn uncertain<T>(&self) -> UiResult<T> { self.unknown.set(true); self.event(DialogEvent::Unknown); Err(UiError::CleanupUnknown) }
    fn check(&self) -> UiResult<()> {
        if self.unknown.get() || self.thread.get() != unsafe { T::GetCurrentThreadId() }
            || self.control.route.lock().map_or(true, |route| route.unknown) { Err(UiError::CleanupUnknown) } else { Ok(()) }
    }
    fn enter(&self) -> DialogReturn<'_> {
        if self.thread.get() != unsafe { T::GetCurrentThreadId() } { self.unknown.set(true); }
        self.depth.set(self.depth.get().saturating_add(1)); DialogReturn(self)
    }
    fn responded(&self, response: DialogResponse) {
        if self.response.replace(Some(response)).is_some() { self.unknown.set(true); self.event(DialogEvent::Unknown); }
        else { self.event(DialogEvent::Response(response)); }
    }
    fn native_window(&self) -> UiResult<Option<F::HWND>> {
        self.check()?;
        if !self.showing.get() || self.show_returned.get() { return Ok(None); }
        let window = match self.kind {
            DialogKind::Project => {
                let Some(ole) = self.ole.get() else { return Ok(None); };
                let ole = ole.get()?;
                if self.window_query_entered.replace(true) { return self.uncertain(); }
                unsafe { *self.window_output.get() = HWND::default(); }
                let result = unsafe { (ole.vtable().GetWindow)(ole.as_raw(), self.window_output.get()) };
                if result.0 == HRESULT_PENDING { return self.uncertain(); }
                self.window_query_entered.set(false);
                let window = unsafe { (*self.window_output.get()).0 };
                // IOleWindow documents E_FAIL when the object has no window.
                // Before first native presentation that is ordinary not-ready,
                // never an observer-created response or a retry of an action.
                if result.0 == 0x80004005u32 as i32 && window.is_null()
                    && self.project_window.get().is_null() && !self.presented.get() { return Ok(None); }
                if result.0 != 0 || window.is_null() { return self.uncertain(); }
                if !self.project_window.get().is_null() && self.project_window.get() != window { return self.uncertain(); }
                self.project_window.set(window); window
            },
            DialogKind::Quit => self.task.get(),
        };
        if window.is_null() { return Ok(None); }
        let mut process = 0;
        if unsafe { W::GetWindowThreadProcessId(window, &mut process) } != self.thread.get()
            || process != unsafe { T::GetCurrentProcessId() } { return self.uncertain(); }
        Ok(Some(window))
    }
    fn visible(&self) {
        if self.presented.get() || !self.showing.get() || self.unknown.get() { return; }
        match self.native_window() {
            Ok(Some(window)) if unsafe { W::IsWindowVisible(window) } != 0 => {
                if !self.presented.replace(true) { self.event(DialogEvent::Presented); }
            },
            Ok(_) => {},
            Err(_) => { let _ = self.uncertain::<()>(); },
        }
    }
    fn close_on_sta(&self) {
        if self.check().is_err() || !self.showing.get() { return; }
        match self.kind {
            DialogKind::Project => {
                if self.close_entered.replace(true) { return; }
                let result = self.file.get().and_then(|file| file.get().ok()).map(|file| unsafe { file.Close(CANCEL) });
                if result.is_none_or(|result| result.is_err()) { self.unknown.set(true); self.event(DialogEvent::Unknown); }
            }
            DialogKind::Quit => {
                let window = self.task.get();
                if window.is_null() { return; } // TDN_CREATED will observe the already-latched STOP.
                if self.close_entered.replace(true) { return; }
                // Same STA, actual TaskDialog HWND. Its real button callback and
                // Show return remain authoritative; this is not a synthetic reply.
                unsafe { W::SendMessageW(window, C::TDM_CLICK_BUTTON as u32, W::IDCANCEL as usize, 0); }
            }
        }
    }
    fn setup_route(self: &Rc<Self>) -> UiResult<()> {
        let class = register_class()?;
        let module = unsafe { L::GetModuleHandleW(null()) };
        if module.is_null() { return Err(UiError::NativeFailure); }
        let window = unsafe { W::CreateWindowExW(0, class as usize as *const u16, null(), 0,
            0, 0, 0, 0, W::HWND_MESSAGE, null_mut(), module, Rc::as_ptr(self).cast()) };
        // WM_NCCREATE registers its original before a later construction result.
        if window.is_null() && self.window.get().is_null() && self.depth.get() == 0 { return Err(UiError::NativeFailure); }
        if window.is_null() || self.window.get() != window { return self.uncertain(); }
        {
            let mut route = self.control.route.lock().map_err(|_| UiError::CleanupUnknown)?;
            if route.bound || route.retired || route.unknown { return self.uncertain(); }
            route.window = window as usize; route.bound = true;
        }
        if unsafe { W::SetTimer(window, TIMER, 25, None) } != TIMER { return self.uncertain(); }
        self.timer.set(true); Ok(())
    }
    pub fn run(self: &Rc<Self>, parent: DialogParent) -> UiResult<DialogResult> {
        if self.begun.replace(true) { return self.uncertain(); }
        self.thread.set(unsafe { T::GetCurrentThreadId() });
        if let Err(error) = sta() { return self.no_native_object(error); }
        if parent.thread != self.thread.get() { return self.no_native_object(UiError::OrdinaryContext); }
        let parent = parent.window;
        let mut process = 0;
        if parent.0.is_null() || unsafe { W::GetWindowThreadProcessId(parent.0, &mut process) } != self.thread.get()
            || process != unsafe { T::GetCurrentProcessId() } { return self.no_native_object(UiError::OrdinaryContext); }
        if let Err(error) = self.setup_route() {
            if self.window.get().is_null() && !self.timer.get() && !self.unknown.get() { return self.no_native_object(error); }
            return self.uncertain();
        }
        let result = match self.kind { DialogKind::Project => self.project(parent), DialogKind::Quit => self.quit(parent) };
        if self.unknown.get() || result == Err(UiError::CleanupUnknown) { return self.uncertain(); }
        self.release_once()?;
        result.map(|selected| DialogResult { created: self.created.get(), response: self.response.get(), selected })
    }
    fn no_native_object<T>(&self, error: UiError) -> UiResult<T> {
        let mut route = self.control.route.lock().map_err(|_| UiError::CleanupUnknown)?;
        if route.bound || route.unknown || !self.window.get().is_null() || self.created.get() { return self.uncertain(); }
        route.retired = true; drop(route);
        self.path_text.try_borrow_mut().map_err(|_| UiError::CleanupUnknown)?.release()?;
        self.settled.set(true); self.event(DialogEvent::Settled); Err(error)
    }
    fn project(self: &Rc<Self>, parent: HWND) -> UiResult<Option<PathBuf>> {
        let file_output = self.file_output.begin()?;
        let created = unsafe { windows_sys::Win32::System::Com::CoCreateInstance(
            (&FileOpenDialog as *const windows::core::GUID).cast(), null_mut(),
            windows_sys::Win32::System::Com::CLSCTX_INPROC_SERVER,
            (&IFileOpenDialog::IID as *const windows::core::GUID).cast(), file_output) };
        let file = self.file_output.complete(HRESULT(created))?;
        self.file.set(ComOriginal::new(file)).map_err(|_| UiError::State)?;
        self.created.set(true); self.event(DialogEvent::Created);
        let file = self.file.get().ok_or(UiError::State)?.get()?;
        let ole_output = self.ole_output.begin()?;
        let queried = unsafe { (file.vtable().base__.base__.base__.QueryInterface)(file.as_raw(), &IOleWindow::IID, ole_output) };
        self.ole.set(ComOriginal::new(self.ole_output.complete(queried)?)).map_err(|_| UiError::State)?;
        hresult(unsafe { file.SetOptions(FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM | FOS_PATHMUSTEXIST
            | FOS_DONTADDTORECENT | FOS_NODEREFERENCELINKS) })?;
        hresult(unsafe { file.SetTitle(PCWSTR(self.title.as_ptr())) })?;
        let events: IFileDialogEvents = FileEvents { dialog: self.clone() }.into();
        self.events.set(ComOriginal::new(events)).map_err(|_| UiError::State)?;
        // Raw SDK out-parameter form retains the cookie destination in this
        // already registered Rc original, including an unexpected pending return.
        let events = self.events.get().ok_or(UiError::State)?.get()?;
        let advised = unsafe { (file.vtable().base__.Advise)(file.as_raw(), events.as_raw(), self.cookie_output.get()) };
        if advised.0 == HRESULT_PENDING { return self.uncertain(); }
        if advised.is_err() && unsafe { *self.cookie_output.get() } != 0 { return self.uncertain(); }
        hresult(advised.ok())?;
        self.cookie.set(Some(unsafe { *self.cookie_output.get() }));
        if self.control.stopped.load(Ordering::SeqCst) { return Ok(None); }
        self.showing.set(true); self.event(DialogEvent::ShowEntered);
        let returned = unsafe { file.Show(Some(parent)) };
        if returned.as_ref().is_err_and(|error| error.code().0 == HRESULT_PENDING) { return self.uncertain(); }
        self.showing.set(false); self.show_returned.set(true); self.event(DialogEvent::ShowReturned);
        match returned {
            Ok(()) => {
                if self.response.get() != Some(DialogResponse::Accept) { return self.uncertain(); }
                let item_output = self.item_output.begin()?;
                let selected = unsafe { (file.vtable().base__.GetResult)(file.as_raw(), item_output) };
                self.item.set(ComOriginal::new(self.item_output.complete(selected)?)).map_err(|_| UiError::State)?;
                let mut text = self.path_text.try_borrow_mut().map_err(|_| UiError::CleanupUnknown)?;
                text.entered = true;
                let item = self.item.get().ok_or(UiError::State)?.get()?;
                let path = unsafe { (item.vtable().GetDisplayName)(item.as_raw(), SIGDN_FILESYSPATH, &mut text.value) };
                text.complete(path.ok())?;
                let path = text.read(NAME_UNITS)?;
                // Native-selected data only. The shared project SourceBook still
                // independently probes/registers full identity before publication.
                mapped(project_path_hint(&path), UiError::NativeFailure)?;
                Ok(Some(PathBuf::from(path)))
            }
            Err(error) if error.code() == CANCEL => {
                if self.response.get().is_none() { self.responded(DialogResponse::Decline); }
                else if !self.control.stopped.load(Ordering::SeqCst) { return self.uncertain(); }
                Ok(None)
            }
            Err(_) => Err(UiError::NativeFailure),
        }
    }
    fn quit(self: &Rc<Self>, parent: HWND) -> UiResult<Option<PathBuf>> {
        if self.control.stopped.load(Ordering::SeqCst) { return Ok(None); }
        let config = self.task_config.get();
        // Original storage precedes entry; the callback never borrows a mutable
        // Rust reference held across TaskDialogIndirect's reentrant modal loop.
        unsafe { *config = C::TASKDIALOGCONFIG {
            cbSize: size_of::<C::TASKDIALOGCONFIG>() as u32, hwndParent: parent.0,
            dwFlags: C::TDF_ALLOW_DIALOG_CANCELLATION | C::TDF_POSITION_RELATIVE_TO_WINDOW | C::TDF_SIZE_TO_CONTENT,
            dwCommonButtons: C::TDCBF_OK_BUTTON | C::TDCBF_CANCEL_BUTTON,
            pszWindowTitle: self.title.as_ptr(), pszMainInstruction: self.instruction.as_ptr(), pszContent: self.content.as_ptr(),
            Anonymous1: C::TASKDIALOGCONFIG_0 { pszMainIcon: C::TD_WARNING_ICON }, nDefaultButton: W::IDCANCEL,
            pfCallback: Some(task_callback), lpCallbackData: Rc::as_ptr(self) as isize,
            ..C::TASKDIALOGCONFIG::default()
        }; }
        self.showing.set(true); self.event(DialogEvent::ShowEntered);
        let returned = unsafe { C::TaskDialogIndirect(config, self.task_button.get(), null_mut(), null_mut()) };
        if returned == HRESULT_PENDING { return self.uncertain(); }
        self.showing.set(false); self.show_returned.set(true); self.event(DialogEvent::ShowReturned);
        if returned != 0 { return Err(UiError::NativeFailure); }
        if !self.created.get() || !self.task_destroyed.get() { return self.uncertain(); }
        let expected = match unsafe { *self.task_button.get() } { W::IDOK => DialogResponse::Accept, W::IDCANCEL => DialogResponse::Decline,
            _ => return self.uncertain() };
        if self.response.get() != Some(expected) { return self.uncertain(); }
        Ok(None)
    }
    fn release_once(&self) -> UiResult<()> {
        self.check()?;
        if self.depth.get() != 0 || self.showing.get() || self.settled.get() || self.window_query_entered.get()
            || !self.file_output.settled() || !self.ole_output.settled() || !self.item_output.settled() { return self.uncertain(); }
        if self.kind == DialogKind::Quit && self.created.get() && !self.task_destroyed.get() { return self.uncertain(); }
        self.event(DialogEvent::Releasing);
        if self.unknown.get() { return self.uncertain(); }
        if let Some(cookie) = self.cookie.get() {
            if self.unadvise_entered.replace(true) { return self.uncertain(); }
            if unsafe { self.file.get().ok_or(UiError::State)?.get()?.Unadvise(cookie) }.is_err() { return self.uncertain(); }
            self.cookie.set(None);
        }
        if self.depth.get() != 0 { return self.uncertain(); }
        self.path_text.try_borrow_mut().map_err(|_| UiError::CleanupUnknown)?.release()?;
        if let Some(original) = self.item.get() { original.release(); }
        if let Some(original) = self.ole.get() { original.release(); }
        if let Some(original) = self.file.get() { original.release(); }
        if let Some(original) = self.events.get() { original.release(); }
        #[cfg(feature = "windows-installed-observation")]
        self.folder.release();
        let window = self.window.get();
        let mut route = self.control.route.lock().map_err(|_| UiError::CleanupUnknown)?;
        if route.unknown || !route.bound || route.retired || route.window != window as usize { return self.uncertain(); }
        route.retired = true; route.window = 0; // Lock remains held through original DestroyWindow.
        if self.timer.replace(false) && unsafe { W::KillTimer(window, TIMER) } == 0 { return self.uncertain(); }
        let mut message = W::MSG::default();
        // One fixed posted close and one coalesced timer; remove them before HWND
        // destruction so neither can outlive/rebind to another native object.
        unsafe { W::PeekMessageW(&mut message, window, CLOSE_MESSAGE, CLOSE_MESSAGE, W::PM_REMOVE); }
        unsafe { W::PeekMessageW(&mut message, window, W::WM_TIMER, W::WM_TIMER, W::PM_REMOVE); }
        if unsafe { W::DestroyWindow(window) } == 0 || !self.window.get().is_null() || self.depth.get() != 0 { return self.uncertain(); }
        drop(route); self.settled.set(true); self.event(DialogEvent::Settled); Ok(())
    }
    pub fn settled(&self) -> bool { self.settled.get() && !self.unknown.get() }
    pub fn created(&self) -> bool { self.created.get() }

    #[cfg(feature = "windows-installed-observation")]
    fn observation_turn_ready(&self) -> bool {
        self.depth.get() == 1 && self.created.get() && self.presented.get() && self.showing.get()
            && !self.show_returned.get() && self.response.get().is_none() && !self.control.stopped.load(Ordering::SeqCst)
            && !self.close_entered.get() && !self.settled.get() && !self.unknown.get()
    }
    #[cfg(feature = "windows-installed-observation")]
    fn enter_observation_turn(&self) -> Option<ObservationTurnReturn<'_>> {
        if !self.observation_turn_ready() || self.observation_entered.replace(true) { return None; }
        Some(ObservationTurnReturn(self))
    }
    #[cfg(feature = "windows-installed-observation")]
    fn observation_turn_active(&self) -> bool { self.observation_entered.get() && self.observation_turn_ready() }

    #[cfg(feature = "windows-installed-observation")]
    pub fn installed_observation(&self) -> UiResult<DialogObservation> {
        self.check()?;
        let visible = if self.showing.get() {
            self.native_window()?.is_some_and(|window| unsafe { W::IsWindowVisible(window) } != 0)
        } else { false };
        Ok(DialogObservation { kind: self.kind, created: self.created.get(), showing: self.showing.get(), visible,
            presented: self.presented.get(), response: self.response.get(), show_returned: self.show_returned.get(),
            callbacks_active: self.depth.get() != 0, observation_turn: self.observation_turn_active(),
            stopped: self.control.stopped.load(Ordering::SeqCst),
            close_entered: self.close_entered.get(), settled: self.settled(), folder_ready: self.folder.ready.get() })
    }
    #[cfg(feature = "windows-installed-observation")]
    fn folder_readback(&self, index: usize) -> UiResult<()> {
        let file = self.file.get().ok_or(UiError::State)?.get()?;
        let original = self.folder.item.get().ok_or(UiError::State)?.get()?;
        let slot = self.folder.readbacks.get(index).filter(|slot| slot.get().is_none()).ok_or(UiError::State)?;
        let returned = unsafe { (file.vtable().base__.GetFolder)(file.as_raw(), self.folder.readback_outputs[index].get()) };
        if returned.0 == HRESULT_PENDING { return self.uncertain(); }
        if returned.is_err() && unsafe { !(*self.folder.readback_outputs[index].get()).is_null() } { return self.uncertain(); }
        hresult(returned.ok())?;
        let pointer = unsafe { *self.folder.readback_outputs[index].get() };
        if pointer.is_null() { return self.uncertain(); }
        slot.set(ComOriginal::new(unsafe { IShellItem::from_raw(pointer) })).map_err(|_| UiError::State)?;
        let current = slot.get().ok_or(UiError::State)?.get()?;
        let compared = unsafe { (current.vtable().Compare)(current.as_raw(), original.as_raw(),
            SICHINT_CANONICAL.0 as u32, self.folder.comparisons[index].get()) };
        if compared.0 == HRESULT_PENDING { return self.uncertain(); }
        hresult(compared.ok())?;
        if unsafe { *self.folder.comparisons[index].get() } != 0 { return Err(UiError::State); }
        self.folder.ready.set(true); Ok(())
    }
    #[cfg(feature = "windows-installed-observation")]
    pub fn installed_action(&self, action: DialogAction<'_>) -> UiResult<bool> {
        self.check()?;
        if !self.observation_turn_active() { return Err(UiError::State); }
        if self.kind == DialogKind::Quit { self.quit_action.check()?; }
        if !self.created.get() || !self.showing.get() || self.show_returned.get() || self.response.get().is_some()
            || self.control.stopped.load(Ordering::SeqCst) || self.close_entered.get() || self.settled.get() {
            return Err(UiError::State);
        }
        let Some(window) = self.native_window()? else { return Ok(false); };
        if unsafe { W::IsWindowVisible(window) } == 0 { return Ok(false); }
        if let DialogAction::ChooseFolder(path) = action {
            if self.kind != DialogKind::Project || self.folder.requested.replace(true) { return Err(UiError::State); }
            let path = path.to_str().filter(|value| value.encode_utf16().count() < NAME_UNITS).ok_or(UiError::State)?;
            mapped(project_path_hint(path), UiError::State)?;
            self.folder.input.set(wide(path)).map_err(|_| UiError::State)?;
            let input = self.folder.input.get().ok_or(UiError::State)?;
            let returned = unsafe { SH::SHCreateItemFromParsingName(input.as_ptr(), null_mut(),
                (&IShellItem::IID as *const windows::core::GUID).cast(), self.folder.item_output.get()) };
            if returned == HRESULT_PENDING { return self.uncertain(); }
            if returned < 0 && unsafe { !(*self.folder.item_output.get()).is_null() } { return self.uncertain(); }
            hresult(HRESULT(returned).ok())?;
            let pointer = unsafe { *self.folder.item_output.get() };
            if pointer.is_null() { return self.uncertain(); }
            self.folder.item.set(ComOriginal::new(unsafe { IShellItem::from_raw(pointer) })).map_err(|_| UiError::State)?;
            let item = self.folder.item.get().ok_or(UiError::State)?.get()?;
            if !self.observation_turn_active() { return Err(UiError::State); }
            let returned = unsafe { self.file.get().ok_or(UiError::State)?.get()?.SetFolder(item) };
            if returned.as_ref().is_err_and(|error| error.code().0 == HRESULT_PENDING) { return self.uncertain(); }
            hresult(returned)?;
            // After an effectful SetFolder there is no false/not-ready/retry.
            // Read back the actual current folder before any Accept is allowed.
            self.folder_readback(0)?; return Ok(true);
        }
        let accept = matches!(action, DialogAction::Accept);
        if self.kind == DialogKind::Quit {
            // TDN_CREATED's original TaskDialog owns logical common-button
            // IDs. This path never guesses its private native child layout.
            self.check()?;
            if self.native_window()? != Some(window) || self.task.get() != window
                || unsafe { W::IsWindowVisible(window) } == 0 { return Err(UiError::State); }
            self.check()?;
            if !self.created.get() || self.task_destroyed.get() || !self.showing.get() || self.show_returned.get()
                || self.response.get().is_some() || self.control.stopped.load(Ordering::SeqCst)
                || self.close_entered.get() || self.settled.get() { return Err(UiError::State); }
            if !self.observation_turn_active() { return Err(UiError::State); }
            return self.quit_action.request(|| {
                // Entry consumes the one-shot latch before any reentrant call.
                // The send result is not a response, Show-return or finality fact.
                unsafe { W::SendMessageW(window, C::TDM_CLICK_BUTTON as u32,
                    if accept { W::IDOK as usize } else { W::IDCANCEL as usize }, 0); }
                self.check()
            });
        }
        if accept && self.kind == DialogKind::Project { self.folder_readback(1)?; }
        let button = unsafe { W::GetDlgItem(window, if accept { W::IDOK } else { W::IDCANCEL }) };
        let mut process = 0;
        if button.is_null() || unsafe { W::IsChild(window, button) } == 0
            || unsafe { W::GetWindowThreadProcessId(button, &mut process) } != self.thread.get()
            || process != unsafe { T::GetCurrentProcessId() }
            || unsafe { W::IsWindowVisible(button) } == 0
            || unsafe { windows_sys::Win32::UI::Input::KeyboardAndMouse::IsWindowEnabled(button) } == 0 {
            return Err(UiError::State);
        }
        // The actual native button owns the response. No GuiFacts/result setter
        // or arbitrary HWND/message/PID control is exposed to the observer.
        if !self.observation_turn_active() { return Err(UiError::State); }
        unsafe { W::SendMessageW(button, W::BM_CLICK, 0, 0); }
        self.check()?; Ok(true)
    }
}
struct DialogReturn<'a>(&'a Dialog);
impl Drop for DialogReturn<'_> { fn drop(&mut self) { self.0.depth.set(self.0.depth.get().saturating_sub(1)); } }
#[cfg(feature = "windows-installed-observation")]
struct ObservationTurnReturn<'a>(&'a Dialog);
#[cfg(feature = "windows-installed-observation")]
impl Drop for ObservationTurnReturn<'_> { fn drop(&mut self) { self.0.observation_entered.set(false); } }

fn register_class() -> UiResult<u16> {
    static CLASS_ATOM: OnceLock<UiResult<u16>> = OnceLock::new();
    *CLASS_ATOM.get_or_init(|| {
        let module = unsafe { L::GetModuleHandleW(null()) };
        if module.is_null() { return Err(UiError::NativeFailure); }
        let class = W::WNDCLASSW { lpfnWndProc: Some(control_window), hInstance: module,
            lpszClassName: CLASS.as_ptr(), ..W::WNDCLASSW::default() };
        let atom = unsafe { W::RegisterClassW(&class) };
        // Never adopt another component's identically named class.
        if atom == 0 { Err(UiError::NativeFailure) } else { Ok(atom) }
    })
}
unsafe extern "system" fn control_window(window: F::HWND, message: u32, wparam: usize, lparam: isize) -> isize {
    if message == W::WM_NCCREATE {
        let create = unsafe { &*(lparam as *const W::CREATESTRUCTW) };
        let original = create.lpCreateParams.cast::<Dialog>();
        if original.is_null() { return 0; }
        let pointer = original as isize;
        let original = unsafe { &*original }; let _returned = original.enter();
        // Adopt the actual partial HWND before the registration attempt. A
        // failed/readback-mismatched attempt never becomes "not created".
        original.window.set(window);
        unsafe { F::SetLastError(0); }
        let previous = unsafe { W::SetWindowLongPtrW(window, W::GWLP_USERDATA, pointer) };
        let error = unsafe { F::GetLastError() };
        if previous != 0 || error != 0 || unsafe { W::GetWindowLongPtrW(window, W::GWLP_USERDATA) } != pointer {
            original.unknown.set(true); return 0;
        }
        return 1;
    }
    let original = unsafe { W::GetWindowLongPtrW(window, W::GWLP_USERDATA) } as *const Dialog;
    if !original.is_null() {
        let original = unsafe { &*original }; let _returned = original.enter();
        if message == CLOSE_MESSAGE && wparam == 0 && lparam == 0 {
            if original.control.stopped.load(Ordering::SeqCst) { original.close_on_sta(); } return 0;
        }
        if message == W::WM_TIMER && wparam == TIMER {
            original.visible();
            if original.control.stopped.load(Ordering::SeqCst) { original.close_on_sta(); }
            // The original DialogReturn remains live throughout this event.
            // Nested timers/native callbacks cannot enter a second own turn.
            #[cfg(feature = "windows-installed-observation")]
            if let Some(_turn_returned) = original.enter_observation_turn() {
                original.event(DialogEvent::ObservationTurn);
            }
            return 0;
        }
        if message == W::WM_NCDESTROY {
            unsafe { F::SetLastError(0); }
            let previous = unsafe { W::SetWindowLongPtrW(window, W::GWLP_USERDATA, 0) };
            let error = unsafe { F::GetLastError() };
            if previous != original as *const Dialog as isize || error != 0
                || unsafe { W::GetWindowLongPtrW(window, W::GWLP_USERDATA) } != 0 { original.unknown.set(true); }
            else { original.window.set(null_mut()); }
        }
        return unsafe { W::DefWindowProcW(window, message, wparam, lparam) };
    }
    unsafe { W::DefWindowProcW(window, message, wparam, lparam) }
}
unsafe extern "system" fn task_callback(window: F::HWND, message: u32, wparam: usize, _: isize, context: isize) -> i32 {
    if context == 0 { return 0; }
    let original = unsafe { &*(context as *const Dialog) }; let _returned = original.enter();
    match message as i32 {
        C::TDN_CREATED => {
            if original.created.replace(true) || !original.task.get().is_null() { original.unknown.set(true); return 0; }
            original.task.set(window); original.event(DialogEvent::Created);
            if original.control.stopped.load(Ordering::SeqCst) { original.close_on_sta(); }
        }
        C::TDN_BUTTON_CLICKED => {
            match wparam as i32 { W::IDOK => original.responded(DialogResponse::Accept),
                W::IDCANCEL => original.responded(DialogResponse::Decline), _ => { original.unknown.set(true); } }
        }
        C::TDN_DESTROYED => {
            if original.task.get() != window || original.task_destroyed.replace(true) { original.unknown.set(true); }
            original.task.set(null_mut());
        }
        _ => {},
    }
    0
}

#[implement(IFileDialogEvents)]
struct FileEvents { dialog: Rc<Dialog> }
impl IFileDialogEvents_Impl for FileEvents_Impl {
    fn OnFileOk(&self, _: Ref<'_, IFileDialog>) -> windows::core::Result<()> {
        let _returned = self.dialog.enter(); self.dialog.responded(DialogResponse::Accept); Ok(())
    }
    fn OnFolderChanging(&self, _: Ref<'_, IFileDialog>, _: Ref<'_, IShellItem>) -> windows::core::Result<()> {
        let _returned = self.dialog.enter();
        #[cfg(feature = "windows-installed-observation")]
        self.dialog.folder.ready.set(false);
        Ok(())
    }
    fn OnFolderChange(&self, _: Ref<'_, IFileDialog>) -> windows::core::Result<()> {
        let _returned = self.dialog.enter(); self.dialog.visible(); Ok(())
    }
    fn OnSelectionChange(&self, _: Ref<'_, IFileDialog>) -> windows::core::Result<()> { let _returned = self.dialog.enter(); Ok(()) }
    fn OnShareViolation(&self, _: Ref<'_, IFileDialog>, _: Ref<'_, IShellItem>) -> windows::core::Result<FDE_SHAREVIOLATION_RESPONSE> { let _returned = self.dialog.enter(); Ok(FDESVR_REFUSE) }
    fn OnTypeChange(&self, _: Ref<'_, IFileDialog>) -> windows::core::Result<()> { let _returned = self.dialog.enter(); Ok(()) }
    fn OnOverwrite(&self, _: Ref<'_, IFileDialog>, _: Ref<'_, IShellItem>) -> windows::core::Result<FDE_OVERWRITE_RESPONSE> { let _returned = self.dialog.enter(); Ok(FDEOR_REFUSE) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stop_before_native_construction_is_latched_without_a_foreign_window() -> UiResult<()> {
        let control = DialogControl::new();
        assert!(control.request_stop().is_ok());
        assert!(control.stopped.load(Ordering::SeqCst));
        let route = control.route.lock().map_err(|_| UiError::CleanupUnknown)?;
        assert!(!route.bound); assert!(!route.posted); assert_eq!(route.window, 0);
        #[cfg(feature = "windows-installed-observation")]
        {
            let dialog = Dialog::new(DialogKind::Project, Arc::new(DialogControl::new()), Box::new(|_| {}));
            assert!(dialog.enter_observation_turn().is_none());
            dialog.created.set(true); dialog.presented.set(true); dialog.showing.set(true); dialog.depth.set(1);
            let turn = dialog.enter_observation_turn().ok_or(UiError::State)?;
            assert!(dialog.observation_turn_active()); assert_eq!(dialog.depth.get(), 1);
            assert!(dialog.enter_observation_turn().is_none());
            dialog.depth.set(2);
            assert!(!dialog.observation_turn_active()); assert!(dialog.enter_observation_turn().is_none());
            dialog.depth.set(1); assert!(dialog.observation_turn_active());
            drop(turn); assert!(!dialog.observation_turn_active()); assert_eq!(dialog.depth.get(), 1);
            dialog.control.stopped.store(true, Ordering::SeqCst);
            assert!(dialog.enter_observation_turn().is_none());
        }
        Ok(())
    }
    #[test]
    fn retired_original_cannot_repost_to_a_reused_window() -> UiResult<()> {
        let control = DialogControl::new();
        { let mut route = control.route.lock().map_err(|_| UiError::CleanupUnknown)?; route.bound = true; route.retired = true; }
        assert!(control.request_stop().is_ok()); assert!(!control.route.lock().map_err(|_| UiError::CleanupUnknown)?.posted);
        #[cfg(feature = "windows-installed-observation")]
        {
            let dialog = Dialog::new(DialogKind::Project, Arc::new(DialogControl::new()), Box::new(|_| {}));
            dialog.created.set(true); dialog.presented.set(true); dialog.showing.set(true); dialog.depth.set(1);
            for condition in [&dialog.unknown, &dialog.show_returned, &dialog.settled, &dialog.close_entered] {
                condition.set(true); assert!(dialog.enter_observation_turn().is_none()); condition.set(false);
            }
            dialog.response.set(Some(DialogResponse::Decline)); assert!(dialog.enter_observation_turn().is_none());
            dialog.response.set(None); dialog.showing.set(false); assert!(dialog.enter_observation_turn().is_none());
            dialog.showing.set(true); dialog.depth.set(0); assert!(dialog.enter_observation_turn().is_none());
            dialog.depth.set(1); assert!(dialog.enter_observation_turn().is_some());
            assert!(!dialog.observation_entered.get());
        }
        Ok(())
    }
}
