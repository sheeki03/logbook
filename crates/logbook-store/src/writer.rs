//! Single-writer task + read pool (plan §2).
//!
//! SQLite in WAL mode permits exactly one writer and many concurrent readers.
//! We honour that directly:
//!
//! - **One writer.** A dedicated OS thread owns the single write [`Connection`]
//!   and drains a `std::sync::mpsc` command channel. All mutations are
//!   serialized through it, so there is never write contention and never a
//!   `SQLITE_BUSY` from two writers.
//! - **A read pool.** Reads borrow a connection from a small free-list of
//!   read-only connections (opened lazily up to a cap); WAL lets them run
//!   concurrently with the writer and with each other.
//!
//! Each write command carries a `oneshot`-style reply channel so callers can
//! await durability and surface errors.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use rusqlite::{Connection, OpenFlags};

use logbook_core::Event;

use crate::error::{Result, StoreError};
use crate::schema::{configure_connection, event_to_row, run_migrations};

/// A unit reply channel for a write command.
type Ack = mpsc::Sender<Result<()>>;

/// Commands accepted by the writer thread.
enum WriteCmd {
    /// Insert (or replace on id) a single event.
    Insert(Box<Event>, Ack),
    /// Insert (or replace on id) a batch of events in one transaction.
    InsertBatch(Vec<Event>, Ack),
    /// Run an arbitrary closure against the write connection (for migrations,
    /// inventory upserts, retention, etc.). Boxed so callers can do anything.
    #[allow(clippy::type_complexity)]
    Exec(Box<dyn FnOnce(&mut Connection) -> Result<()> + Send>, Ack),
    /// Flush + shut the writer thread down.
    Shutdown(Ack),
}

/// Handle to the single-writer thread. Cloneable; the thread shuts down when
/// the last handle is dropped (or [`WriterHandle::shutdown`] is called).
#[derive(Clone)]
struct WriterHandle {
    tx: Sender<WriteCmd>,
    join: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl WriterHandle {
    /// Spawn the writer thread against the database at `path`, applying pragmas
    /// and running migrations before accepting commands.
    fn spawn(path: PathBuf) -> Result<Self> {
        let (ready_tx, ready_rx) = mpsc::channel::<Result<()>>();
        let (tx, rx) = mpsc::channel::<WriteCmd>();

        let join = std::thread::Builder::new()
            .name("logbook-store-writer".into())
            .spawn(move || {
                writer_loop(path, rx, ready_tx);
            })
            .map_err(StoreError::Io)?;

        // Wait for the writer to finish setup (open + pragmas + migrations).
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                tx,
                join: Arc::new(Mutex::new(Some(join))),
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(StoreError::WriterGone),
        }
    }

    /// Send a command and block for its acknowledgement.
    fn send_blocking(&self, make: impl FnOnce(Ack) -> WriteCmd) -> Result<()> {
        let (ack_tx, ack_rx) = mpsc::channel();
        self.tx
            .send(make(ack_tx))
            .map_err(|_| StoreError::WriterGone)?;
        ack_rx.recv().map_err(|_| StoreError::WriterGone)?
    }

    /// Signal shutdown and join the thread.
    fn shutdown(&self) -> Result<()> {
        // Best-effort flush signal; ignore if already gone.
        let _ = self.send_blocking(WriteCmd::Shutdown);
        if let Some(handle) = self.join.lock().expect("writer join mutex").take() {
            let _ = handle.join();
        }
        Ok(())
    }
}

/// The writer thread body: open the connection, run migrations, signal ready,
/// then drain commands until shutdown or the channel closes.
fn writer_loop(path: PathBuf, rx: Receiver<WriteCmd>, ready_tx: Sender<Result<()>>) {
    let mut conn = match open_writer(&path) {
        Ok(c) => c,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };
    let _ = ready_tx.send(Ok(()));

    while let Ok(cmd) = rx.recv() {
        match cmd {
            WriteCmd::Insert(event, ack) => {
                let _ = ack.send(insert_one(&conn, &event));
            }
            WriteCmd::InsertBatch(events, ack) => {
                let _ = ack.send(insert_batch(&mut conn, &events));
            }
            WriteCmd::Exec(f, ack) => {
                let _ = ack.send(f(&mut conn));
            }
            WriteCmd::Shutdown(ack) => {
                let _ = ack.send(Ok(()));
                break;
            }
        }
    }
}

/// Open the single write connection (read/write/create) and prepare it.
fn open_writer(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let mut conn = Connection::open(path)?;
    configure_connection(&conn)?;
    run_migrations(&mut conn)?;
    Ok(conn)
}

/// Open a read-only connection. WAL lets these run concurrently with the writer.
fn open_reader(path: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    // Readers must agree on WAL + busy timeout; journal_mode is a no-op on a
    // read-only handle but the busy timeout matters.
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    Ok(conn)
}

const INSERT_SQL: &str = "INSERT OR REPLACE INTO events \
    (id, trace_id, parent_id, timestamp, duration_ms, kind, type, category, \
     operation, name, status, error, session_id, turn, max_sensitivity, body) \
    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)";

fn insert_one(conn: &Connection, event: &Event) -> Result<()> {
    let row = event_to_row(event)?;
    conn.execute(
        INSERT_SQL,
        rusqlite::params![
            row.id,
            row.trace_id,
            row.parent_id,
            row.timestamp,
            row.duration_ms,
            row.kind,
            row.type_,
            row.category,
            row.operation,
            row.name,
            row.status,
            row.error,
            row.session_id,
            row.turn,
            row.max_sensitivity,
            row.body,
        ],
    )?;
    Ok(())
}

fn insert_batch(conn: &mut Connection, events: &[Event]) -> Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare_cached(INSERT_SQL)?;
        for event in events {
            let row = event_to_row(event)?;
            stmt.execute(rusqlite::params![
                row.id,
                row.trace_id,
                row.parent_id,
                row.timestamp,
                row.duration_ms,
                row.kind,
                row.type_,
                row.category,
                row.operation,
                row.name,
                row.status,
                row.error,
                row.session_id,
                row.turn,
                row.max_sensitivity,
                row.body,
            ])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// A simple bounded free-list of read-only connections.
struct ReadPool {
    path: PathBuf,
    idle: Mutex<Vec<Connection>>,
    max_idle: usize,
}

impl ReadPool {
    fn new(path: PathBuf, max_idle: usize) -> Self {
        Self {
            path,
            idle: Mutex::new(Vec::new()),
            max_idle,
        }
    }

    /// Borrow a connection (reusing an idle one if available), run `f`, and
    /// return the connection to the pool.
    fn with<T>(&self, f: impl FnOnce(&Connection) -> Result<T>) -> Result<T> {
        let conn = {
            let mut idle = self.idle.lock().expect("read pool mutex");
            idle.pop()
        };
        let conn = match conn {
            Some(c) => c,
            None => open_reader(&self.path)?,
        };
        let result = f(&conn);
        // Return to pool on success or failure (the connection is still valid
        // for read-only use); drop if the pool is full.
        let mut idle = self.idle.lock().expect("read pool mutex");
        if idle.len() < self.max_idle {
            idle.push(conn);
        }
        result
    }
}

/// Shared inner state behind [`crate::Store`].
pub(crate) struct StoreInner {
    path: PathBuf,
    writer: WriterHandle,
    readers: ReadPool,
}

impl StoreInner {
    pub(crate) fn open(path: PathBuf) -> Result<Self> {
        let writer = WriterHandle::spawn(path.clone())?;
        // In-memory databases can't be reopened by a separate read connection
        // (each `:memory:` open is a distinct db), so the read pool is only
        // meaningful for file-backed stores. We still create it; callers using
        // `:memory:` should read through the writer via `exec`.
        let readers = ReadPool::new(path.clone(), 4);
        Ok(Self {
            path,
            writer,
            readers,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn insert(&self, event: &Event) -> Result<()> {
        let event = event.clone();
        self.writer
            .send_blocking(move |ack| WriteCmd::Insert(Box::new(event), ack))
    }

    pub(crate) fn insert_batch(&self, events: Vec<Event>) -> Result<()> {
        self.writer
            .send_blocking(move |ack| WriteCmd::InsertBatch(events, ack))
    }

    pub(crate) fn exec<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut Connection) -> Result<()> + Send + 'static,
    {
        self.writer
            .send_blocking(move |ack| WriteCmd::Exec(Box::new(f), ack))
    }

    /// Run a read closure against a read-pool connection.
    ///
    /// For `:memory:` stores the read pool can't be used (each `:memory:` open
    /// is a distinct database), so the closure is routed through the single
    /// writer connection instead. That is why this requires `Send + 'static`:
    /// the in-memory path hands the closure to the writer thread and the value
    /// back through a typed channel, avoiding any shared-mutex shim.
    pub(crate) fn read<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        if self.is_memory() {
            // Route through the writer connection. The closure carries its own
            // typed reply channel so the value travels back directly.
            let (tx, rx) = mpsc::channel::<Result<T>>();
            self.exec(move |conn| {
                let _ = tx.send(f(conn));
                Ok(())
            })?;
            // `exec` blocks until the writer has run (and dropped) the closure,
            // so exactly one message is queued by the time we receive here.
            rx.recv().map_err(|_| StoreError::WriterGone)?
        } else {
            self.readers.with(f)
        }
    }

    pub(crate) fn shutdown(&self) -> Result<()> {
        self.writer.shutdown()
    }

    /// Whether this store is backed by an in-memory database (read pool can't be
    /// shared across connections for `:memory:`).
    fn is_memory(&self) -> bool {
        let p = self.path.to_string_lossy();
        p == ":memory:" || p.is_empty() || p.contains("mode=memory")
    }
}
