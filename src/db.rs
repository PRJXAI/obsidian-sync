use crate::{
    Error, Result,
    storage::{BlockingPool, private_root},
};
use fs2::FileExt;
use rusqlite::Connection;
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

#[derive(Clone)]
pub struct Database {
    path: Arc<PathBuf>,
    pool: BlockingPool,
    // Keep both directory and lock alive across all task/worker clones.
    _lock: Arc<File>,
    _directory: Arc<File>,
    connections: Arc<std::sync::Mutex<Vec<Connection>>>,
}
impl Database {
    pub async fn open(directory: &Path, pool: BlockingPool) -> Result<Self> {
        let path = directory.to_owned();
        let (root, lock, file) = pool
            .run(move || {
                let root = private_root(&path)?;
                let lock = File::from(rustix::fs::openat(
                    &root,
                    "writer.lock",
                    rustix::fs::OFlags::RDWR
                        | rustix::fs::OFlags::CREATE
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::from_bits_truncate(0o600),
                )?);
                lock.try_lock_exclusive().map_err(|_| Error::WriterActive)?;
                root.sync_all()?;
                let file = path.join("state.sqlite3");
                for name in ["state.sqlite3", "state.sqlite3-wal", "state.sqlite3-shm"] {
                    if let Ok(meta) = std::fs::symlink_metadata(path.join(name))
                        && (!meta.is_file() || meta.file_type().is_symlink())
                    {
                        return Err(Error::Invalid);
                    }
                }
                Ok((root, lock, file))
            })
            .await?;
        let db = Self {
            path: Arc::new(file),
            pool,
            _lock: Arc::new(lock),
            _directory: Arc::new(root),
            connections: Arc::new(std::sync::Mutex::new(Vec::new())),
        };
        db.run(|connection| {
            let version: i64 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
            if ![0, 1, 2, 3].contains(&version) {
                return Err(Error::Invalid);
            }
            connection.pragma_update(None, "journal_mode", "WAL")?;
            let mut schema=SCHEMA.to_owned();
            if version==2 {
                let mut columns=connection.prepare("PRAGMA table_info(couch_databases)")?;
                let names=columns.query_map([],|r|r.get::<_,String>(1))?.collect::<std::result::Result<Vec<_>,_>>()?;
                if !names.iter().any(|name|name=="active") {
                    schema=schema.replace("PRAGMA user_version=3;", "ALTER TABLE couch_databases ADD COLUMN active INTEGER NOT NULL DEFAULT 1; PRAGMA user_version=3;");
                }
            }
            connection.execute_batch(&schema)?;
            connection.execute(
                "INSERT OR IGNORE INTO server_meta(key,value) VALUES('instance',?1)",
                [uuid::Uuid::new_v4().to_string()],
            )?;
            // Only after acquiring the process-lifetime writer lock: old processes are dead.
            connection.execute(
                "UPDATE jobs SET state='queued', owner=NULL WHERE state='running'",
                [],
            )?;
            Ok(())
        })
        .await?;
        let root = db._directory.clone();
        db.pool
            .run(move || {
                root.sync_all()?;
                Ok(())
            })
            .await?;
        Ok(db)
    }
    pub async fn run<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let path = self.path.clone();
        let guard = self._lock.clone();
        let directory = self._directory.clone();
        let connections = self.connections.clone();
        self.pool
            .run(move || {
                // Canceled async callers cannot release the writer lock before this task finishes.
                let (_guard, _directory) = (guard, directory);
                let cached = connections.lock().map_err(|_| Error::Backend)?.pop();
                let mut conn = match cached {
                    Some(conn) => conn,
                    None => {
                        let conn = Connection::open(&*path)?;
                        conn.busy_timeout(Duration::from_secs(5))?;
                        conn.pragma_update(None, "foreign_keys", "ON")?;
                        conn.pragma_update(None, "synchronous", "FULL")?;
                        conn
                    }
                };
                let result = f(&mut conn);
                connections.lock().map_err(|_| Error::Backend)?.push(conn);
                result
            })
            .await
    }
    pub async fn checkpoint(&self) -> Result<()> {
        self.run(|c| {
            c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
            Ok(())
        })
        .await
    }
    /// Online SQLite backup via VACUUM INTO. Target must not exist; CLI-only, trusted path.
    pub async fn backup(&self, target: PathBuf) -> Result<()> {
        self.run(move |c| {
            if !target.is_absolute() {
                return Err(Error::Invalid);
            }
            c.execute("VACUUM INTO ?1", [target.to_str().ok_or(Error::Invalid)?])?;
            File::open(&target)?.sync_all()?;
            File::open(target.parent().ok_or(Error::Invalid)?)?.sync_all()?;
            Ok(())
        })
        .await
    }
}
const SCHEMA: &str = "
BEGIN IMMEDIATE;
CREATE TABLE IF NOT EXISTS principals(id TEXT PRIMARY KEY, digest BLOB UNIQUE NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS vaults(id TEXT PRIMARY KEY, quota INTEGER NOT NULL CHECK(quota>0), allocated INTEGER NOT NULL DEFAULT 0, revision INTEGER NOT NULL DEFAULT 0, last_claim INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS grants(principal TEXT NOT NULL REFERENCES principals(id), vault TEXT NOT NULL REFERENCES vaults(id), writable INTEGER NOT NULL, PRIMARY KEY(principal,vault));
CREATE TABLE IF NOT EXISTS blobs(vault TEXT NOT NULL REFERENCES vaults(id), id TEXT NOT NULL, size INTEGER NOT NULL CHECK(size>=0), digest BLOB NOT NULL, ready INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(vault,id));
CREATE TABLE IF NOT EXISTS heads(vault TEXT NOT NULL REFERENCES vaults(id), path TEXT NOT NULL, revision INTEGER NOT NULL, blob TEXT, PRIMARY KEY(vault,path), FOREIGN KEY(vault,blob) REFERENCES blobs(vault,id));
CREATE TABLE IF NOT EXISTS changes(vault TEXT NOT NULL REFERENCES vaults(id), revision INTEGER NOT NULL, path TEXT NOT NULL, blob TEXT, PRIMARY KEY(vault,revision), FOREIGN KEY(vault,blob) REFERENCES blobs(vault,id));
CREATE TABLE IF NOT EXISTS replays(principal TEXT NOT NULL REFERENCES principals(id), vault TEXT NOT NULL REFERENCES vaults(id), operation TEXT NOT NULL, key TEXT NOT NULL, hash BLOB NOT NULL, result TEXT NOT NULL, PRIMARY KEY(principal,vault,operation,key));
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, vault TEXT NOT NULL REFERENCES vaults(id), state TEXT NOT NULL CHECK(state IN ('queued','running','done','failed')), owner TEXT, attempts INTEGER NOT NULL DEFAULT 0, available INTEGER NOT NULL DEFAULT 0, claimed INTEGER NOT NULL DEFAULT 0);
CREATE INDEX IF NOT EXISTS jobs_due ON jobs(state,available,vault);
CREATE TABLE IF NOT EXISTS server_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS couch_databases(name TEXT PRIMARY KEY, vault TEXT UNIQUE NOT NULL REFERENCES vaults(id), seq INTEGER NOT NULL DEFAULT 0 CHECK(seq>=0), active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS couch_revisions(vault TEXT NOT NULL REFERENCES vaults(id), id TEXT NOT NULL, rev TEXT NOT NULL, generation INTEGER NOT NULL, parent TEXT, blob TEXT, digest BLOB, deleted INTEGER NOT NULL DEFAULT 0, kind TEXT, PRIMARY KEY(vault,id,rev), FOREIGN KEY(vault,id,parent) REFERENCES couch_revisions(vault,id,rev), FOREIGN KEY(vault,blob) REFERENCES blobs(vault,id));
CREATE INDEX IF NOT EXISTS couch_children ON couch_revisions(vault,id,parent);
CREATE TABLE IF NOT EXISTS couch_heads(vault TEXT NOT NULL REFERENCES vaults(id), id TEXT NOT NULL, seq INTEGER NOT NULL, winner TEXT NOT NULL, PRIMARY KEY(vault,id), UNIQUE(vault,seq), FOREIGN KEY(vault,id,winner) REFERENCES couch_revisions(vault,id,rev));
CREATE TABLE IF NOT EXISTS couch_local(vault TEXT NOT NULL REFERENCES vaults(id), id TEXT NOT NULL, revision INTEGER NOT NULL CHECK(revision>0), body BLOB NOT NULL, PRIMARY KEY(vault,id));
CREATE TABLE IF NOT EXISTS couch_managers(principal TEXT NOT NULL REFERENCES principals(id), vault TEXT NOT NULL REFERENCES vaults(id), PRIMARY KEY(principal,vault));
CREATE TABLE IF NOT EXISTS couch_archives(vault TEXT PRIMARY KEY REFERENCES vaults(id), name TEXT NOT NULL, seq INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS couch_archive_grants(principal TEXT NOT NULL REFERENCES principals(id), vault TEXT NOT NULL REFERENCES vaults(id), writable INTEGER NOT NULL, PRIMARY KEY(principal,vault));
PRAGMA user_version=3;
COMMIT;
";
