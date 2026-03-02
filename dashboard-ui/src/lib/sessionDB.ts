/**
 * IndexedDB-backed session storage for crawl reports.
 * Each imported report.json is saved as a "session" that persists across page reloads.
 */

const DB_NAME = "prowl_sessions";
const DB_VERSION = 1;
const STORE_NAME = "sessions";

export interface SessionMeta {
  id: string;
  name: string;
  target: string;
  date: number; // epoch ms
  endpointCount: number;
}

export interface SessionRecord extends SessionMeta {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any; // full report.json payload
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "id" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function saveSession(
  name: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any
): Promise<string> {
  const target = data.target || "";

  // De-dup: reuse existing session with the same target URL
  const existing = (await listSessions()).find((s) => s.target === target);
  const id = existing?.id ?? `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  const record: SessionRecord = {
    id,
    name: existing?.name ?? name, // keep original name if updating
    target,
    date: Date.now(),
    endpointCount: Array.isArray(data.endpoints) ? data.endpoints.length : 0,
    data,
  };
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).put(record); // upsert by id
    tx.oncomplete = () => resolve(id);
    tx.onerror = () => reject(tx.error);
  });
}

export async function listSessions(): Promise<SessionMeta[]> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const req = tx.objectStore(STORE_NAME).getAll();
    req.onsuccess = () => {
      const records: SessionRecord[] = req.result;
      // Return metadata only (no data blob), sorted newest first
      const metas: SessionMeta[] = records
        .map(({ id, name, target, date, endpointCount }) => ({
          id,
          name,
          target,
          date,
          endpointCount,
        }))
        .sort((a, b) => b.date - a.date);
      resolve(metas);
    };
    req.onerror = () => reject(req.error);
  });
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function loadSession(id: string): Promise<any | null> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readonly");
    const req = tx.objectStore(STORE_NAME).get(id);
    req.onsuccess = () => {
      const record: SessionRecord | undefined = req.result;
      resolve(record?.data ?? null);
    };
    req.onerror = () => reject(req.error);
  });
}

export async function deleteSession(id: string): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, "readwrite");
    tx.objectStore(STORE_NAME).delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/** Remove duplicate sessions that share the same target URL, keeping only the newest. */
export async function deduplicateSessions(): Promise<number> {
  const all = await listSessions(); // already sorted newest-first
  const seen = new Set<string>();
  let removed = 0;
  for (const s of all) {
    if (seen.has(s.target)) {
      await deleteSession(s.id);
      removed++;
    } else {
      seen.add(s.target);
    }
  }
  return removed;
}
