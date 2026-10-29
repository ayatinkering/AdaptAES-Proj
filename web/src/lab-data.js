const HISTORY_KEY = "adaptaes-run-summaries-v1";
export function readHistory() {
  try {
    return JSON.parse(sessionStorage.getItem(HISTORY_KEY) || "[]");
  } catch {
    return [];
  }
}
export function clearHistory() {
  sessionStorage.removeItem(HISTORY_KEY);
  window.dispatchEvent(new Event("adaptaes-history"));
}
function remember(path, data) {
  if (
    !["encrypt", "compare", "stream"].includes(path) &&
    !(data.state === "done" && data.result)
  )
    return;
  const value = data.result || data;
  const rows = value.rows || [
    {
      design: data.config?.algorithm,
      bytes: data.original_bytes,
      encryption_ms: data.encryption_ms,
      decryption_ms: data.decryption_ms,
      verified: data.verified,
      changed_bits: data.diffusion?.changed_bits,
    },
  ];
  // Summaries only: never retain plaintext, ciphertext, key material or raw attack details.
  const summary = {
    id: Date.now() + "-" + Math.random().toString(36).slice(2),
    time: new Date().toISOString(),
    type: value.kind || path,
    bytes: value.total_bytes || value.bytes || data.original_bytes || null,
    seed: value.seed ?? null,
    repeats: value.repeats || value.trials || 1,
    rows: rows.map(({ details, curve, ...r }) => r),
    methodology:
      value.methodology ||
      value.scope ||
      data.measurement ||
      "Same input and key; five timed encryption runs after warm-up.",
  };
  try {
    sessionStorage.setItem(
      HISTORY_KEY,
      JSON.stringify([summary, ...readHistory()].slice(0, 40)),
    );
  } catch {
    /* The live experiment still works when browser storage is unavailable. */
  }
  window.dispatchEvent(new Event("adaptaes-history"));
}
export async function request(path, body, method) {
  const response = await fetch(
    "/api/" + path,
    body
      ? {
          method: method || "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        }
      : method
        ? { method }
        : {},
  );
  let data;
  try {
    data = await response.json();
  } catch {
    throw Error(
      "The research API did not return a result. Check the connection and retry.",
    );
  }
  if (!response.ok)
    throw Error(data.error || "Could not complete the request.");
  remember(path, data);
  return data;
}
export function exportCsv(name, rows) {
  if (!rows.length) return;
  const columns = [...new Set(rows.flatMap(Object.keys))];
  const cell = (v) => '"' + String(v ?? "").replaceAll('"', '""') + '"';
  const text = [
    columns.map(cell).join(","),
    ...rows.map((r) =>
      columns
        .map((k) =>
          cell(typeof r[k] === "object" ? JSON.stringify(r[k]) : r[k]),
        )
        .join(","),
    ),
  ].join("\r\n");
  const url = URL.createObjectURL(
    new Blob([text], { type: "text/csv;charset=utf-8" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
