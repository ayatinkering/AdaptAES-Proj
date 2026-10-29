import React, { useState, useEffect } from "react";
import { request, exportCsv, readHistory, clearHistory } from "./lab-data";
const fmt = (n, d = 3) =>
  Number(n).toLocaleString(undefined, { maximumFractionDigits: d });
const policy = (n) =>
  n <= 128
    ? { rounds: 4, arx: true }
    : n <= 512
      ? { rounds: 6 }
      : n <= 1024
        ? { rounds: 8 }
        : { rounds: 10 };
const label = (n) => {
  const p = policy(n);
  return `AES-${p.rounds}${p.arx ? " + ARX" : ""}`;
};
export function PacketSelector({ size, onChange, disabled = false }) {
  return (
    <div className="packet-selector">
      <label htmlFor="packet-range">
        Payload size <strong>{fmt(size, 0)} bytes</strong>
      </label>
      <input
        id="packet-range"
        type="range"
        min="1"
        max={Math.max(2048, size)}
        disabled={disabled}
        value={size}
        onChange={(e) => onChange(Number(e.target.value))}
      />
      <div className="policy-bands">
        {[
          [1, 128, "4 + ARX"],
          [129, 512, "6 rounds"],
          [513, 1024, "8 rounds"],
          [1025, 2048, "10 rounds"],
        ].map(([lo, hi, text]) => (
          <button
            key={lo}
            disabled={disabled}
            className={
              size >= lo && (lo === 1025 || size <= hi) ? "selected" : ""
            }
            onClick={() => onChange(lo)}
          >
            {text}
            <small>
              {lo}–{hi === 2048 ? "65,536" : hi} B
            </small>
          </button>
        ))}
      </div>
    </div>
  );
}
export function Home({ catalog, go }) {
  const [size, setSize] = useState(128),
    [busy, setBusy] = useState(false),
    [result, setResult] = useState(null),
    [error, setError] = useState("");
  const p = policy(size);
  const attackRows = catalog?.datasets?.["figures/attack_results.csv"] || [];
  const attackControl = attackRows.find((row) => row.design === "AES-4");
  const attackHybrid = attackRows.find((row) => row.design === "AES-4 + ARX");
  const recorded = (
    catalog?.datasets?.["figures/speed_results.csv"] || []
  ).filter((r) => Number(r.bytes) === 256);
  const hy = recorded.find((r) => r.design === "AES-4 + ARX"),
    aes = recorded.find((r) => r.design === "AES-10");
  async function run() {
    setBusy(true);
    setError("");
    try {
      setResult(
        await request("encrypt", {
          data: btoa("A".repeat(size)),
          key: "000102030405060708090a0b0c0d0e0f",
          mode: "adaptive_arx",
        }),
      );
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>AdaptAES lab</h1>
          <p>Payload-dependent AES rounds with an ARX mixing stage.</p>
        </div>
        <button className="secondary" onClick={() => go("results")}>
          Research results
        </button>
      </div>
      <section className="home-encryption">
        <div>
          <h2>Choose a packet size</h2>
          <PacketSelector
            disabled={busy}
            size={size}
            onChange={(n) => {
              setSize(n);
              setResult(null);
            }}
          />
          <button className="primary" disabled={busy} onClick={run}>
            {busy ? "Encrypting…" : "Run encryption"}
          </button>
          {error && <p role="alert">{error}</p>}
        </div>
        <div className="home-pipeline">
          <h2>{label(size)}</h2>
          <div className="pipeline-flow">
            <span>
              Plaintext<small>{size} bytes</small>
            </span>
            <span>
              Padding<small>{Math.floor(size / 16) + 1} blocks</small>
            </span>
            <span>
              Initial key<small>AddRoundKey</small>
            </span>
            {Array.from({ length: p.rounds }, (_, i) => i + 1).flatMap((n) => [
              <span key={n}>R{n}</span>,
              ...(p.arx && n === 2
                ? [
                    <span key="arx" className="arx-node">
                      ARX
                    </span>,
                  ]
                : []),
            ])}
            <span>Ciphertext</span>
          </div>
          {result ? (
            <>
              <div className="home-run-values">
                <span>
                  <strong>{fmt(result.encryption_ms)} ms</strong>Encryption
                </span>
                <span>
                  <strong>{fmt(result.throughput_mib_s)} MiB/s</strong>
                  Throughput
                </span>
                <span className="verified-text">
                  {result.verified ? "Exact recovery verified" : ""}
                </span>
              </div>
              <pre className="home-cipher">
                {result.ciphertext.slice(0, 128)}
                {result.ciphertext.length > 128 ? "…" : ""}
              </pre>
              <p className="lab-note">
                Measured server encryption time. State inspection is available
                in the workbench.
              </p>
            </>
          ) : (
            <p className="lab-note">
              Run the actual Python implementation. Timing excludes
              visualisation.
            </p>
          )}
          <button className="secondary" onClick={() => go("encrypt")}>
            Open full workbench
          </button>
        </div>
      </section>
      <section className="home-evidence">
        <h2>Recorded experiment highlights</h2>
        <div className="evidence-lines">
          <div>
            <strong>
              {hy && aes
                ? fmt(Number(aes.median_ms) / Number(hy.median_ms), 2) + "×"
                : "—"}
            </strong>
            <span>
              Fixed hybrid speedup over AES-10
              <small>256 B · supplied padded-message benchmark</small>
            </span>
          </div>
          <div>
            <strong>
              {attackControl
                ? `${attackControl.key_recoveries_by_this_attack} / ${attackControl.trials}`
                : "—"}
            </strong>
            <span>
              AES-4 keys recovered
              <small>Recorded integral attack control</small>
            </span>
          </div>
          <div>
            <strong>
              {attackHybrid?.mean_surviving_guesses_after_1024_queries ?? "—"}
            </strong>
            <span>
              Hybrid candidates surviving the same equation
              <small>
                {attackHybrid?.trials ?? "—"} recorded trials · attack-specific
                observation
              </small>
            </span>
          </div>
        </div>
        <button className="text-button" onClick={() => go("analyze")}>
          Inspect experiments
        </button>
      </section>
      <Architecture compact />
    </>
  );
}
export function StreamLab({
  title = "Packet-stream experiment",
  initialSizes = "64, 128, 129, 512, 513, 1024, 1025",
}) {
  const [sizes, setSizes] = useState(initialSizes),
    [seed, setSeed] = useState("20261029"),
    [busy, setBusy] = useState(false),
    [result, setResult] = useState(null),
    [error, setError] = useState(""),
    [metric, setMetric] = useState("latency");
  async function run() {
    setError("");
    setBusy(true);
    try {
      const values = sizes.split(",").map((s) => Number(s.trim()));
      setResult(await request("stream", { sizes: values, seed: Number(seed) }));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  const max = result
    ? Math.max(
        ...result.rows.flatMap((r) =>
          metric === "latency"
            ? [r.adaptive_ms, r.aes10_ms]
            : [r.adaptive_mib_s, r.aes10_mib_s],
        ),
      ) * 1.1
    : 1;
  return (
    <section className="stream-lab">
      <div className="lab-section-heading">
        <h2>{title}</h2>
        {result && (
          <button
            className="secondary"
            onClick={() => exportCsv("adaptaes-packet-stream.csv", result.rows)}
          >
            Export CSV
          </button>
        )}
      </div>
      <p className="lab-note">
        Synthetic payloads processed by the real cipher. No network traffic is
        generated.
      </p>
      <div className="stream-controls">
        <label>
          Packet sizes in bytes
          <input
            value={sizes}
            disabled={busy}
            onChange={(e) => {
              setSizes(e.target.value);
              setResult(null);
            }}
            placeholder="64, 128, 129, 512"
          />
          <small>1–12 comma-separated sizes · 1–4,096 bytes each</small>
        </label>
        <label>
          Seed
          <input
            type="number"
            value={seed}
            min="0"
            max="4294967295"
            disabled={busy}
            onChange={(e) => {
              setSeed(e.target.value);
              setResult(null);
            }}
          />
        </label>
        <button className="primary" disabled={busy} onClick={run}>
          {busy ? "Processing packets…" : "Process stream"}
        </button>
      </div>
      <div className="stream-presets">
        {[
          ["Boundary sweep", "128, 129, 512, 513, 1024, 1025"],
          ["Small packets", "32, 64, 96, 128, 64, 32"],
          ["Mixed workload", "64, 128, 256, 512, 1024, 1500"],
        ].map(([name, value]) => (
          <button
            key={name}
            className="secondary"
            onClick={() => {
              setSizes(value);
              setResult(null);
            }}
            disabled={busy}
          >
            {name}
          </button>
        ))}
      </div>
      {busy && (
        <p className="lab-note" role="status">
          Running a warm-up and three timed repetitions per method for each
          packet. Decryption is verified outside the timer.
        </p>
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {result && (
        <>
          <div className="stream-summary">
            <span>
              <b>{result.packets}</b> packets
            </span>
            <span>
              <b>{fmt(result.total_bytes, 0)} B</b> processed
            </span>
            <span>
              <b>{fmt(result.speedup, 2)}×</b> AES-10 time / AdaptAES time
            </span>
            <span className="verified-text">
              {result.verified ? "All packets verified" : ""}
            </span>
          </div>
          <div className="chart-control">
            <label>
              Measure
              <select
                value={metric}
                onChange={(e) => setMetric(e.target.value)}
              >
                <option value="latency">Latency · lower is faster</option>
                <option value="throughput">
                  Throughput · higher is faster
                </option>
              </select>
            </label>
            <span>
              <i className="swatch adaptive" />
              AdaptAES <i className="swatch standard" />
              AES-10
            </span>
          </div>
          <div
            className="packet-chart"
            role="img"
            aria-label={"Measured packet " + metric + " comparison"}
          >
            {result.rows.map((r) => (
              <div className="packet-chart-row" key={r.packet}>
                <span>
                  #{r.packet} · {r.bytes} B<small>{r.algorithm}</small>
                </span>
                <div>
                  {[
                    [
                      "adaptive",
                      metric === "latency" ? r.adaptive_ms : r.adaptive_mib_s,
                    ],
                    [
                      "standard",
                      metric === "latency" ? r.aes10_ms : r.aes10_mib_s,
                    ],
                  ].map(([name, value]) => (
                    <div className="packet-bar-line" key={name}>
                      <div className="packet-bar-track">
                        <div
                          className={"packet-bar " + name}
                          style={{ width: (value / max) * 100 + "%" }}
                        />
                      </div>
                      <span>
                        {fmt(value)} {metric === "latency" ? "ms" : "MiB/s"}
                      </span>
                    </div>
                  ))}
                </div>
                <strong>{fmt(r.speedup, 2)}×</strong>
              </div>
            ))}
          </div>
          <details>
            <summary>Packet measurements and verification</summary>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    {[
                      "Packet",
                      "Bytes",
                      "Configuration",
                      "AdaptAES ms",
                      "AES-10 ms",
                      "Recovery",
                    ].map((t) => (
                      <th key={t}>{t}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {result.rows.map((r) => (
                    <tr key={r.packet}>
                      <td>{r.packet}</td>
                      <td className="num">{r.bytes}</td>
                      <td>{r.algorithm}</td>
                      <td className="num">{fmt(r.adaptive_ms)}</td>
                      <td className="num">{fmt(r.aes10_ms)}</td>
                      <td>{r.verified ? "Verified" : "Failed"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
          <p className="lab-note">{result.methodology}</p>
          <p className="lab-note">
            Measured on the server running this API. Speedup may vary between
            runs and hosts.
          </p>
        </>
      )}
    </section>
  );
}
export function RunHistory() {
  const [rows, setRows] = useState(readHistory);
  useEffect(() => {
    const f = () => setRows(readHistory());
    window.addEventListener("adaptaes-history", f);
    return () => window.removeEventListener("adaptaes-history", f);
  }, []);
  return (
    <section className="history-lab">
      <div className="lab-section-heading">
        <h2>Session history</h2>
        <div>
          <button
            className="secondary"
            disabled={!rows.length}
            onClick={() =>
              exportCsv(
                "adaptaes-session.csv",
                rows.flatMap((r) =>
                  r.rows.map((value) => ({
                    time: r.time,
                    experiment: r.type,
                    seed: r.seed,
                    repetitions: r.repeats,
                    methodology: r.methodology,
                    ...value,
                  })),
                ),
              )
            }
          >
            Export CSV
          </button>
          <button
            className="text-button"
            disabled={!rows.length}
            onClick={clearHistory}
          >
            Clear history
          </button>
        </div>
      </div>
      <p className="lab-note">
        Last 40 completed runs in this browser tab. Summaries only; plaintext,
        ciphertext and keys are excluded.
      </p>
      {!rows.length ? (
        <p>Run an encryption, comparison or attack to collect results here.</p>
      ) : (
        <div className="history-list">
          {rows.map((r) => (
            <details key={r.id}>
              <summary>
                <span>{r.type}</span>
                <time>{new Date(r.time).toLocaleTimeString()}</time>
                <span>
                  {r.bytes ? `${fmt(r.bytes, 0)} B` : `${r.repeats} trial(s)`}
                </span>
              </summary>
              <p className="lab-note">{r.methodology}</p>
              <pre>{JSON.stringify(r.rows, null, 2)}</pre>
              <button
                className="secondary"
                onClick={() => exportCsv("adaptaes-" + r.type + ".csv", r.rows)}
              >
                Export this run
              </button>
            </details>
          ))}
        </div>
      )}
    </section>
  );
}
export function Architecture({ compact = false }) {
  return (
    <section className="architecture-lab">
      <h2>Adaptive architecture</h2>
      <div className="architecture-flow">
        <span>Payload length</span>
        <span>Round policy</span>
        <span>AES rounds 1–2</span>
        <span>
          ARX after round 2<small>Only for the hybrid path</small>
        </span>
        <span>Remaining AES rounds</span>
        <span>Ciphertext</span>
      </div>
      <div className="architecture-columns">
        <div>
          <h3>Round allocation</h3>
          <table>
            <thead>
              <tr>
                <th>Payload</th>
                <th>AdaptAES–ARX</th>
                <th>AES reference</th>
              </tr>
            </thead>
            <tbody>
              {[
                ["1–128 B", "4 rounds + ARX"],
                ["129–512 B", "6 rounds"],
                ["513–1,024 B", "8 rounds"],
                ["1,025–65,536 B", "10 rounds"],
              ].map(([n, m]) => (
                <tr key={n}>
                  <td>{n}</td>
                  <td>{m}</td>
                  <td>10 rounds</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div>
          <h3>What changes</h3>
          <p>
            The hybrid inserts two reversible ARX iterations between AES rounds
            2 and 3. It uses 32-bit modular addition, XOR, and rotations of 7,
            11, 17 and 23 bits.
          </p>
          <p>
            The fixed hybrid always uses four AES rounds. The adaptive
            integration selects it only for payloads up to 128 bytes.
          </p>
          {!compact && (
            <>
              <h3>Measurement definitions</h3>
              <dl>
                <dt>Throughput</dt>
                <dd>payload bytes / 2²⁰ / encryption seconds</dd>
                <dt>Speedup</dt>
                <dd>AES-10 encryption time / AdaptAES encryption time</dd>
                <dt>Diffusion</dt>
                <dd>popcount(C XOR C′) / 128 × 100%</dd>
              </dl>
              <p>
                Integral tests measure surviving key candidates and verified
                AES-4 recovery. Differential and linear probes measure
                finite-sample patterns. Block substitution tests message
                integrity separately.
              </p>
            </>
          )}
        </div>
      </div>
    </section>
  );
}
export function DiffusionRounds({ stages }) {
  if (!stages?.length) return null;
  const rows = stages.filter(
    (s) => s.name === "Input block" || /AddRoundKey|ARX/.test(s.name),
  );
  return (
    <div className="diffusion-rounds">
      <h3>Diffusion through the rounds</h3>
      <p className="lab-note">
        Changed bits after flipping one input bit. Diffusion is not a
        cryptanalytic security score.
      </p>
      {rows.map((s) => (
        <div key={s.name}>
          <span>{s.name.replace(" · AddRoundKey", "")}</span>
          <div className="diffusion-track">
            <span style={{ width: (s.changed_bits / 128) * 100 + "%" }} />
          </div>
          <strong>{s.changed_bits} / 128</strong>
        </div>
      ))}
    </div>
  );
}
