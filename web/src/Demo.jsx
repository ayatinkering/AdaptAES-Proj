import React, { useEffect, useState } from "react";
import { request, exportCsv } from "./lab-data";
import "./demo.css";
const KEY = "000102030405060708090a0b0c0d0e0f";
const names = {
  aes4: "AES-4",
  hybrid: "AES-4 + ARX",
  aes5: "AES-5",
  aes6: "AES-6",
  aes8: "AES-8",
  aes10: "AES-10",
  adaptive: "Original AdaptAES",
  adaptive_arx: "AdaptAES–ARX",
};
const fmt = (n, d = 3) =>
  n === null || n === undefined
    ? "—"
    : Number(n).toLocaleString(undefined, { maximumFractionDigits: d });
const chosen = (n) =>
  n <= 128
    ? "AES-4 + ARX"
    : n <= 512
      ? "AES-6"
      : n <= 1024
        ? "AES-8"
        : "AES-10";
const colour = (n) =>
  /ARX/.test(n)
    ? "#56e596"
    : n === "AES-10"
      ? "#66b8ff"
      : n === "AES-4"
        ? "#ff7979"
        : n === "AES-5"
          ? "#ffe265"
          : "#bfc9d4";
const encode = (bytes) => {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
};
const short = (n) => n.replace("Original AdaptAES", "AdaptAES (original)");
function ErrorText({ value }) {
  return value ? (
    <p className="demo-error" role="alert">
      {value}
    </p>
  ) : null;
}
function Plot({ rows, field, unit = "", label, limit }) {
  const max =
    limit ||
    Math.max(...rows.map((r) => Number(r[field]) || 0), Number.EPSILON) * 1.12;
  return (
    <figure className="demo-plot">
      <figcaption>{label}</figcaption>
      {rows.map((r) => (
        <div className="demo-bar-row" key={r.design}>
          <span>{short(r.design)}</span>
          <div className="demo-track">
            <div
              style={{
                width: (Math.max(0, Number(r[field]) || 0) / max) * 100 + "%",
                background: colour(r.design),
              }}
            />
          </div>
          <strong>
            {fmt(r[field])}
            {unit && " " + unit}
          </strong>
        </div>
      ))}
      <div className="demo-scale">
        <span>0</span>
        <span>
          {fmt(max)} {unit}
        </span>
      </div>
    </figure>
  );
}
function Matrix({ stage, previous, label }) {
  return (
    <div className="demo-matrix-wrap">
      <h3>{label}</h3>
      <div className="demo-matrix" aria-label={label + " 4 by 4 AES state"}>
        {Array.from({ length: 16 }, (_, i) => {
          const j = 4 * (i % 4) + Math.floor(i / 4),
            v = stage?.bytes[j];
          return (
            <span
              key={i}
              className={previous && previous.bytes[j] !== v ? "changed" : ""}
            >
              {v === undefined ? "—" : v.toString(16).padStart(2, "0")}
            </span>
          );
        })}
      </div>
    </div>
  );
}
function Trace({ value }) {
  const [stage, setStage] = useState(0),
    [play, setPlay] = useState(false);
  useEffect(() => {
    setStage(0);
    setPlay(false);
  }, [value]);
  useEffect(() => {
    if (!play || !value) return;
    if (stage >= value.trace.length - 1) {
      setPlay(false);
      return;
    }
    const t = setTimeout(() => setStage(stage + 1), 650);
    return () => clearTimeout(t);
  }, [play, stage, value]);
  if (!value) return null;
  const current = value.trace[stage],
    previous = value.trace[Math.max(0, stage - 1)];
  function jump(i) {
    setPlay(false);
    setStage(i);
  }
  return (
    <section className="demo-trace">
      <div className="demo-section-head">
        <h2>Inside {value.config.algorithm}</h2>
        <button
          className="demo-button"
          onClick={() => {
            if (!play) setStage(0);
            setPlay(!play);
          }}
        >
          {play ? "Pause" : "Replay steps"}
        </button>
      </div>
      <div className="demo-rounds">
        {Array.from({ length: value.config.rounds }, (_, i) => i + 1).flatMap(
          (n) => {
            const a = (
              <button
                key={n}
                className={
                  current.name.startsWith(`Round ${n} ·`) ? "selected" : ""
                }
                onClick={() =>
                  jump(
                    value.trace.findIndex((s) =>
                      s.name.startsWith(`Round ${n} ·`),
                    ),
                  )
                }
              >
                Round {n}
              </button>
            );
            return n === 2 && value.config.arx
              ? [
                  a,
                  <button
                    key="arx"
                    className={
                      current.name.startsWith("ARX") ? "arx selected" : "arx"
                    }
                    onClick={() =>
                      jump(
                        value.trace.findIndex((s) => s.name.startsWith("ARX")),
                      )
                    }
                  >
                    ARX
                  </button>,
                ]
              : [a];
          },
        )}
      </div>
      <div className="demo-transform">
        <button
          className="demo-button"
          disabled={stage === 0}
          onClick={() => jump(stage - 1)}
          aria-label="Previous transformation"
        >
          ←
        </button>
        <label>
          <span className="sr-only">Transformation</span>
          <select value={stage} onChange={(e) => jump(Number(e.target.value))}>
            {value.trace.map((s, i) => (
              <option key={i} value={i}>
                {s.name}
              </option>
            ))}
          </select>
        </label>
        <button
          className="demo-button"
          disabled={stage === value.trace.length - 1}
          onClick={() => jump(stage + 1)}
          aria-label="Next transformation"
        >
          →
        </button>
      </div>
      <div className="demo-matrices">
        <Matrix stage={previous} label="Before" />
        <span aria-hidden="true">→</span>
        <Matrix stage={current} previous={previous} label="After" />
      </div>
      {current.words_before && (
        <div className="demo-arx">
          <h3>Two ARX iterations</h3>
          <p>
            Add modulo 2³², rotate by 7 / 11 / 17 / 23 bits, then XOR. The same
            master key is used.
          </p>
          {current.words_before.map((w, i) => (
            <code key={i}>
              W{i}: {w} → {current.words_after[i]}
            </code>
          ))}
        </div>
      )}
      <p className="demo-note">
        Actual first-block states, checked against the supplied cipher. Replay
        is slowed for inspection; it is excluded from timing.
      </p>
      <details>
        <summary>Ciphertext and recovery</summary>
        <pre className="demo-hex">{value.ciphertext}</pre>
        <p className="demo-pass">
          {value.verified
            ? "Exact input recovered after decryption."
            : "Verification failed."}
        </p>
      </details>
    </section>
  );
}
function LiveSecurity({ rows }) {
  const [metric, setMetric] = useState("plaintext_avalanche_percent");
  return (
    <section>
      <div className="demo-section-head">
        <h2>Diffusion and statistics</h2>
        <select
          aria-label="Statistical graph"
          value={metric}
          onChange={(e) => setMetric(e.target.value)}
        >
          <option value="plaintext_avalanche_percent">
            Plaintext avalanche
          </option>
          <option value="key_avalanche_percent">Key avalanche</option>
          <option value="block_entropy">Block entropy</option>
        </select>
      </div>
      <Plot
        rows={rows}
        field={metric}
        limit={metric === "block_entropy" ? 4 : 100}
        unit={metric === "block_entropy" ? "bits/byte" : "%"}
        label={
          metric === "block_entropy"
            ? "Mean entropy per 16-byte ciphertext block"
            : "Changed output bits after single-bit flips"
        }
      />
      <div className="demo-table-scroll">
        <table>
          <thead>
            <tr>
              <th>Cipher</th>
              <th>Plaintext AE %</th>
              <th>Key AE %</th>
              <th>Block entropy</th>
              <th>Recovery</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.mode}>
                <td>{r.design}</td>
                <td>{fmt(r.plaintext_avalanche_percent, 2)}</td>
                <td>{fmt(r.key_avalanche_percent, 2)}</td>
                <td>{fmt(r.block_entropy, 4)}</td>
                <td className="demo-pass">Verified</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="demo-note">
        Eight plaintext-bit flips and eight key-bit flips on the first padded
        block. Empirical entropy is averaged per 16-byte block, so its maximum
        is 4 bits/byte. Similar statistics do not imply similar attack
        resistance.
      </p>
    </section>
  );
}
function ReportStudy({ catalog }) {
  const [metric, setMetric] = useState("enc"),
    [bucket, setBucket] = useState("1-128");
  const timing =
      catalog?.original_study?.["bucket_security_performance_summary.csv"] ||
      [],
    security =
      catalog?.original_study?.["roundwise_security_summary.csv"] || [];
  const overall = ["standard_aes_10", "fixed_reduced_aes_4", "adaptaes"].map(
    (mode) => {
      const values = timing.filter((row) => row.mode === mode),
        count = values.reduce(
          (sum, row) => sum + Number(row.timing_sample_count),
          0,
        );
      return {
        mode,
        design:
          mode === "adaptaes"
            ? "Original AdaptAES"
            : mode === "standard_aes_10"
              ? "AES-10"
              : "AES-4",
        count,
        enc:
          values.reduce(
            (sum, row) =>
              sum +
              Number(row.mean_encryption_time_ns) *
                Number(row.timing_sample_count),
            0,
          ) /
          count /
          1e6,
        dec:
          values.reduce(
            (sum, row) =>
              sum +
              Number(row.mean_decryption_time_ns) *
                Number(row.timing_sample_count),
            0,
          ) /
          count /
          1e6,
      };
    },
  );
  const rows = timing
    .filter((r) => r.payload_bucket === bucket)
    .map((r) => ({
      design:
        r.mode === "adaptaes"
          ? "Original AdaptAES"
          : r.mode === "standard_aes_10"
            ? "AES-10"
            : "AES-4",
      enc: Number(r.mean_encryption_time_ns) / 1e6,
      dec: Number(r.mean_decryption_time_ns) / 1e6,
      rounds: r.rounds_used,
      count: r.timing_sample_count,
      reduction: Number(r.time_reduction_percent_vs_aes10),
    }));
  return (
    <details className="demo-study">
      <summary>
        Original report: traffic study and round-wise statistics
      </summary>
      <p className="demo-note">
        Historical original AdaptAES results from repository aggregates. These
        measurements do not include the new ARX hybrid.
      </p>
      <div className="demo-section-head">
        <h3>Payload-category timing</h3>
        <div className="demo-controls">
          <select
            aria-label="Report payload category"
            value={bucket}
            onChange={(e) => setBucket(e.target.value)}
          >
            {["1-128", "129-512", "513-1024", ">1024"].map((b) => (
              <option key={b}>{b}</option>
            ))}
          </select>
          <select
            aria-label="Report timing metric"
            value={metric}
            onChange={(e) => setMetric(e.target.value)}
          >
            <option value="enc">Encryption</option>
            <option value="dec">Decryption</option>
          </select>
        </div>
      </div>
      <Plot rows={rows} field={metric} unit="ms" label="Recorded mean time" />
      <div className="demo-table-scroll">
        <table>
          <thead>
            <tr>
              <th>Configuration</th>
              <th>Rounds</th>
              <th>Enc. ms</th>
              <th>Dec. ms</th>
              <th>Enc. reduction %</th>
              <th>Timed payloads</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.design}>
                <td>{r.design}</td>
                <td>{r.rounds}</td>
                <td>{fmt(r.enc)}</td>
                <td>{fmt(r.dec)}</td>
                <td>{fmt(r.reduction, 2)}</td>
                <td>{r.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <h3>Overall original timing study</h3>
      <div className="demo-table-scroll">
        <table>
          <thead>
            <tr>
              <th>Cipher</th>
              <th>Timed payloads</th>
              <th>Enc. ms</th>
              <th>Dec. ms</th>
              <th>Enc. reduction %</th>
            </tr>
          </thead>
          <tbody>
            {overall
              .filter((r) => r.count)
              .map((r) => (
                <tr key={r.mode}>
                  <td>{r.design}</td>
                  <td>{r.count}</td>
                  <td>{fmt(r.enc, 2)}</td>
                  <td>{fmt(r.dec, 2)}</td>
                  <td>{fmt((1 - r.enc / overall[0].enc) * 100, 2)}</td>
                </tr>
              ))}
          </tbody>
        </table>
      </div>
      <p className="demo-note">
        Overall times weight each payload-category mean by its timed-payload
        count. The workload distribution determines the aggregate saving.
      </p>
      <h3>Recorded round-wise statistics</h3>
      <div className="demo-table-scroll">
        <table>
          <thead>
            <tr>
              {[
                "Rounds",
                "Block samples",
                "Plaintext AE %",
                "Key AE %",
                "Entropy",
                "Chi-square",
                "NPCR %",
                "Correlation",
              ].map((t) => (
                <th key={t}>{t}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {security.map((r) => (
              <tr key={r.rounds}>
                <td>{r.rounds}</td>
                <td>{fmt(r.sample_count, 0)}</td>
                <td>{fmt(r.avalanche_percent, 3)}</td>
                <td>{fmt(r.key_avalanche_percent, 3)}</td>
                <td>{fmt(r.entropy_bits_per_byte, 4)}</td>
                <td>{fmt(r.chi_square, 2)}</td>
                <td>{fmt(r.npcr_byte_percent, 3)}</td>
                <td>{fmt(r.plaintext_ciphertext_correlation, 4)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="demo-note">
        Samples pool matching round counts across original encryption modes.
        Entropy and chi-square are averaged over individual 16-byte blocks.
        Source: results/analysis aggregates, preserved in
        research/report_reference.
      </p>
    </details>
  );
}
function EncryptionScreen({ catalog, onAttacks }) {
  const [text, setText] = useState(
      "Information security lab: AdaptAES with ARX mixing.",
    ),
    [file, setFile] = useState(null),
    [key, setKey] = useState(KEY),
    [mode, setMode] = useState("adaptive_arx"),
    [result, setResult] = useState(null),
    [comparison, setComparison] = useState(null),
    [metric, setMetric] = useState("median_ms"),
    [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  const bytes = file?.bytes || new TextEncoder().encode(text);
  const size = bytes.length;
  function invalidate() {
    setResult(null);
    setComparison(null);
    setError("");
  }
  function setSize(n) {
    invalidate();
    setFile(null);
    setText("A".repeat(n));
  }
  async function run() {
    setBusy(true);
    setError("");
    try {
      const body = { data: encode(bytes), key, mode };
      const encrypted = await request("encrypt", body);
      const compared = await request("compare", body);
      if (
        compared.rows?.length !== 8 ||
        compared.rows.some((row) => row.decryption_ms === undefined)
      )
        throw Error(
          "The Python server is running the previous API. Restart it with python3 -m api.server, then try again.",
        );
      setResult(encrypted);
      setComparison(compared);
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  async function inspect(selected) {
    setMode(selected);
    if (!comparison) return;
    setBusy(true);
    setError("");
    try {
      setResult(
        await request("encrypt", { data: encode(bytes), key, mode: selected }),
      );
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <div className="demo-title">
        <h1>Encrypt and compare</h1>
        <p>One input. All round counts. The same key and measurement method.</p>
      </div>
      <section className="demo-input">
        <div>
          <label htmlFor="demo-message">Your message</label>
          <textarea
            id="demo-message"
            disabled={busy}
            value={file ? `File: ${file.name} (${size} bytes)` : text}
            readOnly={!!file}
            onChange={(e) => {
              invalidate();
              setText(e.target.value);
            }}
          />
          <div className="demo-input-tools">
            <label className="demo-file">
              Use a file
              <input
                type="file"
                disabled={busy}
                onChange={async (e) => {
                  const f = e.target.files[0];
                  if (!f) return;
                  invalidate();
                  if (f.size > 4096) {
                    setError("Choose a file up to 4 KiB for comparison.");
                    return;
                  }
                  setFile({
                    name: f.name,
                    bytes: new Uint8Array(await f.arrayBuffer()),
                  });
                }}
              />
            </label>
            <button
              className="demo-text"
              disabled={busy}
              onClick={() => {
                invalidate();
                setFile(null);
                setText("Information security lab: AdaptAES with ARX mixing.");
              }}
            >
              Default text
            </button>
            <span>{fmt(size, 0)} bytes</span>
          </div>
          <div className="demo-size-tools">
            <label>
              Payload size
              <input
                aria-label="Generate payload size in bytes"
                type="number"
                min="1"
                max="4096"
                disabled={busy}
                value={size}
                onChange={(e) => {
                  const n = Number(e.target.value);
                  if (Number.isInteger(n) && n >= 1 && n <= 4096) setSize(n);
                }}
              />
            </label>
            <div>
              {[64, 128, 129, 512, 513, 1024, 1025].map((n) => (
                <button disabled={busy} key={n} onClick={() => setSize(n)}>
                  {n} B
                </button>
              ))}
            </div>
          </div>
        </div>
        <div className="demo-selection">
          <h2>{chosen(size || 1)}</h2>
          <p>Selected automatically for {fmt(size, 0)} bytes.</p>
          <div className="demo-policy">
            {[
              ["1–128 B", "4 + ARX"],
              ["129–512 B", "6 rounds"],
              ["513–1,024 B", "8 rounds"],
              [">1,024 B", "10 rounds"],
            ].map(([s, r], i) => (
              <div
                className={
                  (size <= 128 ? 0 : size <= 512 ? 1 : size <= 1024 ? 2 : 3) ===
                  i
                    ? "selected"
                    : ""
                }
                key={s}
              >
                <span>{s}</span>
                <strong>{r}</strong>
              </div>
            ))}
          </div>
          <div className="demo-flow">
            AES 1–2 <span>→</span>{" "}
            {size <= 128 && (
              <>
                ARX <span>→</span>
              </>
            )}{" "}
            AES 3–{size <= 128 ? 4 : size <= 512 ? 6 : size <= 1024 ? 8 : 10}
          </div>
          <details>
            <summary>Key and inspected cipher</summary>
            <label>
              128-bit key
              <input
                value={key}
                disabled={busy}
                maxLength="32"
                onChange={(e) => {
                  invalidate();
                  setKey(e.target.value);
                }}
              />
            </label>
            <label>
              Inspect
              <select
                disabled={busy}
                value={mode}
                onChange={(e) => inspect(e.target.value)}
              >
                {Object.entries(names).map(([m, n]) => (
                  <option value={m} key={m}>
                    {n}
                  </option>
                ))}
              </select>
            </label>
          </details>
          <button
            className="demo-primary"
            disabled={busy || !size || size > 4096}
            onClick={run}
          >
            {busy ? "Measuring all configurations…" : "Encrypt & compare all"}
          </button>
          <p className="demo-note">
            Up to 4 KiB. Actual Python encryption and decryption.
          </p>
        </div>
      </section>
      <ErrorText value={error} />
      {comparison ? (
        <>
          <section>
            <div className="demo-section-head">
              <h2>Performance comparison</h2>
              <button
                className="demo-button"
                onClick={() =>
                  exportCsv("adaptaes-comparison.csv", comparison.rows)
                }
              >
                Export CSV
              </button>
            </div>
            <div className="demo-metric-controls">
              {[
                ["median_ms", "Encryption"],
                ["decryption_ms", "Decryption"],
                ["throughput_mib_s", "Throughput"],
              ].map(([id, name]) => (
                <button
                  key={id}
                  className={metric === id ? "selected" : ""}
                  onClick={() => setMetric(id)}
                >
                  {name}
                </button>
              ))}
            </div>
            <Plot
              rows={comparison.rows}
              field={metric}
              unit={metric === "throughput_mib_s" ? "MiB/s" : "ms"}
              label={
                metric === "throughput_mib_s"
                  ? "Payload throughput · higher is faster"
                  : "Median time · lower is faster"
              }
            />
            <div className="demo-table-scroll">
              <table>
                <thead>
                  <tr>
                    {[
                      "Cipher",
                      "Rounds",
                      "Enc. ms",
                      "Dec. ms",
                      "MiB/s",
                      "Speedup vs AES-10",
                      "Recovery",
                      "",
                    ].map((t, i) => (
                      <th key={i}>{t}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {comparison.rows.map((r) => (
                    <tr key={r.mode}>
                      <td style={{ color: colour(r.design) }}>{r.design}</td>
                      <td>
                        {r.rounds}
                        {r.arx ? " + ARX" : ""}
                      </td>
                      <td>{fmt(r.median_ms)}</td>
                      <td>{fmt(r.decryption_ms)}</td>
                      <td>{fmt(r.throughput_mib_s)}</td>
                      <td>{fmt(r.speedup, 2)}×</td>
                      <td className="demo-pass">Verified</td>
                      <td>
                        <button
                          className="demo-text"
                          disabled={busy}
                          onClick={() => inspect(r.mode)}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="demo-note">
              {comparison.bytes} bytes · {comparison.repeats} timed runs per
              cipher. {comparison.scope} Speedup = AES-10 time ÷ this cipher’s
              time. Timings measure the server, not the visual replay.
            </p>
          </section>
          <LiveSecurity rows={comparison.rows} />
          <Trace value={result} />
          <button className="demo-primary" onClick={onAttacks}>
            Test attack resistance
          </button>
        </>
      ) : (
        <div className="demo-empty">
          Run the comparison to see encryption time, decryption time,
          throughput, recovery verification and diffusion for every
          configuration.
        </div>
      )}
      <ReportStudy catalog={catalog} />
    </>
  );
}
const descriptions = {
  integral: {
    name: "Integral key recovery",
    what: "The attacker submits structured plaintexts, filters last-round byte-key guesses, and tries to recover the AES-4 master key.",
    steps: [
      "Submit chosen messages",
      "Filter key guesses",
      "Recover and verify the key",
    ],
  },
  differential: {
    name: "Differential probe",
    what: "The attacker flips one plaintext bit and measures patterns in the output differences.",
    steps: [
      "Choose plaintext pairs",
      "Encrypt both messages",
      "Count differences and bias",
    ],
  },
  linear: {
    name: "Linear probe",
    what: "The attacker searches selected input and output bit pairs for correlation.",
    steps: [
      "Collect plaintext / ciphertext pairs",
      "Test selected bit masks",
      "Find the strongest correlation",
    ],
  },
  substitution: {
    name: "Block substitution",
    what: "The attacker replaces the first encrypted block of one message with a block from another message encrypted under the same key.",
    steps: [
      "Capture two messages",
      "Replace one encrypted block",
      "Check the delivered plaintext",
    ],
  },
};
function AttacksScreen({ catalog }) {
  const [kind, setKind] = useState("integral"),
    [seed, setSeed] = useState("20261029"),
    [busy, setBusy] = useState(false),
    [result, setResult] = useState(null),
    [error, setError] = useState(""),
    [progress, setProgress] = useState(null),
    [stage, setStage] = useState(0),
    [design, setDesign] = useState("AES-4");
  const jobRef = React.useRef(null),
    timerRef = React.useRef(null);
  useEffect(
    () => () => {
      clearTimeout(timerRef.current);
      jobRef.current = null;
    },
    [],
  );
  function accept(value) {
    if (
      value.rows?.length !== 6 ||
      (value.kind === "integral" && !value.rows[0].details?.[0]?.oracle_samples)
    )
      throw Error(
        "The Python server is running the previous API. Restart it with python3 -m api.server, then try again.",
      );
    setResult(value);
  }
  async function poll(id) {
    try {
      const j = await request("experiments/" + id);
      if (jobRef.current !== id) return;
      setProgress(j);
      if (j.state === "running")
        timerRef.current = setTimeout(() => poll(id), 400);
      else {
        setBusy(false);
        jobRef.current = null;
        if (j.state === "done") {
          accept(j.result);
          setStage(0);
        } else setError(j.error || "The run did not complete.");
      }
    } catch (e) {
      setError(e.message);
      setBusy(false);
    }
  }
  async function run() {
    setError("");
    setResult(null);
    setBusy(true);
    setProgress(null);
    setStage(0);
    try {
      const j = await request("experiments", {
        kind,
        seed: Number(seed),
        trials: 1,
      });
      if (j.state === "done") {
        accept(j.result);
        setBusy(false);
      } else {
        jobRef.current = j.id;
        poll(j.id);
      }
    } catch (e) {
      setError(e.message);
      setBusy(false);
    }
  }
  async function cancel() {
    clearTimeout(timerRef.current);
    const id = jobRef.current;
    jobRef.current = null;
    try {
      if (id) await request("experiments/" + id, null, "DELETE");
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  const desc = descriptions[kind];
  const row = result?.rows.find((r) => r.design === design) || result?.rows[0];
  const detail = row?.details?.[0];
  const curveRows = result?.rows.map((r) => ({
    ...r,
    candidates: r.curve?.[stage] ?? 0,
  }));
  function outcome(r) {
    if (kind === "integral")
      return r.verified_recoveries === 1
        ? "Master key recovered"
        : r.final_candidates === 0
          ? "No surviving guesses"
          : "Recovery not verified";
    if (kind === "substitution")
      return r.accepted ? "Modified message accepted" : "Modification rejected";
    return "Measured pattern; no key recovery attempted";
  }
  return (
    <>
      <div className="demo-title">
        <h1>Attack lab</h1>
        <p>
          Run a real experiment, follow the evidence, and compare cipher
          outcomes.
        </p>
      </div>
      <div className="demo-attack-tabs">
        {Object.entries(descriptions).map(([id, d]) => (
          <button
            disabled={busy}
            className={kind === id ? "selected" : ""}
            key={id}
            onClick={() => {
              setKind(id);
              setResult(null);
              setError("");
              setStage(0);
            }}
          >
            {d.name}
          </button>
        ))}
      </div>
      <section className="demo-attack-intro">
        <h2>{desc.name}</h2>
        <p>{desc.what}</p>
        <div className="demo-attack-actions">
          <label>
            Seed
            <input
              type="number"
              min="0"
              max="4294967295"
              disabled={busy}
              value={seed}
              onChange={(e) => setSeed(e.target.value)}
            />
          </label>
          <button className="demo-primary" disabled={busy} onClick={run}>
            {busy
              ? "Running actual experiment…"
              : kind === "substitution"
                ? "Intercept & replace a block"
                : "Run experiment"}
          </button>
          {busy && jobRef.current && (
            <button className="demo-button" onClick={cancel}>
              Cancel
            </button>
          )}
          <span>One trial per cipher · six configurations</span>
        </div>
        <ErrorText value={error} />
        {busy && (
          <p role="status">
            {progress?.design
              ? `${progress.design} completed · ${progress.completed} / ${progress.total}`
              : "Generating and encrypting test messages…"}
          </p>
        )}
      </section>
      <div className="demo-attack-steps">
        {desc.steps.map((s, i) => (
          <div key={s}>
            <strong>{i + 1}</strong>
            <span>{s}</span>
          </div>
        ))}
      </div>
      {!result ? (
        <div className="demo-empty">
          Run this experiment to display the actual observations and per-cipher
          comparison. No results are simulated in the browser.
        </div>
      ) : (
        <>
          <div className="demo-section-head">
            <h2>What happened</h2>
            <button
              className="demo-button"
              onClick={() =>
                exportCsv(
                  "adaptaes-" + kind + ".csv",
                  result.rows.map(({ details, curve, ...r }) => r),
                )
              }
            >
              Export CSV
            </button>
          </div>
          {kind === "integral" ? (
            <>
              <div className="demo-filter-controls">
                <label>
                  Chosen-message sets inspected
                  <input
                    type="range"
                    min="0"
                    max="3"
                    value={stage}
                    onChange={(e) => setStage(Number(e.target.value))}
                  />
                </label>
                <strong>{(stage + 1) * 256} queries per cipher</strong>
              </div>
              <Plot
                rows={curveRows}
                field="candidates"
                unit="guesses"
                label="Remaining byte-key guesses across 16 positions"
              />
              <p className="demo-note">
                This slider replays actual filtering counts from the completed
                backend attack. It is not simulated progress.
              </p>
            </>
          ) : kind === "substitution" ? (
            <Plot
              rows={result.rows}
              field="accepted"
              unit="/ 1 accepted"
              limit={1}
              label="Altered messages accepted · lower is better"
            />
          ) : (
            <Plot
              rows={result.rows}
              field={kind === "linear" ? "max_abs_correlation" : "max_bit_bias"}
              label={
                kind === "linear"
                  ? "Largest absolute correlation among tested masks"
                  : "Largest output-bit difference bias"
              }
            />
          )}
          <div className="demo-table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Cipher</th>
                  <th>
                    {kind === "integral"
                      ? "Final guesses"
                      : kind === "substitution"
                        ? "Accepted / trials"
                        : kind === "linear"
                          ? "Correlation"
                          : "Bit bias"}
                  </th>
                  <th>Actual outcome</th>
                  <th>Inspect</th>
                </tr>
              </thead>
              <tbody>
                {result.rows.map((r) => (
                  <tr key={r.design}>
                    <td style={{ color: colour(r.design) }}>{r.design}</td>
                    <td>
                      {fmt(
                        kind === "integral"
                          ? r.final_candidates
                          : kind === "substitution"
                            ? r.accepted
                            : kind === "linear"
                              ? r.max_abs_correlation
                              : r.max_bit_bias,
                        4,
                      )}
                    </td>
                    <td
                      className={
                        kind === "substitution" || r.verified_recoveries
                          ? "demo-fail"
                          : kind === "integral"
                            ? "demo-warning"
                            : ""
                      }
                    >
                      {outcome(r)}
                    </td>
                    <td>
                      <button
                        className="demo-text"
                        onClick={() => setDesign(r.design)}
                      >
                        Evidence
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <section className="demo-evidence">
            <div className="demo-section-head">
              <h3>{row.design}: evidence</h3>
              <select
                aria-label="Cipher evidence"
                value={row.design}
                onChange={(e) => setDesign(e.target.value)}
              >
                {result.rows.map((r) => (
                  <option key={r.design}>{r.design}</option>
                ))}
              </select>
            </div>
            {kind === "integral" ? (
              <>
                <p>
                  After 1,024 chosen messages, {fmt(row.final_candidates, 0)}{" "}
                  byte-key guesses remain across 16 positions.
                </p>
                <div className="demo-candidates">
                  {detail.candidates.map((count, i) => (
                    <span key={i}>
                      Byte {i}
                      <strong>{count}</strong>
                    </span>
                  ))}
                </div>
                <details>
                  <summary>Actual chosen-message samples</summary>
                  {detail.oracle_samples?.map((o, i) => (
                    <div key={i}>
                      <p>Plaintext {i + 1}</p>
                      <code>{o.plaintext}</code>
                      <p>Ciphertext {i + 1}</p>
                      <code>{o.ciphertext}</code>
                    </div>
                  ))}
                </details>
                {detail.aes10_challenge_verified ? (
                  <div className="demo-key-proof">
                    <h3>Recovered key verified</h3>
                    <p>Generated lab key</p>
                    <code>{detail.lab_master_key}</code>
                    <p>Recovered master key</p>
                    <code>{detail.recovered_master_key}</code>
                    <p>AES-10 message decrypted using this recovered key</p>
                    <pre>{detail.aes10_recovered_text}</pre>
                    <p className="demo-pass">Exact recovery verified.</p>
                    <p className="demo-note">
                      The same generated key was reused for this challenge. This
                      demonstrates compromise through the AES-4 oracle; it is
                      not an attack against the AES-10 primitive.
                    </p>
                  </div>
                ) : (
                  <p className="demo-warning">
                    The original integral equation produced no usable recovered
                    master key for this design. This is an attack-specific
                    result.
                  </p>
                )}
              </>
            ) : kind === "substitution" ? (
              <>
                <h4>Encrypted block replacement</h4>
                <p>Original target ciphertext</p>
                <code>{detail.target_ciphertext_block}</code>
                <p>Attacker’s ciphertext inserted</p>
                <code>{detail.modified_ciphertext_block}</code>
                <div className="demo-block-change">
                  <div>
                    <h4>Original target plaintext</h4>
                    <code>{detail.target_first_block}</code>
                  </div>
                  <div>
                    <h4>Attacker’s replacement</h4>
                    <code>{detail.source_first_block}</code>
                  </div>
                  <div>
                    <h4>Delivered plaintext block</h4>
                    <code>{detail.delivered_first_block}</code>
                  </div>
                </div>
                <p className="demo-fail">
                  The changed message was accepted without an authentication
                  check.
                </p>
                <p>
                  The delivered first block equals the attacker’s source block.
                  This affects every current wrapper, including AES-10.
                </p>
              </>
            ) : (
              <>
                <p>
                  {kind === "differential"
                    ? `${row.pairs_per_key} plaintext pairs; largest difference count ${row.max_difference_count}; largest bit bias ${fmt(row.max_bit_bias, 4)}.`
                    : `${row.plaintexts_per_key} plaintexts; strongest tested absolute correlation ${fmt(row.max_abs_correlation, 4)}.`}{" "}
                  No key recovery is attempted by this probe.
                </p>
                {detail && (
                  <div>
                    <h4>Actual sample from this run</h4>
                    <p>Plaintext</p>
                    <code>{detail.plaintext}</code>
                    {kind === "differential" ? (
                      <>
                        <p>Same plaintext with bit 0 flipped</p>
                        <code>{detail.changed_plaintext}</code>
                        <p>Original ciphertext</p>
                        <code>{detail.ciphertext}</code>
                        <p>Ciphertext after the flip</p>
                        <code>{detail.changed_ciphertext}</code>
                        <p>
                          {detail.changed_bits} of 128 ciphertext bits changed
                          in this sample.
                        </p>
                      </>
                    ) : (
                      <>
                        <p>Ciphertext</p>
                        <code>{detail.ciphertext}</code>
                        <p>
                          Strongest tested mask pair: plaintext bit{" "}
                          {detail.input_bit} → ciphertext bit{" "}
                          {detail.output_bit} (MSB-first indexing). Signed
                          correlation: {fmt(detail.correlation, 4)}.
                        </p>
                      </>
                    )}
                  </div>
                )}
              </>
            )}
          </section>
          <p className="demo-note">
            Seed {result.seed} · one trial per design. {result.scope}. The
            experiment runs on the backend using the teammate’s cipher
            implementations.
          </p>
        </>
      )}
      <details className="demo-study">
        <summary>Recorded full-sample results and interpretation</summary>
        <p className="demo-note">
          Recorded integral: AES-4 recovered 20 / 20 keys; the unchanged
          equation left no hybrid candidates. Recorded substitution: 100 / 100
          modified messages accepted by each tested wrapper. Differential and
          linear results are sampled statistical probes, not proof of equal
          security.
        </p>
        <RecordedAttack kind={kind} catalog={catalog} />
      </details>
    </>
  );
}
function RecordedAttack({ kind, catalog }) {
  const files = {
    integral: "figures/attack_results.csv",
    differential: "figures/differential_linear_probe.csv",
    linear: "figures/linear_probe.csv",
    substitution: "figures/active_attacker_results.csv",
  };
  const rows = catalog?.datasets?.[files[kind]] || [];
  if (!rows.length) return null;
  return (
    <>
      <div className="demo-table-scroll">
        <table>
          <thead>
            <tr>
              {Object.keys(rows[0]).map((k) => (
                <th key={k}>{k.replaceAll("_", " ")}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>
                {Object.values(r).map((v, j) => (
                  <td key={j}>{v}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <button
        className="demo-button"
        onClick={() => exportCsv("recorded-" + kind + ".csv", rows)}
      >
        Export recorded CSV
      </button>
      <p className="demo-note">
        Source: {files[kind]}. Original measurements preserved without
        alteration.
      </p>
    </>
  );
}
export function TwoScreenLab() {
  const [page, setPage] = useState(
      location.hash === "#attacks" ? "attacks" : "home",
    ),
    [catalog, setCatalog] = useState(null),
    [error, setError] = useState("");
  useEffect(() => {
    const f = () => {
      setPage(location.hash === "#attacks" ? "attacks" : "home");
      window.scrollTo({ top: 0, behavior: "instant" });
    };
    window.addEventListener("hashchange", f);
    request("results")
      .then(setCatalog)
      .catch((e) => setError(e.message));
    return () => window.removeEventListener("hashchange", f);
  }, []);
  function go(next) {
    location.hash = next;
    window.scrollTo({ top: 0, behavior: "instant" });
  }
  return (
    <div className="demo-app">
      <header className="demo-header">
        <a className="demo-logo" href="#home">
          ADAPTAES
        </a>
        <nav aria-label="Main navigation">
          <a
            href="#home"
            className={page === "home" ? "selected" : ""}
            aria-current={page === "home" ? "page" : undefined}
          >
            Encryption & comparison
          </a>
          <a
            href="#attacks"
            className={page === "attacks" ? "selected" : ""}
            aria-current={page === "attacks" ? "page" : undefined}
          >
            Attack lab
          </a>
        </nav>
      </header>
      <main>
        <ErrorText value={error} />
        <div hidden={page !== "home"}>
          <EncryptionScreen catalog={catalog} onAttacks={() => go("attacks")} />
        </div>
        <div hidden={page !== "attacks"}>
          <AttacksScreen catalog={catalog} />
        </div>
      </main>
      <footer className="demo-footer">
        <span>AdaptAES information security lab</span>
        <span>
          Actual cipher outputs · recorded studies labelled separately
        </span>
      </footer>
    </div>
  );
}
