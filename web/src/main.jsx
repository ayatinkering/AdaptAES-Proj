import React, { useState, useEffect, useRef } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";
import { request as api, exportCsv } from "./lab-data";
import {
  Home,
  PacketSelector,
  StreamLab,
  RunHistory,
  Architecture,
  DiffusionRounds,
} from "./Lab";
import "./lab.css";

const encoder = new TextEncoder();
const MODES = [
  ["adaptive_arx", "AdaptAES–ARX"],
  ["adaptive", "Original AdaptAES"],
  ["hybrid", "Fixed AES-4 + ARX"],
  ["aes4", "Fixed AES-4"],
  ["aes5", "Fixed AES-5"],
  ["aes10", "Standard AES-10"],
];
const TITLES = {
  integral: "Integral key-recovery experiment",
  differential: "Differential pattern probe",
  linear: "Linear-correlation probe",
  substitution: "Active block-substitution experiment",
};
const SOURCE_MAP = {
  integral: "evaluate_hybrid.py",
  differential: "probe_differential_linear.py",
  linear: "probe_linear.py",
  substitution: "probe_active_attacker.py",
};
const CSV_MAP = {
  integral: "figures/attack_results.csv",
  differential: "figures/differential_linear_probe.csv",
  linear: "figures/linear_probe.csv",
  substitution: "figures/active_attacker_results.csv",
};
const hex = (bytes) =>
  Array.from(bytes, (x) => x.toString(16).padStart(2, "0")).join("");
const b64 = (bytes) => {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
};
const from64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
function download(name, content, type = "application/json") {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function number(value, digits = 3) {
  return Number(value).toLocaleString(undefined, {
    maximumFractionDigits: digits,
  });
}
function picked(mode, length) {
  const rounds = mode.startsWith("adaptive")
    ? length <= 128
      ? 4
      : length <= 512
        ? 6
        : length <= 1024
          ? 8
          : 10
    : mode === "hybrid"
      ? 4
      : Number(mode.slice(3));
  const arx = mode === "hybrid" || (mode === "adaptive_arx" && rounds === 4);
  return { rounds, arx, label: `AES-${rounds}${arx ? " + ARX" : ""}` };
}
function ErrorLine({ error }) {
  return error ? (
    <p className="error" role="alert">
      {error}
    </p>
  ) : null;
}
function SectionTitle({ number: step, children, aside }) {
  return (
    <div className="section-title">
      <h2>{children}</h2>
      {aside}
    </div>
  );
}
function StateGrid({ bytes, previous, label }) {
  return (
    <div className="state-table">
      <span className="matrix-caption">{label}</span>
      <div className="matrix" aria-label={label}>
        {Array.from({ length: 16 }, (_, i) => {
          const j = 4 * (i % 4) + Math.floor(i / 4);
          return (
            <span
              key={j}
              className={
                previous && bytes?.[j] !== previous[j] ? "byte changed" : "byte"
              }
              title={`Row ${Math.floor(i / 4)}, column ${i % 4}; state index ${j}`}
            >
              {bytes ? bytes[j].toString(16).padStart(2, "0") : "—"}
            </span>
          );
        })}
      </div>
      <small>128 bits / column-major state</small>
    </div>
  );
}
function CipherPath({ config }) {
  const stages = Array.from({ length: config.rounds }, (_, i) => i + 1).flatMap(
    (n) => (n === 2 && config.arx ? [String(n), "ARX"] : [String(n)]),
  );
  return (
    <div className="cipher-path" aria-label="Selected encryption path">
      <span className="path-terminal">In</span>
      {stages.map((s, i) => (
        <React.Fragment key={i}>
          <span className="path-line" />
          <span className={s === "ARX" ? "round arx" : "round"}>
            {s === "ARX" ? s : "R" + s}
          </span>
        </React.Fragment>
      ))}
      <span className="path-line" />
      <span className="path-terminal">Out</span>
    </div>
  );
}
function RoundOverview({ config, result, stage, onStage }) {
  const active = result?.trace[stage]?.name || "";
  return (
    <section
      className="round-overview"
      aria-label="Round allocation and encryption progress"
    >
      <div className="round-overview-heading">
        <h2>Encryption rounds</h2>
        <span>{result ? "Block trace verified" : "Ready"}</span>
      </div>
      <div className="round-facts">
        <span>
          <b>{config.rounds}</b> AES rounds
        </span>
        <span>
          <b>{config.arx ? "2" : "0"}</b> ARX iterations
        </span>
        <span>
          <b>16 B</b> per block
        </span>
        <span>
          <b>128 bit</b> key
        </span>
      </div>
      <div className="round-timeline">
        <div className="round-card input-round">
          <strong>Input</strong>
          <small>Pad → split into blocks</small>
        </div>
        {Array.from({ length: config.rounds }, (_, i) => i + 1).flatMap((n) => {
          const index = result?.trace.findIndex((item) =>
            item.name.startsWith(`Round ${n} ·`),
          );
          const node = (
            <button
              key={n}
              disabled={!result}
              className={
                "round-card " +
                (active.startsWith(`Round ${n} ·`) ? "current-round" : "")
              }
              onClick={() => onStage(index)}
            >
              <strong>Round {n}</strong>
              <small>
                {n === config.rounds
                  ? "Substitute · shift · key"
                  : "Substitute · shift · mix · key"}
              </small>
            </button>
          );
          return n === 2 && config.arx
            ? [
                node,
                <button
                  key="arx"
                  disabled={!result}
                  className={
                    "round-card arx-round " +
                    (active.startsWith("ARX") ? "current-round" : "")
                  }
                  onClick={() =>
                    onStage(
                      result.trace.findIndex((item) =>
                        item.name.startsWith("ARX"),
                      ),
                    )
                  }
                >
                  <strong>ARX mixing</strong>
                  <small>Add · rotate · XOR × 2</small>
                </button>,
              ]
            : [node];
        })}
        <div className="round-card output-round">
          <strong>Output</strong>
          <small>
            {result ? "Decryption verified ✓" : "Ciphertext → verify recovery"}
          </small>
        </div>
      </div>
      <p>
        {result
          ? `Inspecting: ${active}. Select a round or use Replay encryption below.`
          : "Initial key addition precedes round 1. The final round omits MixColumns."}
      </p>
    </section>
  );
}
function designClass(name = "") {
  if (/random/i.test(name)) return "design-reference";
  if (/ARX/.test(name)) return "design-hybrid";
  if (/AES-10/.test(name)) return "design-aes10";
  if (/AES-5/.test(name)) return "design-aes5";
  if (/AES-4|Original AdaptAES/.test(name)) return "design-aes4";
  return "design-reference";
}
function DesignLegend() {
  return (
    <div className="design-legend" aria-label="Chart colour key">
      {[
        ["AES-4", "Reduced-round control"],
        ["AES-4 + ARX", "Hybrid prototype"],
        ["AES-5", "Extra-round reference"],
        ["AES-10", "Full-round reference"],
      ].map(([name, description]) => (
        <span key={name} className={designClass(name)}>
          <i aria-hidden="true" />
          {name}
          <small>{description}</small>
        </span>
      ))}
    </div>
  );
}
function DemoGuide({ analysis = false }) {
  return (
    <details className="demo-guide">
      <summary>How to try this {analysis ? "experiment" : "workbench"}</summary>
      {analysis ? (
        <ol>
          <li>
            Start with <b>Integral</b> and choose <b>Run locally</b>.
          </li>
          <li>
            Keep seed <code>20261029</code> and <b>1 trial</b>, then choose{" "}
            <b>Run experiment</b>.
          </li>
          <li>
            AES-4 should finish with 16 candidates: one correct byte at each of
            16 positions. The evaluator verifies whether the recovered master
            key is correct.
          </li>
          <li>
            For the hybrid, inspect whether the original integral equation
            leaves any candidates. Zero means the equation failed, not that
            every attack fails.
          </li>
          <li>
            Try <b>Differential</b> and <b>Linear</b> in Recorded mode to
            compare the full-sample probes against the random reference.
          </li>
          <li>
            Try <b>Block substitution</b> to see the separate message-wrapper
            integrity issue.
          </li>
        </ol>
      ) : (
        <ol>
          <li>
            Type <code>Hello, AdaptAES!</code> in the text box and keep{" "}
            <b>AdaptAES–ARX</b> selected.
          </li>
          <li>
            Choose <b>Encrypt &amp; inspect</b>. Check the selected round count,
            ciphertext and <b>Exact plaintext recovered</b>.
          </li>
          <li>
            In <b>Encryption steps</b>, select the ARX operation to inspect the
            actual state before and after mixing.
          </li>
          <li>
            Choose the <b>128</b> and <b>129</b> size presets. The first selects
            AES-4 + ARX; the second selects AES-6.
          </li>
          <li>
            Choose <b>Compare methods</b> for a repeated timing comparison, or
            change one input bit below the trace.
          </li>
          <li>
            Open <b>Analysis</b> for attacks and <b>Research</b> for the
            supplied experiment results.
          </li>
        </ol>
      )}
    </details>
  );
}
function Bars({ rows, metric, label, unit = "" }) {
  const values = rows.map((r) => Number(r[metric]));
  const max = Math.max(...values, Number.EPSILON) * 1.12;
  return (
    <div className="bar-chart">
      <p className="chart-caption">{label}</p>
      {rows.map((r, i) => (
        <div
          className={`bar-row ${metric === "accepted" ? "design-aes4" : designClass(r.design)}`}
          key={i}
        >
          <span>{r.design}</span>
          <svg
            viewBox="0 0 500 25"
            role="img"
            aria-label={`${r.design}: ${number(values[i])} ${unit}`}
          >
            <rect x="0" y="5" width="500" height="15" className="bar-track" />
            <rect
              x="0"
              y="5"
              width={(values[i] / max) * 500}
              height="15"
              className="bar-value"
            />
          </svg>
          <span className="num">
            {number(values[i])}
            {unit && " " + unit}
          </span>
        </div>
      ))}
    </div>
  );
}
function Curves({ rows }) {
  const max = Math.max(...rows.flatMap((r) => r.curve), 1);
  return (
    <div className="curve-chart">
      <svg
        viewBox="0 0 700 230"
        role="img"
        aria-label="Actual remaining key guesses after each chosen-plaintext set"
      >
        <line x1="55" y1="185" x2="655" y2="185" className="axis" />
        {[0, 1, 2, 3].map((i) => (
          <g key={i}>
            <text x={55 + i * 200} y="212" textAnchor="middle">
              {(i + 1) * 256}
            </text>
            <line
              x1={55 + i * 200}
              y1="25"
              x2={55 + i * 200}
              y2="185"
              className="gridline"
            />
          </g>
        ))}
        {[0, max / 2, max].map((v, i) => (
          <text key={i} x="45" y={188 - i * 80} textAnchor="end">
            {Math.round(v)}
          </text>
        ))}
        {rows.map((r, i) => (
          <polyline
            key={r.design}
            points={r.curve
              .map((v, j) => `${55 + j * 200},${185 - (v / max) * 160}`)
              .join(" ")}
            className={"series series-" + i}
          />
        ))}
        <text x="355" y="230" textAnchor="middle">
          Chosen plaintext queries per trial
        </text>
      </svg>
      <p className="chart-axis-caption">
        Each point is a measured mean after a 256-query set. Lower counts show
        how the equation filters candidates.
      </p>
      <div className="legend">
        {rows.map((r, i) => (
          <span key={r.design} className={"legend-item line-" + i}>
            {r.design}
          </span>
        ))}
      </div>
    </div>
  );
}

function Workspace({ openSource, onAnalyze }) {
  const [input, setInput] = useState("A message worth understanding.");
  const [tab, setTab] = useState("text");
  const [file, setFile] = useState(null);
  const [mode, setMode] = useState("adaptive_arx");
  const [key, setKey] = useState("000102030405060708090a0b0c0d0e0f");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [stage, setStage] = useState(0);
  const [block, setBlock] = useState(0);
  const [bit, setBit] = useState(0);
  const [comparison, setComparison] = useState(null);
  const [copy, setCopy] = useState("Copy hex");
  const [playing, setPlaying] = useState(false);
  useEffect(() => {
    if (!playing || !result) return;
    if (stage >= result.trace.length - 1) {
      setPlaying(false);
      return;
    }
    const timer = setTimeout(() => setStage(stage + 1), 650);
    return () => clearTimeout(timer);
  }, [playing, result, stage]);
  const bytes =
    tab === "file" ? file?.bytes || new Uint8Array() : encoder.encode(input);
  const size = bytes.length;
  const config = picked(mode, size);
  const fileRef = useRef();
  function invalidate() {
    setPlaying(false);
    setResult(null);
    setComparison(null);
    setError("");
    setBlock(0);
    setStage(0);
  }
  function changeMode(e) {
    invalidate();
    setMode(e.target.value);
  }
  function preset(n, pattern = "size") {
    invalidate();
    setTab("samples");
    setInput(
      pattern === "repeat"
        ? "0123456789ABCDEF".repeat(n / 16)
        : Array.from({ length: n }, (_, i) =>
            String.fromCharCode(65 + (i % 26)),
          ).join(""),
    );
  }
  async function run(
    compare = false,
    selectedBlock = block,
    selectedBit = bit,
  ) {
    setBusy(true);
    setError("");
    try {
      const body = {
        data: b64(bytes),
        key,
        mode,
        block: selectedBlock,
        bit: selectedBit,
      };
      if (compare) setComparison(await api("compare", body));
      else {
        const r = await api("encrypt", body);
        setPlaying(false);
        setResult(r);
        if (size <= 4096) setComparison(await api("compare", body));
        setStage(
          r.trace.findIndex((s) => s.name.startsWith("ARX")) >= 0
            ? r.trace.findIndex((s) => s.name.startsWith("ARX"))
            : 1,
        );
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }
  const adaptiveTiming = comparison?.rows.find(
    (row) => row.design === "AdaptAES–ARX",
  );
  const standardTiming = comparison?.rows.find(
    (row) => row.design === "AES-10",
  );
  const current = result?.trace[stage],
    before = result?.trace[Math.max(0, stage - 1)];
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>Encryption lab</h1>
          <p>
            Encrypt a message. See the selected rounds. Compare with AES-10.
          </p>
        </div>
        <button
          className="text-button source-link"
          onClick={() => openSource("aes_hybrid.py")}
        >
          Cipher source
        </button>
      </div>

      <div className="workbench">
        <section className="input-pane">
          <SectionTitle number="01">
            Plaintext <span className="muted">/ your input</span>
          </SectionTitle>
          <div
            className="tabs input-tabs"
            role="tablist"
            aria-label="Input type"
          >
            {["text", "file", "samples"].map((t) => (
              <button
                key={t}
                role="tab"
                aria-selected={tab === t}
                className={tab === t ? "active" : ""}
                onClick={() => {
                  invalidate();
                  setTab(t);
                }}
              >
                {t === "samples"
                  ? "Sample payloads"
                  : t === "file"
                    ? "File"
                    : "Text"}
              </button>
            ))}
          </div>
          {tab === "file" ? (
            <div className="file-zone">
              <input
                ref={fileRef}
                id="file-upload"
                type="file"
                onChange={async (e) => {
                  invalidate();
                  const f = e.target.files[0];
                  if (!f) {
                    setFile(null);
                    return;
                  }
                  if (f.size > 65536) {
                    setError(
                      "Choose a file up to 64 KiB for this live Python experiment.",
                    );
                    setFile(null);
                    return;
                  }
                  setFile({
                    name: f.name,
                    bytes: new Uint8Array(await f.arrayBuffer()),
                  });
                }}
              />
              <label htmlFor="file-upload" className="file-label">
                {file ? file.name : "Choose a file"}
                <span>
                  {file
                    ? `${number(file.bytes.length, 0)} bytes`
                    : "Any file type · up to 64 KiB"}
                </span>
              </label>
              {file && (
                <pre className="file-preview">
                  {hex(file.bytes.slice(0, 48))
                    .match(/.{1,2}/g)
                    ?.join(" ")}
                  {file.bytes.length > 48 ? " …" : ""}
                </pre>
              )}
            </div>
          ) : (
            <>
              <label className="sr-only" htmlFor="plaintext">
                Message to encrypt
              </label>
              <textarea
                id="plaintext"
                spellCheck="false"
                value={input}
                onChange={(e) => {
                  invalidate();
                  setInput(e.target.value);
                }}
                placeholder="Enter your message…"
              />
              {tab === "samples" && (
                <div className="sample-options">
                  <button onClick={() => preset(64, "repeat")}>
                    Repeated blocks · 64 B
                  </button>
                  <button onClick={() => preset(84)}>
                    Short message · 84 B
                  </button>
                  <button onClick={() => preset(1460)}>
                    Traffic-size sample · 1460 B
                  </button>
                  <small>
                    Generated contents; 1460 B is a sample size, not a live
                    packet.
                  </small>
                </div>
              )}
            </>
          )}
          <div className="input-meta">
            <span>
              {number(size, 0)} <span className="muted">bytes</span>
            </span>
            <span>
              {tab === "file"
                ? "Binary input"
                : `${Array.from(input).length} characters / UTF-8`}
            </span>
            <button
              className="text-button"
              onClick={() => {
                invalidate();
                setInput("");
                setFile(null);
                if (fileRef.current) fileRef.current.value = "";
              }}
            >
              Clear
            </button>
          </div>
          <PacketSelector
            disabled={busy}
            size={size}
            onChange={(n) => preset(n)}
          />
          <div className="thresholds">
            <span>Test a boundary</span>
            <div>
              {[128, 129, 512, 513, 1024, 1025].map((n) => (
                <button key={n} onClick={() => preset(n)}>
                  {n}
                </button>
              ))}
            </div>
          </div>
          <div className="automatic-selection">
            <strong>{config.label}</strong>
            <small>
              {number(size, 0)} bytes → {config.rounds} rounds
              {config.arx ? " + ARX" : ""}
            </small>
          </div>
          <details className="manual-mode">
            <summary>Change reference method</summary>
            <label className="field-label" htmlFor="mode">
              Encryption configuration
            </label>
            <select id="mode" value={mode} onChange={changeMode}>
              {MODES.map(([v, label]) => (
                <option value={v} key={v}>
                  {label}
                </option>
              ))}
            </select>
          </details>
          <details className="key-details">
            <summary>
              128-bit key <span>{key.slice(0, 8)}…</span>
            </summary>
            <label className="sr-only" htmlFor="key">
              32-character hexadecimal key
            </label>
            <input
              id="key"
              value={key}
              maxLength={32}
              spellCheck="false"
              onChange={(e) => {
                invalidate();
                setKey(e.target.value);
              }}
            />
            <div className="key-actions">
              <small>Public demo key. Nothing is saved.</small>
              <button
                className="text-button"
                onClick={() => {
                  invalidate();
                  setKey(hex(crypto.getRandomValues(new Uint8Array(16))));
                }}
              >
                Generate key
              </button>
            </div>
          </details>
          <div className="run-row">
            <button
              className="primary"
              disabled={busy || size === 0 || size > 65536}
              onClick={() => run()}
            >
              {busy
                ? "Processing…"
                : size <= 4096
                  ? "Encrypt & compare"
                  : "Encrypt & inspect"}
              <span>↗</span>
            </button>
            <button
              className="secondary"
              disabled={busy || size === 0 || size > 4096}
              onClick={() => run(true)}
              title="Five timed runs after a warm-up; up to 4 KiB"
            >
              Compare methods
            </button>
          </div>
          <ErrorLine error={error} />
        </section>
        <section className="output-pane">
          <SectionTitle
            number="02"
            aside={
              <span className="status">
                {result ? "Verified output" : "Ready"}
              </span>
            }
          >
            Ciphertext <span className="muted">/ encrypted output</span>
          </SectionTitle>
          <div className="selected-cipher">
            <div>
              <span>
                {size
                  ? `${number(size, 0)} bytes selects`
                  : "Selected configuration"}
              </span>
              <h3>{config.label}</h3>
            </div>
            <span className="bit-label">
              128-bit block
              <br />
              128-bit key
            </span>
          </div>
          <CipherPath config={config} />
          <details className="policy-details">
            <summary>Selection policy</summary>
            <p className="policy-note">
              {mode === "adaptive_arx"
                ? config.arx
                  ? "ARX mixing runs after round 2. Larger payloads retain the original 6/8/10-round policy."
                  : "This size uses the original AES path. ARX is applied only to payloads up to 128 bytes."
                : mode === "hybrid"
                  ? "Fixed four-round AES with the exact ARX transformation from the supplied prototype."
                  : mode === "adaptive"
                    ? "The original payload-size policy selects 4, 6, 8 or 10 AES rounds."
                    : "Fixed-round reference using the supplied Python AES core."}
            </p>
          </details>
          {result ? (
            <>
              <div className="hex-heading">
                <span>Hexadecimal ciphertext</span>
                <button
                  className="text-button"
                  onClick={async () => {
                    try {
                      await navigator.clipboard.writeText(result.ciphertext);
                      setCopy("Copied");
                      setTimeout(() => setCopy("Copy hex"), 1400);
                    } catch {
                      setError(
                        "Clipboard is unavailable. Select and copy the hexadecimal output.",
                      );
                    }
                  }}
                >
                  {copy}
                </button>
              </div>
              <pre className="hex-output">
                {result.ciphertext
                  .slice(0, 1024)
                  .match(/.{1,2}/g)
                  ?.join(" ")}
                {result.ciphertext.length > 1024
                  ? "\n… Download full output to inspect every byte."
                  : ""}
              </pre>
              <div className="metrics">
                <div>
                  <span>Encryption</span>
                  <strong>
                    {number(result.encryption_ms)} <small>ms</small>
                  </strong>
                </div>
                <div>
                  <span>Decryption</span>
                  <strong>
                    {number(result.decryption_ms)} <small>ms</small>
                  </strong>
                </div>
                <div>
                  <span>Throughput</span>
                  <strong>
                    {number(result.throughput_mib_s)} <small>MiB/s</small>
                  </strong>
                </div>
              </div>
              <p className="measurement">
                Single encryption run · visual replay excluded.
              </p>
              <div className="verification">
                <span>✓ Exact plaintext recovered</span>
                <span>
                  {result.blocks} blocks / {result.padding_bytes} padding bytes
                </span>
              </div>
              <div className="download-row">
                <button
                  className="text-button"
                  onClick={() =>
                    download(
                      "ciphertext.bin",
                      Uint8Array.from(result.ciphertext.match(/../g), (b) =>
                        parseInt(b, 16),
                      ),
                      "application/octet-stream",
                    )
                  }
                >
                  Download ciphertext ↓
                </button>
                <button
                  className="text-button"
                  onClick={() =>
                    download(
                      file?.name || "recovered.txt",
                      from64(result.recovered),
                      "application/octet-stream",
                    )
                  }
                >
                  Download recovered input ↓
                </button>
              </div>
            </>
          ) : (
            <div className="empty-output">
              <div className="empty-brackets" aria-hidden="true">
                [ 00 — FF ]
              </div>
              <p>Your ciphertext will appear here.</p>
              <span>
                Encrypt a message to inspect its state
                <br />
                and verify exact decryption.
              </span>
            </div>
          )}
        </section>
      </div>
      <RoundOverview
        config={config}
        result={result}
        stage={stage}
        onStage={(index) => {
          setPlaying(false);
          setStage(index);
        }}
      />
      {comparison && (
        <section className="comparison">
          <SectionTitle
            aside={
              <button
                className="text-button"
                onClick={() =>
                  download(
                    "local-comparison.json",
                    JSON.stringify(comparison, null, 2),
                  )
                }
              >
                Export JSON ↓
              </button>
            }
          >
            AdaptAES vs standard AES
          </SectionTitle>
          <p className="muted">
            {comparison.bytes} bytes · median of five timed runs · same input
            and key
          </p>
          <div className="direct-comparison">
            <div>
              <span>AdaptAES · automatic</span>
              <strong>
                {number(adaptiveTiming.median_ms)} <small>ms</small>
              </strong>
              <p>{number(adaptiveTiming.throughput_mib_s)} MiB/s</p>
            </div>
            <div>
              <span>Standard AES · 10 rounds</span>
              <strong>
                {number(standardTiming.median_ms)} <small>ms</small>
              </strong>
              <p>{number(standardTiming.throughput_mib_s)} MiB/s</p>
            </div>
            <div>
              <span>Measured speed ratio</span>
              <strong>
                {number(standardTiming.median_ms / adaptiveTiming.median_ms, 2)}
                ×
              </strong>
              <p>AES-10 time / AdaptAES time</p>
            </div>
          </div>
          <Bars
            rows={comparison.rows}
            metric="median_ms"
            label="Encryption time · lower is faster"
            unit="ms"
          />
          <Bars
            rows={comparison.rows}
            metric="throughput_mib_s"
            label="Throughput · higher is faster"
            unit="MiB/s"
          />
          <details>
            <summary>Measurement details</summary>
            <DataTable rows={comparison.rows} />
          </details>
        </section>
      )}
      <section className="inspector">
        <SectionTitle
          number="03"
          aside={
            result ? (
              <label className="block-select">
                Block{" "}
                <select
                  aria-label="Inspect block"
                  value={block}
                  disabled={busy}
                  onChange={(e) => {
                    setBlock(Number(e.target.value));
                    run(false, Number(e.target.value));
                  }}
                >
                  {Array.from({ length: result.blocks }, (_, i) => (
                    <option key={i} value={i}>
                      {i + 1} of {result.blocks}
                    </option>
                  ))}
                </select>
              </label>
            ) : (
              <span className="muted">Select one 16-byte block</span>
            )
          }
        >
          Encryption steps
        </SectionTitle>
        <div className="inspection-layout">
          <div className="operation-list">
            {result ? (
              result.trace.map((s, i) => (
                <button
                  key={i}
                  className={
                    (stage === i ? "selected " : "") +
                    (s.words_after ? "arx-operation" : "")
                  }
                  onClick={() => setStage(i)}
                >
                  <span>{String(i).padStart(2, "0")}</span>
                  {s.name}
                </button>
              ))
            ) : (
              <div className="operation-placeholder">
                <span>SubBytes</span>
                <span>ShiftRows</span>
                <span>MixColumns</span>
                <span>AddRoundKey</span>
                <span>ARX mixing</span>
              </div>
            )}
          </div>
          <div className="state-inspection">
            <div className="state-heading">
              <h3>{current?.name || "Block state"}</h3>
              <div className="trace-controls">
                <button
                  title="Replay measured intermediate states at a readable pace; this is not encryption duration"
                  disabled={!result}
                  onClick={() => {
                    if (!playing) setStage(0);
                    setPlaying(!playing);
                  }}
                >
                  {playing ? "Pause" : "Replay encryption"}
                </button>
                <button
                  aria-label="Previous operation"
                  disabled={!result || stage === 0}
                  onClick={() => setStage(stage - 1)}
                >
                  ←
                </button>
                <button
                  aria-label="Next operation"
                  disabled={!result || stage === result.trace.length - 1}
                  onClick={() => setStage(stage + 1)}
                >
                  →
                </button>
              </div>
            </div>
            <div className="matrices">
              <StateGrid bytes={before?.bytes} label="Before" />
              <span className="matrix-arrow">→</span>
              <StateGrid
                bytes={current?.bytes}
                previous={before?.bytes}
                label="After"
              />
            </div>
            {current?.words_after ? (
              <div className="arx-detail">
                <h4>Four 32-bit words / little-endian</h4>
                <div className="word-grid">
                  {current.words_after.map((w, i) => (
                    <div key={i}>
                      <span>W{i}</span>
                      <code>{current.words_before[i]}</code>
                      <span>→</span>
                      <code>{w}</code>
                    </div>
                  ))}
                </div>
                <p>
                  Addition modulo 2³², XOR and rotations of 7, 11, 17, 23 bits.
                  Two mixing iterations, using the same master key.
                </p>
              </div>
            ) : (
              <p className="state-note">
                {result
                  ? "Changed byte values are highlighted. The trace is verified against the supplied block implementation."
                  : "Actual intermediate bytes appear after encryption. The final AES round omits MixColumns."}
              </p>
            )}
          </div>
        </div>
      </section>
      {result && (
        <section className="diffusion">
          <SectionTitle
            aside={
              <label>
                Flip input bit{" "}
                <select
                  aria-label="Input bit to flip"
                  value={bit}
                  disabled={busy}
                  onChange={(e) => {
                    setBit(Number(e.target.value));
                    run(false, block, Number(e.target.value));
                  }}
                >
                  {Array.from({ length: 128 }, (_, i) => (
                    <option key={i}>{i}</option>
                  ))}
                </select>
              </label>
            }
          >
            Change one input bit
          </SectionTitle>
          <div className="diffusion-layout">
            <div>
              <strong>
                {result.diffusion.changed_bits}
                <span> / 128 bits</span>
              </strong>
              <p>
                {number(result.diffusion.percent, 2)}% of ciphertext bits
                changed.
              </p>
              <small>
                Matched block and key. A diffusion observation, not a security
                proof.
              </small>
            </div>
            <div className="bit-map" aria-label="Changed output bits">
              {Array.from({ length: 128 }, (_, i) => {
                const a = parseInt(
                    result.diffusion.left.slice(
                      Math.floor(i / 8) * 2,
                      Math.floor(i / 8) * 2 + 2,
                    ),
                    16,
                  ),
                  b = parseInt(
                    result.diffusion.right.slice(
                      Math.floor(i / 8) * 2,
                      Math.floor(i / 8) * 2 + 2,
                    ),
                    16,
                  ),
                  changed = ((a ^ b) >> (7 - (i % 8))) & 1;
                return (
                  <span
                    key={i}
                    title={`Output bit ${i}: ${changed ? "changed" : "unchanged"}`}
                    className={changed ? "bit on" : "bit"}
                  />
                );
              })}
            </div>
          </div>
        </section>
      )}
      <DiffusionRounds stages={result?.diffusion?.stages} />
      <StreamLab />
      <div className="next-section">
        <p></p>
        <button className="text-button" onClick={onAnalyze}>
          Open attack analysis ↗
        </button>
      </div>
    </>
  );
}

function DataTable({ rows }) {
  if (!rows?.length) return <p className="muted">No observations available.</p>;
  const cols = Object.keys(rows[0]).filter(
    (c) => !["details", "curve"].includes(c),
  );
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            {cols.map((c) => (
              <th key={c}>{c.replaceAll("_", " ")}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i}>
              {cols.map((c) => (
                <td className={typeof r[c] === "number" ? "num" : ""} key={c}>
                  {r[c] === null
                    ? "Not verified"
                    : typeof r[c] === "number"
                      ? number(r[c], 4)
                      : Array.isArray(r[c])
                        ? JSON.stringify(r[c])
                        : String(r[c])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Analysis(props) {
  const [section, setSection] = useState("attacks");
  return (
    <>
      <div
        className="tabs lab-page-tabs"
        role="tablist"
        aria-label="Analysis view"
      >
        {[
          ["attacks", "Attack experiments"],
          ["performance", "Packet performance"],
          ["history", "Run history"],
        ].map(([id, name]) => (
          <button
            role="tab"
            aria-selected={section === id}
            key={id}
            className={section === id ? "active" : ""}
            onClick={() => setSection(id)}
          >
            {name}
          </button>
        ))}
      </div>
      {section === "attacks" ? (
        <AttackAnalysis {...props} />
      ) : section === "performance" ? (
        <>
          <div className="page-heading">
            <div>
              <h1>Packet performance</h1>
              <p>
                Compare the adaptive policy and AES-10 across payload sizes.
              </p>
            </div>
          </div>
          <StreamLab title="Payload-size comparison" />
          <RunHistory />
        </>
      ) : (
        <>
          <div className="page-heading">
            <h1>Run history</h1>
          </div>
          <RunHistory />
        </>
      )}
    </>
  );
}

function AttackAnalysis({ catalog, openSource }) {
  const [kind, setKind] = useState("integral"),
    [view, setView] = useState("recorded"),
    [job, setJob] = useState(null),
    [run, setRun] = useState(null),
    [seed, setSeed] = useState(20261029),
    [trials, setTrials] = useState(1),
    [error, setError] = useState(""),
    [starting, setStarting] = useState(false);
  const [showRaw, setShowRaw] = useState(false);
  useEffect(() => {
    if (!job) return;
    let cancelled = false;
    const interval = setInterval(async () => {
      try {
        const j = await api("experiments/" + job);
        if (cancelled) return;
        setRun(j);
        if (j.state !== "running") {
          setJob(null);
          if (j.error) setError(j.error);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e.message);
          setJob(null);
        }
      }
    }, 500);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [job]);
  async function start() {
    setError("");
    setStarting(true);
    setRun(null);
    try {
      const j = await api("experiments", {
        kind,
        seed: Number(seed),
        trials: Number(trials),
      });
      if (j.state === "done") {
        setRun(j);
        setJob(null);
      } else {
        setJob(j.id);
        setRun({ state: "running", completed: 0, total: 4 * trials });
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setStarting(false);
    }
  }
  const recorded = catalog?.datasets?.[CSV_MAP[kind]] || [];
  const result = run?.result;
  const isLive = view === "live";
  function switchKind(k) {
    setKind(k);
    setRun(null);
    setError("");
  }
  const explanations = {
    integral:
      "A structured set of chosen plaintexts filters final-round byte-key guesses. Compare the original equation across four cipher designs.",
    differential:
      "One input-bit difference is propagated through each cipher. Inspect sampled output differences and bit-change bias.",
    linear:
      "Search selected input/output bit pairs for correlation. This is a finite-sample probe, not an exhaustive linear attack.",
    substitution:
      "Replace the first ciphertext block of one message with a block from another message encrypted under the same key.",
  };
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>Attack analysis</h1>
          <p>
            Choose a test. Run it locally or inspect the recorded measurements.
          </p>
        </div>
        <button
          className="text-button"
          onClick={() => openSource(SOURCE_MAP[kind])}
        >
          Experiment source
        </button>
      </div>
      <div
        className="tabs analysis-tabs"
        role="tablist"
        aria-label="Experiment"
      >
        {[
          ["integral", "Integral"],
          ["differential", "Differential"],
          ["linear", "Linear"],
          ["substitution", "Block substitution"],
        ].map(([id, label]) => (
          <button
            key={id}
            role="tab"
            aria-selected={kind === id}
            className={kind === id ? "active" : ""}
            disabled={!!job || starting}
            onClick={() => switchKind(id)}
          >
            {label}
          </button>
        ))}
      </div>
      <DemoGuide analysis />
      {result && (
        <button
          className="secondary"
          onClick={() =>
            exportCsv(
              "adaptaes-" + kind + ".csv",
              result.rows.map(({ details, curve, ...row }) => row),
            )
          }
        >
          Export live results CSV
        </button>
      )}
      <section className="experiment">
        <div className="experiment-heading">
          <h2>{TITLES[kind]}</h2>
          <div className="segmented">
            <button
              className={!isLive ? "active" : ""}
              onClick={() => setView("recorded")}
            >
              Recorded
            </button>
            <button
              className={isLive ? "active" : ""}
              onClick={() => setView("live")}
            >
              Run locally
            </button>
          </div>
        </div>
        <p className="experiment-explanation">{explanations[kind]}</p>
        <DesignLegend />
        <div className="reading-note">
          <strong>What to look for</strong>
          <p>
            {kind === "integral"
              ? "AES-4 is the attack control. A verified key recovery demonstrates the attack works; no surviving hybrid candidates means the original attack condition was disrupted."
              : kind === "substitution"
                ? "Every accepted modified message indicates missing integrity protection. Red bars show successful substitutions, including against full-round AES."
                : kind === "differential"
                  ? "Compare each cipher with the random reference. These bars show sampled differences; a small numerical gap alone is not evidence of a weakness."
                  : "Compare the largest tested bit correlation with the random reference. This is a limited search over selected masks, not a complete security assessment."}
          </p>
        </div>
        {isLive ? (
          <>
            <div className="experiment-controls">
              <label>
                Seed
                <input
                  type="number"
                  min="0"
                  max="4294967295"
                  value={seed}
                  onChange={(e) => setSeed(e.target.value)}
                />
              </label>
              <label>
                Trials per design
                <select
                  value={trials}
                  onChange={(e) => setTrials(e.target.value)}
                >
                  {[1, 2, 3].map((t) => (
                    <option key={t}>{t}</option>
                  ))}
                </select>
              </label>
              <button
                className="primary"
                disabled={!!job || starting}
                onClick={start}
              >
                {starting
                  ? "Running experiment…"
                  : job
                    ? "Running experiment…"
                    : "Run experiment"}
                <span>↗</span>
              </button>
              {job && (
                <button
                  className="secondary"
                  onClick={async () => {
                    try {
                      const state = await api(
                        "experiments/" + job,
                        null,
                        "DELETE",
                      );
                      setRun(state);
                      setJob(null);
                    } catch (e) {
                      setError(e.message);
                    }
                  }}
                >
                  Cancel
                </button>
              )}
            </div>
            <p className="measurement">
              {kind === "integral"
                ? "Four sets × 256 chosen blocks per trial. Uses the supplied integral and key-schedule inversion functions."
                : kind === "substitution"
                  ? "Two generated 32-byte messages per trial. Same key; local reconstruction only."
                  : "256 samples per key in this quick run. Recorded probes use larger sample budgets."}{" "}
              One local worker; 180-second limit.
            </p>
            <ErrorLine error={error} />
            {run?.state === "running" && (
              <div className="job-progress" role="status">
                <progress max={run.total} value={run.completed} />
                <span>
                  {run.completed} / {run.total} completed trials{" "}
                  {run.design && "— " + run.design}
                </span>
              </div>
            )}
            {result ? (
              <>
                <div className="result-heading">
                  <span>Live result / seed {result.seed}</span>
                  <button
                    className="text-button"
                    onClick={() =>
                      download(
                        `${kind}-${result.seed}.json`,
                        JSON.stringify(result, null, 2),
                      )
                    }
                  >
                    Export experiment ↓
                  </button>
                </div>
                {kind === "integral" ? (
                  <>
                    <Curves rows={result.rows} />
                    <div className="outcome-grid">
                      {result.rows.map((r) => (
                        <div key={r.design} className={designClass(r.design)}>
                          <h3>{r.design}</h3>
                          <strong>{r.final_candidates}</strong>
                          <span>remaining key-byte candidates</span>
                          <small>
                            {r.verified_recoveries === null
                              ? r.final_candidates === 0
                                ? "No candidate satisfies this equation"
                                : "Key recovery not evaluated"
                              : `${r.verified_recoveries}/${r.trials} master keys verified`}
                          </small>
                        </div>
                      ))}
                    </div>
                  </>
                ) : kind === "differential" ? (
                  <Bars
                    rows={result.rows}
                    metric="max_bit_bias"
                    label="Mean maximum output-bit bias from 50%"
                  />
                ) : kind === "linear" ? (
                  <Bars
                    rows={result.rows}
                    metric="max_abs_correlation"
                    label="Mean strongest tested absolute correlation"
                  />
                ) : (
                  <>
                    <Bars
                      rows={result.rows}
                      metric="accepted"
                      label="Modified messages accepted"
                    />
                    <BlockDemo row={result.rows[1]?.details[0]} />
                  </>
                )}
                <p className="scope-note">{result.scope}.</p>
                <details>
                  <summary>Inspect live observations</summary>
                  <DataTable rows={result.rows} />
                </details>
              </>
            ) : (
              !job && (
                <div className="experiment-empty">
                  <span>Set the parameters and run an experiment.</span>
                  <p>
                    Results are computed by your local Python implementation.
                  </p>
                </div>
              )
            )}
          </>
        ) : (
          <>
            <div className="result-heading">
              <span>Supplied research / recorded results</span>
              <button
                className="text-button"
                onClick={() => openSource(CSV_MAP[kind])}
              >
                {CSV_MAP[kind]} ↗
              </button>
            </div>
            {kind === "integral" ? (
              <>
                <Bars
                  rows={recorded.map((r) => ({
                    design: r.design,
                    remaining: Number(
                      r.mean_surviving_guesses_after_1024_queries,
                    ),
                  }))}
                  metric="remaining"
                  label="Remaining byte-key guesses after 1,024 queries (20 trials)"
                />
                <div className="finding danger-finding">
                  <strong>AES-4: 20 / 20 master keys recovered.</strong>
                  <p>
                    The unchanged integral equation left zero candidates for
                    AES-4 + ARX, AES-5, AES-6 and AES-10. Only AES-4 recovery is
                    verified by the supplied script.
                  </p>
                </div>
              </>
            ) : kind === "differential" ? (
              <>
                <Bars
                  rows={recorded.map((r) => ({
                    design: r.design,
                    bias: Number(r.mean_max_bit_bias),
                  }))}
                  metric="bias"
                  label="Mean maximum bit-change bias / 2,048 pairs per key"
                />
                <Bars
                  rows={recorded.map((r) => ({
                    design: r.design,
                    count: Number(r.mean_largest_byte_difference_count),
                  }))}
                  metric="count"
                  label="Mean largest output-byte difference count / same experiment"
                  unit="occurrences"
                />
                <p className="scope-note">
                  Eight keys per cipher; random reference from 200 simulated
                  samples. Similar sampled statistics do not establish equal
                  cryptanalytic security.
                </p>
              </>
            ) : kind === "linear" ? (
              <>
                <Bars
                  rows={recorded.map((r) => ({
                    design: r.design,
                    correlation: Number(r.max_abs_correlation_mean),
                  }))}
                  metric="correlation"
                  label="Mean maximum absolute correlation / 2,048 plaintexts per key"
                />
                <p className="scope-note">
                  Four keys per cipher. Searches 16 selected input bits against
                  128 output bits; the random reference uses 200 simulations.
                </p>
              </>
            ) : (
              <>
                <Bars
                  rows={recorded.map((r) => ({
                    design: r.design,
                    accepted: Number(r.substituted_message_accepted),
                  }))}
                  metric="accepted"
                  label="Substituted messages accepted / 100 trials"
                />
                <div className="finding danger-finding">
                  <strong>
                    All four wrappers accepted substituted blocks.
                  </strong>
                  <p>
                    This is a shared lack of message authentication, not
                    recovery of the AES-10 key. The hybrid does not add an
                    integrity check.
                  </p>
                </div>
              </>
            )}
            <button
              className="text-button raw-toggle"
              onClick={() => setShowRaw(!showRaw)}
            >
              {showRaw ? "Hide" : "Show"} original measurement table{" "}
              {showRaw ? "−" : "+"}
            </button>
            {showRaw && <DataTable rows={recorded} />}
          </>
        )}
      </section>
      <section className="research-boundary">
        <h2>What this experiment measures</h2>
        <p>
          {kind === "integral"
            ? "Failure of the original integral equation is an attack-specific observation. It is not evidence that all possible attacks fail. The live adapter verifies the supplied AES-4 master-key recovery and reports candidate filtering separately for other designs."
            : kind === "substitution"
              ? "Independent block encryption preserves block substitutions and repeated patterns. These experiments use no network stack, authentication tag or replay protection."
              : "A limited search measures selected statistical behavior. It does not exhaust the differential or linear properties of the cipher."}
        </p>
        <div className="not-tested">
          <span>Meet-in-the-middle key recovery</span>
          <span>Not run</span>
          <span>Related-key attack</span>
          <span>Not run</span>
        </div>
      </section>
    </>
  );
}
function BlockDemo({ row }) {
  if (!row) return null;
  return (
    <div className="block-demo">
      <h3>One observed substitution / AES-4 + ARX</h3>
      {[
        ["Source A / first block", row.source_first_block],
        ["Target B / first block", row.target_first_block],
        ["Delivered / substituted block", row.delivered_first_block],
      ].map(([l, h]) => (
        <div key={l}>
          <span>{l}</span>
          <code>{h.match(/../g).join(" ")}</code>
        </div>
      ))}
      <p>Modified message accepted. First block equals source A.</p>
    </div>
  );
}

function Results({ catalog, openSource }) {
  const [section, setSection] = useState("performance"),
    [size, setSize] = useState(256),
    [experiment, setExperiment] = useState("padded"),
    [metric, setMetric] = useState("median_ms"),
    [report, setReport] = useState(null),
    [error, setError] = useState("");
  const ds = catalog?.datasets || {};
  const speedKey =
    experiment === "padded"
      ? "figures/speed_results.csv"
      : "figures/direct_timing.csv";
  const rows = (ds[speedKey] || [])
    .filter((r) => Number(r.bytes) === size)
    .map((r) => ({
      ...r,
      median_ms: Number(r.median_ms),
      throughput_mib_s:
        Number(r.bytes) / 2 ** 20 / (Number(r.median_ms) / 1000),
    }));
  const hybridTiming = rows.find((r) => r.design === "AES-4 + ARX")?.median_ms;
  const referenceTiming = rows.find((r) => r.design === "AES-10")?.median_ms;
  const fiveTiming = rows.find((r) => r.design === "AES-5")?.median_ms;
  return (
    <>
      <div className="page-heading">
        <div>
          <h1>Research record</h1>
          <p>
            Measured performance, attack observations, and the source behind
            every result.
          </p>
        </div>
        <button
          className="text-button"
          onClick={() =>
            download("supplied-results.json", JSON.stringify(catalog, null, 2))
          }
        >
          Export measurements ↓
        </button>
      </div>
      <div className="tabs">
        <button
          className={section === "architecture" ? "active" : ""}
          onClick={() => setSection("architecture")}
        >
          Architecture & methods
        </button>
        <button
          className={section === "performance" ? "active" : ""}
          onClick={() => setSection("performance")}
        >
          Performance
        </button>
        <button
          className={section === "evidence" ? "active" : ""}
          onClick={() => setSection("evidence")}
        >
          Evidence index
        </button>
        <button
          className={section === "paper" ? "active" : ""}
          onClick={() => setSection("paper")}
        >
          Original study
        </button>
      </div>
      {section === "architecture" ? (
        <Architecture />
      ) : section === "performance" ? (
        <section className="experiment">
          <div className="experiment-heading">
            <h2>Same-core encryption comparison</h2>
            <button
              className="text-button"
              onClick={() => openSource(speedKey)}
            >
              View source CSV ↗
            </button>
          </div>
          <p className="explanation">
            Choose a message size and compare the recorded implementations.
            Green identifies the hybrid; the figures below are derived only from
            this selected experiment.
          </p>
          <DesignLegend />
          <div className="performance-summary">
            <div className="design-hybrid">
              <span>Hybrid encryption time</span>
              <strong>
                {hybridTiming ? number(hybridTiming) + " ms" : "Not measured"}
              </strong>
              <small>{size} bytes / selected experiment</small>
            </div>
            <div className="design-aes10">
              <span>Hybrid speedup vs AES-10</span>
              <strong>
                {referenceTiming && hybridTiming
                  ? number(referenceTiming / hybridTiming, 2) + "×"
                  : "Not measured"}
              </strong>
              <small>
                {referenceTiming
                  ? "Same payload and timing method"
                  : "AES-10 not in this experiment"}
              </small>
            </div>
            <div className="design-aes5">
              <span>Time saved vs AES-5</span>
              <strong>
                {fiveTiming && hybridTiming
                  ? number((1 - hybridTiming / fiveTiming) * 100, 1) + "%"
                  : "Not measured"}
              </strong>
              <small>Derived from the two measured times</small>
            </div>
          </div>
          <div className="performance-controls">
            <label>
              Graph metric
              <select
                value={metric}
                onChange={(e) => setMetric(e.target.value)}
              >
                <option value="median_ms">
                  Encryption time (lower is faster)
                </option>
                <option value="throughput_mib_s">
                  Throughput (higher is faster)
                </option>
              </select>
            </label>
            <label>
              Timing experiment
              <select
                value={experiment}
                onChange={(e) => setExperiment(e.target.value)}
              >
                <option value="padded">Padded messages · median of 7</option>
                <option value="raw">Raw blocks · median of 40</option>
              </select>
            </label>
            <label>
              Payload size
              <select
                value={size}
                onChange={(e) => setSize(Number(e.target.value))}
              >
                {[16, 64, 256, 768, 1536].map((n) => (
                  <option key={n} value={n}>
                    {n} bytes
                  </option>
                ))}
              </select>
            </label>
          </div>
          <Bars
            rows={rows}
            metric={metric}
            label={`${experiment === "padded" ? "Padded-message" : "Raw-block"} ${metric === "median_ms" ? "encryption time / lower is faster" : "throughput / higher is faster"}`}
            unit={metric === "median_ms" ? "ms" : "MiB/s"}
          />
          <DataTable rows={rows} />
          <p className="scope-note">
            {experiment === "padded"
              ? "Includes PKCS#7 padding, which adds a full block for aligned inputs. Source: evaluate_hybrid.py."
              : "Times unpadded block operations with matched inputs and randomized order. Source: compare_hybrid_five.py."}{" "}
            Recorded on the contributor’s machine; environment was not included.
            These are not live-network timings.
          </p>
          <div className="finding">
            <strong>
              A lightweight insertion, measured against an extra round.
            </strong>
            <p>
              Use AES-5 as the close alternative and AES-10 as the full-round
              reference. Compare measurements only within the same experiment.
            </p>
          </div>
        </section>
      ) : section === "evidence" ? (
        <section className="evidence">
          <SectionTitle>Implemented experiments</SectionTitle>
          <DataTable rows={ds["security_comparison_table.csv"] || []} />
          <details className="supporting-evidence">
            <summary>Matched diffusion / 1,500 input-key pairs</summary>
            <DataTable rows={ds["figures/direct_diffusion.csv"] || []} />
          </details>
          <details className="supporting-evidence">
            <summary>Internal integral balance / white-box diagnostic</summary>
            <DataTable rows={ds["figures/arx_internal_balance.csv"] || []} />
          </details>
          <div className="source-index">
            <h2>Exact source files</h2>
            {catalog?.files
              .filter((f) => f.endsWith(".py") || f === "README_HYBRID.txt")
              .map((f) => (
                <button key={f} onClick={() => openSource(f)}>
                  <span>{f}</span>
                  <span>Read ↗</span>
                </button>
              ))}
          </div>
          <p className="source-hash">
            Source archive SHA-256
            <br />
            <code>{catalog?.sha256}</code>
          </p>
        </section>
      ) : (
        <section className="paper">
          <h2>Packet-size-adaptive round allocation</h2>
          <p className="paper-authors">
            Ayati Rauthan · Ireshi Rawat
            <br />
            Information Security Lab, MIT Manipal
          </p>
          <p>
            The original AdaptAES study chooses four, six, eight or ten AES
            rounds using transport payload length. HIKARI-2021 captures provide
            input lengths; deterministic synthetic bytes provide the plaintext.
          </p>
          <div className="paper-stats">
            <div>
              <strong>6</strong>
              <span>captures</span>
            </div>
            <div>
              <strong>2,355,051</strong>
              <span>payload-bearing packets</span>
            </div>
            <div>
              <strong>300</strong>
              <span>reported timing samples</span>
            </div>
          </div>
          <DataTable
            rows={[
              { payload: "1–128 B", rounds: 4, share: "21.33%" },
              { payload: "129–512 B", rounds: 6, share: "9.05%" },
              { payload: "513–1024 B", rounds: 8, share: "3.98%" },
              { payload: ">1024 B", rounds: 10, share: "65.64%" },
            ]}
          />
          <h3>The hybrid is an extension</h3>
          <p>
            The report predates the ARX prototype. Its original performance and
            statistical findings are kept separate from the supplied hybrid
            experiments. AdaptAES–ARX in the workbench is a new adapter: only
            the four-round payload category receives the supplied ARX cipher.
          </p>
          <p className="scope-note">
            The original report records a 61.11% small-payload encryption-time
            reduction and 0.88% overall reduction. These are historical report
            values, not hybrid or current live measurements; the older raw
            timing files need reconciliation.
          </p>
          <button
            className="secondary"
            onClick={async () => {
              try {
                setReport((await api("paper")).content);
              } catch (e) {
                setError(e.message);
              }
            }}
          >
            Read repository report
          </button>
          <ErrorLine error={error} />
          {report && (
            <details open>
              <summary>Original repository report / Markdown</summary>
              <pre className="report-text">{report}</pre>
            </details>
          )}
        </section>
      )}
    </>
  );
}

function App() {
  const [page, setPage] = useState(location.hash.slice(1) || "home"),
    [catalog, setCatalog] = useState(null),
    [online, setOnline] = useState(null),
    [source, setSource] = useState(null),
    [sourceError, setSourceError] = useState("");
  const dialog = useRef();
  useEffect(() => {
    const f = () => setPage(location.hash.slice(1) || "home");
    window.addEventListener("hashchange", f);
    api("config")
      .then(() => setOnline(true))
      .catch(() => setOnline(false));
    api("results")
      .then(setCatalog)
      .catch((e) => setSourceError(e.message));
    return () => window.removeEventListener("hashchange", f);
  }, []);
  useEffect(() => {
    if (source && dialog.current && !dialog.current.open)
      dialog.current.showModal();
  }, [source]);
  async function openSource(file) {
    try {
      setSource(await api("source?file=" + encodeURIComponent(file)));
    } catch (e) {
      setSourceError(e.message);
    }
  }
  function go(p) {
    location.hash = p;
    window.scrollTo({ top: 0, behavior: "instant" });
  }
  return (
    <div className="app-shell">
      <header>
        <a className="wordmark" href="#home" aria-label="AdaptAES home">
          <svg width="29" height="29" viewBox="0 0 32 32" aria-hidden="true">
            <path d="M5 26V12L16 4l11 8v14M5 19h22M11 26V11M21 26V11" />
          </svg>
          AdaptAES<span className="wordmark-version">/ ARX</span>
        </a>
        <nav aria-label="Main navigation">
          {[
            ["home", "Home"],
            ["encrypt", "Workbench"],
            ["analyze", "Analysis"],
            ["results", "Research"],
          ].map(([id, label]) => (
            <a
              key={id}
              className={page === id ? "current" : ""}
              aria-current={page === id ? "page" : undefined}
              href={"#" + id}
            >
              {label}
            </a>
          ))}
        </nav>
        <span className="backend-status">
          <span
            className={online ? "connection-dot connected" : "connection-dot"}
          />
          {online === null
            ? "Connecting"
            : online
              ? "Python connected"
              : "Backend unavailable"}
        </span>
      </header>
      <main>
        <ErrorLine error={sourceError} />
        {page === "home" ? (
          <Home catalog={catalog} go={go} />
        ) : page === "analyze" ? (
          <Analysis catalog={catalog} openSource={openSource} />
        ) : page === "results" ? (
          <Results catalog={catalog} openSource={openSource} />
        ) : (
          <Workspace openSource={openSource} onAnalyze={() => go("analyze")} />
        )}
      </main>
      <footer>
        <span>
          AdaptAES{" "}
          <span className="muted">/ AES + Addition, Rotation, XOR</span>
        </span>
        <button
          className="text-button"
          onClick={() => openSource("README_HYBRID.txt")}
        >
          Source & methodology ↗
        </button>
        <span className="footer-note">
          Research prototype. Run summaries stay in this tab.
        </span>
      </footer>
      <dialog
        ref={dialog}
        aria-labelledby="source-title"
        onCancel={() => setSource(null)}
      >
        <div className="dialog-header">
          <div>
            <h2 id="source-title">{source?.file}</h2>
            <span>Exact supplied source</span>
          </div>
          <button
            className="secondary"
            onClick={() => {
              dialog.current.close();
              setSource(null);
            }}
          >
            Close ×
          </button>
        </div>
        <pre className="source-code">{source?.content}</pre>
        <div className="dialog-footer">
          <small>SHA-256 / {source?.sha256}</small>
          <button
            className="text-button"
            onClick={() => download(source.file, source.content, "text/plain")}
          >
            Download source ↓
          </button>
        </div>
      </dialog>
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
