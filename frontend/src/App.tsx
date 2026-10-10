import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { fetchControls, fetchMarkdownReport, fetchScan, runAudit } from "./api/client";
import { PAGES_BUILD } from "./browserMode";
import ConnectionForm, { EMPTY_DRAFT, draftToRequest, type ConnectionDraft } from "./components/ConnectionForm";
import { emptyScan, LOCAL_CONTROLS } from "./emptyScan";
import { buildMarkdownReport } from "./reportMarkdown";
import { JSON_FILE_MAX_BYTES, parseScanJson, type ScanParseError } from "./scanSchema";
import CoveragePanel from "./components/CoveragePanel";
import ControlsTable, { buildControlStats } from "./components/ControlsTable";
import CriticalitySummary from "./components/CriticalitySummary";
import FindingCard from "./components/FindingCard";
import Icon from "./components/Icon";
import MobileNav from "./components/MobileNav";
import RiskMatrixGrid from "./components/RiskMatrix";
import SeverityCards from "./components/SeverityCards";
import Sidebar, { type PageId, type SectionId, type View } from "./components/Sidebar";
import Splash from "./components/Splash";
import Toast from "./components/Toast";
import TopBar from "./components/TopBar";
import HelpPage from "./pages/HelpPage";
import ProfilePage from "./pages/ProfilePage";
import SettingsPage from "./pages/SettingsPage";
import SupportPage from "./pages/SupportPage";
import { useSettings } from "./settings/SettingsContext";
import type { TKey } from "./settings/i18n";
import { alertMatchesCoverage } from "./coverageFilter";
import { appendixMarkdown, type TreatStatus } from "./treatment";
import { buildEcosistema } from "./ecosistema";
import { VERSION } from "./pages/SupportPage";
import { buildStudioEvidencia } from "./studioEvidencia";
import { RISK_ORDER, type AuditRequest, type GRCAlert, type RiskLevel, type ScanResponse } from "./types";

const SECTION_LABEL: Record<SectionId, TKey> = {
  panel: "nav.panel",
  matriz: "nav.matrix",
  hallazgos: "nav.findings",
  cobertura: "nav.coverage",
  controles: "nav.controls",
  informe: "nav.report",
};
const PAGE_LABEL: Record<PageId, TKey> = {
  ajustes: "nav.settings",
  ayuda: "nav.help",
  soporte: "nav.support",
  perfil: "nav.profile",
};
const SECTION_ORDER: SectionId[] = ["panel", "matriz", "hallazgos", "cobertura", "controles", "informe"];

function formatDate(iso: string, locale: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(locale, { dateStyle: "medium", timeStyle: "short" });
}

// Best-effort AD domain for the sidebar context card (e.g. "APP01$@dominio.local").
function detectDomain(alerts: GRCAlert[]): string | null {
  for (const a of alerts) {
    const m = a.finding.target.match(/@\s*([\w-]+(?:\.[\w-]+)+)/);
    if (m) return m[1];
  }
  return null;
}

function scrollToSection(target: SectionId) {
  if (target === "panel") window.scrollTo({ top: 0, behavior: "smooth" });
  else document.getElementById(target)?.scrollIntoView({ behavior: "smooth", block: "start" });
}

export default function App() {
  const { t, locale } = useSettings();
  const [data, setData] = useState<ScanResponse | null>(PAGES_BUILD ? emptyScan() : null);
  const [catalog, setCatalog] = useState<Record<string, string> | null>(
    PAGES_BUILD ? LOCAL_CONTROLS.controls : null,
  );
  const [loading, setLoading] = useState(!PAGES_BUILD);
  const [error, setError] = useState<string | null>(null);
  const [riskFilter, setRiskFilter] = useState<RiskLevel | null>(null);
  const [controlFilter, setControlFilter] = useState<string | null>(null);
  const [moduleFilter, setModuleFilter] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [view, setView] = useState<View>("dashboard");
  const [section, setSection] = useState<SectionId>("panel");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [initialSettled, setInitialSettled] = useState(false);
  const [splashDone, setSplashDone] = useState(false);
  const [draft, setDraft] = useState<ConnectionDraft>(EMPTY_DRAFT);
  const [browserMode, setBrowserMode] = useState(PAGES_BUILD);
  const [jsonFileName, setJsonFileName] = useState<string | null>(null);
  const [jsonError, setJsonError] = useState<string | null>(null);
  const sessionRef = useRef<AuditRequest | null>(null);
  const firstLoad = useRef(true);
  const pendingScroll = useRef<SectionId | null>(null);

  // Keep the latest translator reachable from stable callbacks.
  const tRef = useRef(t);
  tRef.current = t;

  const notify = useCallback((msg: string) => setToast(msg), []);

  useEffect(() => {
    document.body.classList.toggle("drawer-open", drawerOpen);
  }, [drawerOpen]);

  const jsonErrorText = useCallback((code: ScanParseError, detail?: string) => {
    const keys: Record<ScanParseError, TKey> = {
      invalid_json: "json.invalid_json",
      not_object: "json.not_object",
      sample: "json.sample",
      credentials: "json.credentials",
      schema: "json.schema",
      too_large: "json.too_large",
    };
    const base = tRef.current(keys[code]);
    return detail ? `${base} (${detail})` : base;
  }, []);

  const applyEmpty = useCallback(() => {
    setData(emptyScan());
    setCatalog((cur) => cur ?? LOCAL_CONTROLS.controls);
    setPreview(null);
    setJsonFileName(null);
    setJsonError(null);
    sessionRef.current = null;
  }, []);

  const loadEmpty = useCallback(async () => {
    setLoading(true);
    setError(null);
    if (PAGES_BUILD) {
      applyEmpty();
      setBrowserMode(true);
      firstLoad.current = false;
      setLoading(false);
      setInitialSettled(true);
      return;
    }
    try {
      const res = await fetchScan();
      setData(res);
      setPreview(null);
      setBrowserMode(false);
      setJsonFileName(null);
      setJsonError(null);
    } catch {
      applyEmpty();
      setBrowserMode(true);
    } finally {
      firstLoad.current = false;
      setLoading(false);
      setInitialSettled(true);
    }
  }, [applyEmpty]);

  const auditWith = useCallback(
    async (req: AuditRequest) => {
      setLoading(true);
      setError(null);
      try {
        const res = await runAudit(req);
        sessionRef.current = req;
        setData(res);
        setPreview(null);
        notify(tRef.current("toast.rescanned", { n: res.total_alerts }));
      } catch (e) {
        setError(e instanceof Error ? e.message : tRef.current("common.unknownError"));
      } finally {
        firstLoad.current = false;
        setLoading(false);
        setInitialSettled(true);
      }
    },
    [notify],
  );

  const submitAudit = useCallback(() => {
    auditWith(draftToRequest(draft));
  }, [auditWith, draft]);

  const clearSession = useCallback(() => {
    sessionRef.current = null;
    setDraft(EMPTY_DRAFT);
    loadEmpty();
  }, [loadEmpty]);

  const rescan = useCallback(() => {
    const req = sessionRef.current;
    if (req) auditWith(req);
    else loadEmpty();
  }, [auditWith, loadEmpty]);

  useEffect(() => {
    loadEmpty();
    if (PAGES_BUILD) {
      setCatalog(LOCAL_CONTROLS.controls);
      return;
    }
    fetchControls()
      .then((c) => setCatalog(c.controls))
      .catch(() => setCatalog(LOCAL_CONTROLS.controls));
  }, [loadEmpty]);

  const openJsonFile = useCallback(
    (file: File) => {
      if (file.size > JSON_FILE_MAX_BYTES) {
        setJsonError(jsonErrorText("too_large"));
        return;
      }
      const reader = new FileReader();
      reader.onload = () => {
        const text = typeof reader.result === "string" ? reader.result : "";
        const parsed = parseScanJson(text);
        if (!parsed.ok) {
          setJsonError(jsonErrorText(parsed.error, parsed.detail));
          return;
        }
        setData(parsed.data);
        setCatalog((cur) => cur ?? LOCAL_CONTROLS.controls);
        setPreview(null);
        setJsonFileName(file.name);
        setJsonError(null);
        setError(null);
        notify(tRef.current("toast.jsonOpened", { f: file.name }));
      };
      reader.onerror = () => setJsonError(jsonErrorText("invalid_json"));
      reader.readAsText(file);
    },
    [jsonErrorText, notify],
  );

  const clearJsonFile = useCallback(() => {
    applyEmpty();
    setBrowserMode(true);
  }, [applyEmpty]);

  // Track the section in view to highlight the nav item and breadcrumb (dashboard only).
  useEffect(() => {
    if (view !== "dashboard") return;
    const onScroll = () => {
      let cur: SectionId = "panel";
      for (const id of SECTION_ORDER) {
        const el = document.getElementById(id);
        if (el && el.getBoundingClientRect().top <= 120) cur = id;
      }
      if (window.scrollY > 0 && window.innerHeight + window.scrollY >= document.body.scrollHeight - 4) {
        cur = "informe";
      }
      setSection(cur);
    };
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, [view]);

  // After returning to the dashboard from a page, scroll once the sections exist.
  useEffect(() => {
    if (view !== "dashboard" || !pendingScroll.current) return;
    const target = pendingScroll.current;
    pendingScroll.current = null;
    requestAnimationFrame(() => scrollToSection(target));
  }, [view]);

  const sortedAlerts = useMemo<GRCAlert[]>(() => {
    if (!data) return [];
    const rank = (r: RiskLevel) => RISK_ORDER.indexOf(r);
    return [...data.alerts].sort((a, b) => rank(a.risk) - rank(b.risk));
  }, [data]);

  const visibleAlerts = useMemo(
    () =>
      sortedAlerts.filter(
        (a) =>
          (!riskFilter || a.risk === riskFilter) &&
          (!controlFilter || a.ens_controls.some((c) => c.id === controlFilter)) &&
          alertMatchesCoverage(a, moduleFilter),
      ),
    [sortedAlerts, riskFilter, controlFilter, moduleFilter],
  );

  const controlStats = useMemo(
    () => buildControlStats(data?.alerts ?? [], catalog),
    [data, catalog],
  );
  const affectedControls = controlStats.filter((s) => s.alerts > 0).length;
  const primaryControls = controlStats.filter((s) => s.primary > 0).length;

  const navigate = (target: SectionId, risk?: RiskLevel | null) => {
    if (risk !== undefined) {
      setRiskFilter(risk);
      setControlFilter(null);
      setModuleFilter(null);
    }
    setSection(target);
    setDrawerOpen(false);
    if (view !== "dashboard") {
      pendingScroll.current = target;
      setView("dashboard");
    } else {
      scrollToSection(target);
    }
  };

  const openPage = (page: PageId) => {
    setView(page);
    setDrawerOpen(false);
    window.scrollTo({ top: 0 });
    // Move focus to the new page heading for keyboard and screen-reader users.
    requestAnimationFrame(() => document.getElementById("page-title")?.focus({ preventScroll: true }));
  };

  const selectControl = (id: string | null) => {
    setControlFilter(id);
    if (id) {
      setModuleFilter(null);
      navigate("hallazgos");
    }
  };

  const selectCoverage = (id: string) => {
    setModuleFilter((cur) => (cur === id ? null : id));
    setRiskFilter(null);
    setControlFilter(null);
    navigate("hallazgos");
  };

  const saveMarkdown = (md: string) => {
    const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "informe-ens-ad-auditor.md";
    a.click();
    URL.revokeObjectURL(url);
    notify(t("toast.downloaded", { f: "informe-ens-ad-auditor.md" }));
  };

  const downloadReport = async () => {
    setDownloading(true);
    try {
      if (browserMode) {
        saveMarkdown(buildMarkdownReport(data ?? emptyScan()));
        return;
      }
      const md = await fetchMarkdownReport(sessionRef.current ?? undefined);
      saveMarkdown(md);
    } catch (e) {
      setError(e instanceof Error ? e.message : t("err.report"));
    } finally {
      setDownloading(false);
    }
  };

  const downloadAppendix = () => {
    const labels: Record<TreatStatus, string> = {
      abierto: t("treat.open"),
      en_curso: t("treat.progress"),
      aceptado: t("treat.accepted"),
      corregido: t("treat.fixed"),
    };
    const md = appendixMarkdown(data?.alerts ?? [], labels, {
      title: t("treat.title"),
      owner: t("treat.owner"),
      status: t("treat.status"),
      due: t("treat.due"),
      empty: t("treat.empty"),
      note: t("treat.note"),
    });
    const blob = new Blob([md], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "anexo-tratamiento.md";
    a.click();
    URL.revokeObjectURL(url);
    notify(t("toast.downloaded", { f: "anexo-tratamiento.md" }));
  };

  const downloadStudio = () => {
    const live = !!data?.scanned;
    const payload = buildStudioEvidencia(data?.alerts ?? [], live ? data?.domain ?? null : null);
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "evidencia-studio-ens-ad-auditor.json";
    a.click();
    URL.revokeObjectURL(url);
    notify(t("toast.downloaded", { f: "evidencia-studio-ens-ad-auditor.json" }));
  };

  const downloadEcosistema = () => {
    const live = !!data?.scanned;
    const payload = buildEcosistema(data?.alerts ?? [], live ? data?.domain ?? null : null, VERSION);
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "ecosistema-ens-ad-auditor.json";
    a.click();
    URL.revokeObjectURL(url);
    notify(t("toast.downloaded", { f: "ecosistema-ens-ad-auditor.json" }));
  };

  const loadPreview = async () => {
    setPreviewLoading(true);
    try {
      if (browserMode) {
        setPreview(buildMarkdownReport(data ?? emptyScan()));
        return;
      }
      setPreview(await fetchMarkdownReport(sessionRef.current ?? undefined));
    } catch (e) {
      setError(e instanceof Error ? e.message : t("err.report"));
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleSplashDone = useCallback(() => setSplashDone(true), []);

  const counts = data?.counts_by_risk ?? { Critico: 0, Alto: 0, Medio: 0, Bajo: 0 };
  const total = data?.total_alerts ?? 0;
  const scanned = !!data?.scanned;
  const domain =
    (scanned && data?.domain) ||
    (data && detectDomain(data.alerts)) ||
    t("ctx.domainFallback");
  const generatedAt = data ? formatDate(data.generated_at, locale) : null;
  const crumb = view === "dashboard" ? t(SECTION_LABEL[section]) : t(PAGE_LABEL[view]);

  return (
    <>
      {!splashDone && <Splash ready={initialSettled} onDone={handleSplashDone} />}

      <div className="app" aria-hidden={!splashDone || undefined}>
        <Sidebar
          view={view}
          section={section}
          riskFilter={riskFilter}
          total={total}
          critical={counts.Critico}
          controlsAffected={affectedControls}
          domain={domain}
          hasData={scanned}
          onNavigate={navigate}
          onOpenPage={openPage}
        />
        <div className="scrim" onClick={() => setDrawerOpen(false)} aria-hidden="true" />

        <div className="main">
          <TopBar
            current={crumb}
            showActions={view === "dashboard"}
            loading={loading}
            downloading={downloading}
            canDownload={!!data}
            onRescan={rescan}
            onDownload={downloadReport}
            onOpenDrawer={() => setDrawerOpen(true)}
            onOpenHelp={() => openPage("ayuda")}
          />

          <main className="view" key={view}>
            {view === "ajustes" && <SettingsPage notify={notify} />}
            {view === "ayuda" && <HelpPage onGo={(s) => navigate(s)} />}
            {view === "soporte" && (
              <SupportPage
                notify={notify}
                scanSummary={data ? t("sup.ctxSummary", { n: total, date: generatedAt ?? "" }) : null}
              />
            )}
            {view === "perfil" && (
              <ProfilePage
                data={data}
                affectedControls={affectedControls}
                totalControls={catalog ? Object.keys(catalog).length : null}
                domain={domain}
                generatedAt={generatedAt}
                onNavigate={navigate}
                onOpenPage={openPage}
              />
            )}

            {view === "dashboard" && (
              <>
                <div className="page-head" id="panel">
                  <div className="ph-text">
                    <h1>{t("dash.title")}</h1>
                    <p className="lead">
                      {t("dash.lead")}
                      {generatedAt && (
                        <>
                          {" "}
                          <span className="muted">{t("dash.generated", { date: generatedAt })}</span>
                        </>
                      )}
                    </p>
                  </div>
                </div>

                <ConnectionForm
                  draft={draft}
                  onChange={setDraft}
                  connectedDomain={scanned && !browserMode ? data?.domain ?? null : null}
                  connectedUser={scanned && !browserMode ? sessionRef.current?.username ?? null : null}
                  loading={loading}
                  onSubmit={submitAudit}
                  onClear={clearSession}
                  browserMode={browserMode}
                  jsonFileName={jsonFileName}
                  jsonError={jsonError}
                  onOpenJson={openJsonFile}
                  onClearJson={clearJsonFile}
                />

                {error && (
                  <div className="alert crit" role="alert">
                    <Icon name="alert" />
                    <span className="spacer">{error}</span>
                    <button type="button" className="btn sm" onClick={rescan}>
                      <Icon name="refresh" size={15} />
                      {t("common.retry")}
                    </button>
                  </div>
                )}

                {!!data?.errors?.length && (
                  <div className="alert warn" role="status">
                    <Icon name="info" />
                    <div>
                      <b>{t("conn.errors")}</b>
                      <ul className="err-list">
                        {data.errors.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}

                {loading && !data && (
                  <div className="card">
                    <div className="empty-state">
                      <Icon name="refresh" size={28} className="spin accent" />
                      <h3>{t("loading.title")}</h3>
                      <p>{t("loading.text")}</p>
                    </div>
                  </div>
                )}

                {data && (
                  <>
                    <div className="kpi-grid">
                      <div className="kpi">
                        <span className="kpi-l">
                          <Icon name="target" size={16} />
                          {t("kpi.total")}
                        </span>
                        <span className="kpi-v num">{data.total_alerts}</span>
                        <span className="kpi-s">{t("kpi.totalSub")}</span>
                      </div>
                      <div className={`kpi${counts.Critico > 0 ? " alert" : ""}`}>
                        <span className="kpi-l">
                          <Icon name="alert" size={16} />
                          {t("kpi.critical")}
                        </span>
                        <span className="kpi-v num">
                          {counts.Critico}
                          <small>{t("kpi.of", { n: total })}</small>
                        </span>
                        <span className="kpi-s">{t("kpi.criticalSub")}</span>
                      </div>
                      <div className="kpi">
                        <span className="kpi-l">
                          <Icon name="activity" size={16} />
                          {t("kpi.high")}
                        </span>
                        <span className="kpi-v num">
                          {counts.Alto}
                          <small>{t("kpi.of", { n: total })}</small>
                        </span>
                        <span className="kpi-s">{t("kpi.highSub", { m: counts.Medio, b: counts.Bajo })}</span>
                      </div>
                      <div className="kpi">
                        <span className="kpi-l">
                          <Icon name="shieldCheck" size={16} />
                          {t("kpi.controls")}
                        </span>
                        <span className="kpi-v num">
                          {affectedControls}
                          {catalog && <small>/{Object.keys(catalog).length}</small>}
                        </span>
                        <span className="kpi-s">{t("kpi.controlsSub", { n: primaryControls })}</span>
                      </div>
                    </div>

                    {data.scanned && <CriticalitySummary summary={data.summary} scanned={data.scanned} />}

                    <SeverityCards
                      counts={counts}
                      total={total}
                      active={riskFilter}
                      onSelect={(r) => setRiskFilter(r)}
                    />

                    <RiskMatrixGrid matrix={data.matrix} scanned={data.scanned} />

                    <section className="block" id="hallazgos" aria-labelledby="h-hallazgos">
                      <div className="block-head">
                        <h2 id="h-hallazgos">{t("findings.title")}</h2>
                        <span className="muted small">{t("findings.hint")}</span>
                      </div>
                      <div className="toolbar">
                        <span className="small">
                          <b className="num">{visibleAlerts.length}</b>
                          <span className="muted"> {t("findings.count", { n: total })}</span>
                        </span>
                        {riskFilter && (
                          <button
                            type="button"
                            className="btn sm ghost"
                            onClick={() => setRiskFilter(null)}
                            title={t("findings.clearRisk")}
                          >
                            {t("findings.riskChip", { r: t(`risk.${riskFilter}`) })}
                            <Icon name="x" size={14} />
                          </button>
                        )}
                        {controlFilter && (
                          <button
                            type="button"
                            className="btn sm ghost"
                            onClick={() => setControlFilter(null)}
                            title={t("findings.clearControl")}
                          >
                            {t("findings.controlChip", { c: controlFilter })}
                            <Icon name="x" size={14} />
                          </button>
                        )}
                        {moduleFilter && (
                          <button
                            type="button"
                            className="btn sm ghost"
                            onClick={() => setModuleFilter(null)}
                            title={t("findings.clearModule")}
                          >
                            {t("findings.moduleChip", {
                              a: data?.coverage?.find((row) => row.id === moduleFilter)?.area ?? moduleFilter,
                            })}
                            <Icon name="x" size={14} />
                          </button>
                        )}
                      </div>
                      {visibleAlerts.length > 0 ? (
                        <div className="findings">
                          {visibleAlerts.map((a) => (
                            <FindingCard
                              key={a.rule_id + a.finding.target}
                              alert={a}
                              onControlSelect={(id) => selectControl(id)}
                            />
                          ))}
                        </div>
                      ) : (
                        <div className="card">
                          <div className="empty-state">
                            <Icon name="shieldCheck" size={28} className="accent" />
                            <h3>
                              {t(
                                riskFilter || controlFilter || moduleFilter
                                  ? "findings.emptyTitle"
                                  : scanned
                                    ? "findings.cleanTitle"
                                    : "findings.noScanTitle",
                              )}
                            </h3>
                            <p>
                              {t(
                                riskFilter || controlFilter || moduleFilter
                                  ? "findings.emptyText"
                                  : scanned
                                    ? "findings.cleanText"
                                    : "findings.noScanText",
                              )}
                            </p>
                            {(riskFilter || controlFilter || moduleFilter) && (
                              <button
                                type="button"
                                className="btn sm"
                                onClick={() => {
                                  setRiskFilter(null);
                                  setControlFilter(null);
                                  setModuleFilter(null);
                                }}
                              >
                                {t("findings.clearFilters")}
                              </button>
                            )}
                          </div>
                        </div>
                      )}
                    </section>

                    <CoveragePanel
                      checks={data.coverage ?? []}
                      active={moduleFilter}
                      onFilter={selectCoverage}
                    />

                    <section className="block" id="controles" aria-labelledby="h-controles">
                      <div className="block-head">
                        <h2 id="h-controles">{t("controls.title")}</h2>
                        <span className="muted small">{t("controls.hint")}</span>
                      </div>
                      <ControlsTable
                        stats={controlStats}
                        totalAlerts={total}
                        selected={controlFilter}
                        onSelect={selectControl}
                      />
                    </section>

                    <section className="block" id="informe" aria-labelledby="h-informe">
                      <div className="block-head">
                        <h2 id="h-informe">{t("report.title")}</h2>
                      </div>
                      <div className="report-grid">
                        <div className="card stack">
                          <span className="ex-ic">
                            <Icon name="fileCheck" size={20} />
                          </span>
                          <h3>{t("report.cardTitle")}</h3>
                          <p className="muted small">{t("report.cardText")}</p>
                          <p className="muted small">{t("report.studioText")}</p>
                          <p className="muted small">{t("report.ecoText")}</p>
                          <div className="row">
                            <button
                              type="button"
                              className="btn primary"
                              onClick={downloadReport}
                              disabled={downloading}
                            >
                              <Icon name="download" size={16} />
                              {downloading ? t("report.generating") : t("report.download")}
                            </button>
                            <button type="button" className="btn" onClick={downloadAppendix}>
                              <Icon name="fileCheck" size={16} />
                              {t("treat.download")}
                            </button>
                            <button type="button" className="btn" onClick={downloadStudio}>
                              <Icon name="download" size={16} />
                              {t("report.studio")}
                            </button>
                            <button type="button" className="btn" onClick={downloadEcosistema}>
                              <Icon name="download" size={16} />
                              {t("report.eco")}
                            </button>
                            <button
                              type="button"
                              className="btn"
                              onClick={loadPreview}
                              disabled={previewLoading}
                            >
                              <Icon name="eye" size={16} />
                              {previewLoading
                                ? t("report.loading")
                                : preview
                                  ? t("report.refreshPreview")
                                  : t("report.preview")}
                            </button>
                          </div>
                        </div>
                        <div className="card">
                          <div className="card-head">
                            <h3>{t("report.preview")}</h3>
                            <span className="chip">informe-ens-ad-auditor.md</span>
                          </div>
                          {preview ? (
                            <pre className="code md-preview">{preview}</pre>
                          ) : (
                            <div className="empty-state">
                              <Icon name="book" size={26} className="muted" />
                              <p>{t(browserMode ? "report.previewEmptyLocal" : "report.previewEmpty")}</p>
                            </div>
                          )}
                        </div>
                      </div>
                    </section>
                  </>
                )}
              </>
            )}

            <p className="legal">{t("legal")}</p>
          </main>
          <MobileNav
            view={view}
            section={section}
            riskFilter={riskFilter}
            total={total}
            critical={counts.Critico}
            onNavigate={navigate}
            onOpenPage={openPage}
          />
        </div>

        {toast && <Toast message={toast} onGone={() => setToast(null)} />}
      </div>
    </>
  );
}
