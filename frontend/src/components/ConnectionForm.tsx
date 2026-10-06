import { useRef, useState, type FormEvent } from "react";
import Icon from "./Icon";
import { useSettings } from "../settings/SettingsContext";
import type { AuditRequest } from "../types";

const INSTALL_URL = "https://github.com/heindall92/ens_ad-auditor#arranque-r%C3%A1pido";

export interface ConnectionDraft {
  domain: string;
  dcHost: string;
  username: string;
  secret: string;
  secretKind: "password" | "nthash";
  authorized: boolean;
}

export const EMPTY_DRAFT: ConnectionDraft = {
  domain: "",
  dcHost: "",
  username: "",
  secret: "",
  secretKind: "password",
  authorized: false,
};

export function draftToRequest(draft: ConnectionDraft): AuditRequest {
  const req: AuditRequest = {
    domain: draft.domain.trim(),
    dc_host: draft.dcHost.trim(),
    username: draft.username.trim(),
    authorized: draft.authorized,
  };
  if (draft.secretKind === "nthash") req.nthash = draft.secret.trim();
  else req.password = draft.secret;
  return req;
}

interface Props {
  draft: ConnectionDraft;
  onChange: (next: ConnectionDraft) => void;
  connectedDomain: string | null;
  connectedUser: string | null;
  loading: boolean;
  onSubmit: () => void;
  onClear: () => void;
  browserMode?: boolean;
  jsonFileName?: string | null;
  jsonError?: string | null;
  onOpenJson?: (file: File) => void;
  onClearJson?: () => void;
}

export default function ConnectionForm({
  draft,
  onChange,
  connectedDomain,
  connectedUser,
  loading,
  onSubmit,
  onClear,
  browserMode = false,
  jsonFileName = null,
  jsonError = null,
  onOpenJson,
  onClearJson,
}: Props) {
  const { t } = useSettings();
  const [showForm, setShowForm] = useState(!connectedDomain);
  const fileRef = useRef<HTMLInputElement>(null);
  const set = (patch: Partial<ConnectionDraft>) => onChange({ ...draft, ...patch });

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (browserMode) return;
    onSubmit();
  };

  const pickJson = () => fileRef.current?.click();
  const onFile = (file: File | undefined) => {
    if (file && onOpenJson) onOpenJson(file);
    if (fileRef.current) fileRef.current.value = "";
  };

  if (browserMode) {
    return (
      <section className="card connect-card" aria-labelledby="conn-h">
        <div className="card-head">
          <h3 id="conn-h">{t("conn.title")}</h3>
          <span className="badge neutral">
            <span className="dot" />
            {t("conn.browserBadge")}
          </span>
        </div>
        <p className="muted small">{t("conn.browserLead")}</p>
        <div className="alert warn connect-legal" role="note">
          <Icon name="info" size={18} />
          <div>
            <b>{t("conn.browserEngineBold")}</b>
            <p>
              {t("conn.browserEngine")}{" "}
              <a href={INSTALL_URL} target="_blank" rel="noopener noreferrer">
                {t("conn.browserInstall")}
                <Icon name="external" size={13} />
              </a>
            </p>
          </div>
        </div>
        {jsonFileName && (
          <p className="muted small">
            <code>{jsonFileName}</code>
            {" · "}
            {t("conn.jsonLoaded")}
          </p>
        )}
        {jsonError && (
          <div className="alert crit" role="alert">
            <Icon name="alert" size={18} />
            <span className="spacer">{jsonError}</span>
          </div>
        )}
        <input
          ref={fileRef}
          className="sr-only"
          type="file"
          accept="application/json,.json"
          aria-label={t("conn.openJson")}
          onChange={(e) => onFile(e.target.files?.[0])}
        />
        <div className="form-foot">
          <span className="muted small">{t("conn.browserNosave")}</span>
          <div className="row">
            <button type="button" className="btn" onClick={pickJson}>
              <Icon name="folderOpen" size={15} />
              {t("conn.openJson")}
            </button>
            {jsonFileName && onClearJson && (
              <button type="button" className="btn ghost" onClick={onClearJson}>
                <Icon name="x" size={15} />
                {t("conn.jsonClear")}
              </button>
            )}
            <button type="button" className="btn primary" disabled>
              <Icon name="lock" size={15} />
              {t("conn.submit")}
            </button>
          </div>
        </div>
      </section>
    );
  }

  if (connectedDomain && !showForm) {
    return (
      <section className="card connect-card" aria-labelledby="conn-h">
        <div className="card-head">
          <h3 id="conn-h">{t("conn.title")}</h3>
          <span className="badge ok">
            <span className="dot" />
            {t("conn.connected")}
          </span>
        </div>
        <p className="muted small">
          <code>{connectedDomain}</code>
          {connectedUser ? (
            <>
              {" · "}
              <code>{connectedUser}</code>
            </>
          ) : null}
        </p>
        <div className="row">
          <button type="button" className="btn sm" onClick={() => setShowForm(true)}>
            <Icon name="key" size={15} />
            {t("conn.change")}
          </button>
          <button type="button" className="btn sm ghost" onClick={onClear}>
            <Icon name="x" size={15} />
            {t("conn.clear")}
          </button>
        </div>
      </section>
    );
  }

  return (
    <form className="card connect-card" onSubmit={submit} autoComplete="off" aria-labelledby="conn-h">
      <div className="card-head">
        <h3 id="conn-h">{t("conn.title")}</h3>
      </div>
      <p className="muted small">{t("conn.lead")}</p>

      <div className="alert warn connect-legal" role="note">
        <Icon name="alert" size={18} />
        <div>
          <b>{t("conn.legalBold")}</b>
          <p>{t("conn.legalText")}</p>
        </div>
      </div>

      <div className="form-grid">
        <label className="fld">
          {t("conn.domain")}
          <input
            type="text"
            name="ad-domain"
            autoComplete="off"
            spellCheck={false}
            value={draft.domain}
            placeholder={t("conn.domainPh")}
            onChange={(e) => set({ domain: e.target.value })}
            required
          />
        </label>
        <label className="fld">
          {t("conn.dc")}
          <input
            type="text"
            name="ad-dc"
            autoComplete="off"
            spellCheck={false}
            value={draft.dcHost}
            placeholder={t("conn.dcPh")}
            onChange={(e) => set({ dcHost: e.target.value })}
            required
          />
        </label>
        <label className="fld">
          {t("conn.user")}
          <input
            type="text"
            name="ad-user"
            autoComplete="username"
            spellCheck={false}
            value={draft.username}
            placeholder={t("conn.userPh")}
            onChange={(e) => set({ username: e.target.value })}
            required
          />
        </label>
        <div className="fld">
          {t("conn.secret")}
          <div className="seg" role="group" aria-label={t("conn.secret")}>
            <button
              type="button"
              aria-pressed={draft.secretKind === "password"}
              onClick={() => set({ secretKind: "password", secret: "" })}
            >
              {t("conn.password")}
            </button>
            <button
              type="button"
              aria-pressed={draft.secretKind === "nthash"}
              onClick={() => set({ secretKind: "nthash", secret: "" })}
            >
              {t("conn.nthash")}
            </button>
          </div>
        </div>
        <label className="fld span2">
          {draft.secretKind === "nthash" ? t("conn.nthash") : t("conn.password")}
          <input
            type={draft.secretKind === "nthash" ? "text" : "password"}
            name="ad-secret"
            autoComplete="off"
            spellCheck={false}
            value={draft.secret}
            placeholder={draft.secretKind === "nthash" ? t("conn.nthashPh") : undefined}
            onChange={(e) => set({ secret: e.target.value })}
            required
          />
        </label>
        <label className="switch-l span2">
          <span className="switch">
            <input
              type="checkbox"
              checked={draft.authorized}
              onChange={(e) => set({ authorized: e.target.checked })}
              required
            />
            <span />
          </span>
          <span>{t("conn.authRequired")}</span>
        </label>
      </div>

      <div className="form-foot">
        <span className="muted small">{t("conn.nosave")}</span>
        <button type="submit" className="btn primary" disabled={loading || !draft.authorized}>
          <Icon name="lock" size={15} />
          {loading ? t("conn.scanning") : t("conn.submit")}
        </button>
      </div>
    </form>
  );
}
