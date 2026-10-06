// Aplica las preferencias guardadas antes del primer pintado (evita parpadeo
// de tema/acento). Debe coincidir con src/settings/SettingsContext.tsx.
try {
  var r = document.documentElement, k = "ens-ad-auditor.", g = function (n) { return localStorage.getItem(k + n); };
  var t = g("theme"), a = g("accent"), l = g("lang"), d = g("density");
  if (t === "light" || t === "dark") r.dataset.theme = t;
  if (/^(teal|blue|green|amber|rose|graphite)$/.test(a || "")) r.dataset.accent = a;
  if (l === "es" || l === "en") r.lang = l;
  if (d === "comoda" || d === "compacta") r.dataset.density = d;
  if (g("reduceMotion") === "1") r.dataset.motion = "reduce";
  if (g("reduceTransparency") === "1") r.dataset.transparency = "reduce";
} catch (e) {}
