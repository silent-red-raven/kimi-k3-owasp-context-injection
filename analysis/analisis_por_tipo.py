"""Análisis por tipo de hallazgo y por escenario (revisión posterior al plan).

Separa los hallazgos contabilizados de data/matriz_registro.csv en tres tipos:
  - codigo:        problemas del código (revisión manual, Bandit, Semgrep)
  - dep_vulnerable: dependencias con vulnerabilidades conocidas (pip-audit)
  - configuracion: recomendaciones de configuración incumplidas (versiones sin fijar)
y calcula, solo para los hallazgos de código, la densidad, la comparación entre
grupos con el escenario como unidad de análisis (respeta el agrupamiento de las
cinco iteraciones) y los análisis de sensibilidad por fragmento.

Uso:  python analysis/analisis_por_tipo.py [raiz_del_paquete] [carpeta_de_salida]
No modifica ningún archivo existente; escribe CSV nuevos en results/tables/.
"""
import sys, itertools
from pathlib import Path
import numpy as np
import pandas as pd
from scipy import stats

ROOT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "results" / "tables"
OUT.mkdir(parents=True, exist_ok=True)
SEMILLA = 20261116
N_BOOT = 20000

m = pd.read_csv(ROOT / "data" / "matriz_registro.csv", dtype=str, keep_default_na=False, encoding="utf-8-sig")
f = pd.read_csv(ROOT / "data" / "fragmentos.csv", encoding="utf-8-sig")
cat_esc = f.drop_duplicates("Escenario").set_index("Escenario")["Categoria_OWASP"]
m["contabilizado"] = m["Confirmado"].str.lower().isin(["sí", "si"]) & (m["Categoria_OWASP"] == m["Escenario"].map(cat_esc))

def tipo(h):
    h = h.lower()
    if h == "pip-audit":
        return "dep_vulnerable"
    if h == "comprobacion_versiones":
        return "configuracion"
    return "codigo"

k = m[m["contabilizado"]].copy()
k["Tipo"] = k["Herramienta"].map(tipo)
TIPOS = ["codigo", "dep_vulnerable", "configuracion"]
GRUPOS = ["control", "experimental"]
ESC = sorted(f["Escenario"].unique())

# 1) Hallazgos por tipo, escenario y grupo
t1 = (k.groupby(["Escenario", "Tipo", "Grupo"]).size().unstack("Grupo", fill_value=0)
        .reindex(pd.MultiIndex.from_product([ESC, TIPOS], names=["Escenario", "Tipo"]), fill_value=0)
        .reindex(columns=GRUPOS, fill_value=0).reset_index())
t1.insert(1, "Categoria_OWASP", t1["Escenario"].map(cat_esc))
t1.to_csv(OUT / "hallazgos_por_tipo_escenario.csv", index=False, encoding="utf-8-sig")
tot = t1.groupby("Tipo")[GRUPOS].sum().reindex(TIPOS)
tot.to_csv(OUT / "hallazgos_por_tipo.csv", encoding="utf-8-sig")

# 2) Severidad por tipo y grupo
sev = (k.groupby(["Tipo", "Grupo", "Severidad"]).size().unstack("Severidad", fill_value=0)
         .reindex(columns=["Baja", "Media", "Alta", "Crítica"], fill_value=0).reset_index())
sev.to_csv(OUT / "severidad_por_tipo.csv", index=False, encoding="utf-8-sig")

# 3) Hallazgos de código por fragmento y densidad solo de código
vc = k[k["Tipo"] == "codigo"].groupby("ID_fragmento").size()
fr = f[["ID_fragmento", "Escenario", "Grupo", "Iteracion", "LdC"]].copy()
fr["V_codigo"] = fr["ID_fragmento"].map(vc).fillna(0).astype(int)
fr["DV_codigo_por_100LdC"] = fr["V_codigo"] / fr["LdC"] * 100
fr.to_csv(OUT / "codigo_por_fragmento.csv", index=False, encoding="utf-8-sig")
filas = []
for g in GRUPOS:
    d = fr[fr["Grupo"] == g]
    filas.append({
        "Grupo": g, "V_codigo": int(d["V_codigo"].sum()), "LdC": int(d["LdC"].sum()),
        "fragmentos_con_hallazgo": int((d["V_codigo"] > 0).sum()), "fragmentos": len(d),
        "V_media_por_fragmento": d["V_codigo"].mean(), "V_DE": d["V_codigo"].std(ddof=1),
        "DV_global_por_100LdC": d["V_codigo"].sum() / d["LdC"].sum() * 100,
        "DV_media_por_fragmento": d["DV_codigo_por_100LdC"].mean(),
        "DV_mediana": d["DV_codigo_por_100LdC"].median(), "DV_maxima": d["DV_codigo_por_100LdC"].max(),
    })
pd.DataFrame(filas).to_csv(OUT / "densidad_codigo_por_grupo.csv", index=False, encoding="utf-8-sig")

# 4) Comparación con el escenario como unidad (respeta el agrupamiento)
pe = fr.pivot_table(index="Escenario", columns="Grupo", values="V_codigo", aggfunc="sum").reindex(ESC)
d_esc = (pe["control"] - pe["experimental"]).to_numpy(dtype=float)
no_nulas = d_esc[d_esc != 0]
res = []
w = stats.wilcoxon(pe["control"], pe["experimental"], zero_method="wilcox", alternative="two-sided", method="exact") if len(no_nulas) else None
res.append({"analisis": "Wilcoxon exacto por escenario (10 escenarios; unidad = escenario)", "n": len(d_esc),
            "informativos": int(len(no_nulas)), "estadistico": float(w.statistic), "p": float(w.pvalue)})
pos = int((no_nulas > 0).sum())
b = stats.binomtest(pos, len(no_nulas), 0.5, alternative="two-sided")
res.append({"analisis": "Prueba de signos exacta por escenario", "n": len(d_esc), "informativos": int(len(no_nulas)),
            "estadistico": pos, "p": float(b.pvalue)})
# permutación exacta por cambio de signo de las diferencias por escenario
obs = abs(d_esc.sum()); cuenta = 0; total = 0
for signos in itertools.product([1, -1], repeat=len(d_esc)):
    total += 1
    if abs((d_esc * np.array(signos)).sum()) >= obs - 1e-12:
        cuenta += 1
res.append({"analisis": "Permutación exacta por cambio de signo (suma de diferencias por escenario)", "n": len(d_esc),
            "informativos": int(len(no_nulas)), "estadistico": float(d_esc.sum()), "p": cuenta / total})

# 5) Sensibilidad por fragmento (ignora el agrupamiento; solo descriptiva)
pp = fr.pivot_table(index=["Escenario", "Iteracion"], columns="Grupo", values="V_codigo")
d_par = (pp["control"] - pp["experimental"]).to_numpy(dtype=float)
w2 = stats.wilcoxon(pp["control"], pp["experimental"])
res.append({"analisis": "Wilcoxon pareado por iteración (prueba del plan; ignora el agrupamiento)", "n": len(d_par),
            "informativos": int((d_par != 0).sum()), "estadistico": float(w2.statistic), "p": float(w2.pvalue)})
u = stats.mannwhitneyu(fr[fr.Grupo == "control"]["V_codigo"], fr[fr.Grupo == "experimental"]["V_codigo"], alternative="two-sided")
res.append({"analisis": "U de Mann-Whitney por fragmento (ignora el agrupamiento)", "n": 100, "informativos": "",
            "estadistico": float(u.statistic), "p": float(u.pvalue)})
a = int((fr[fr.Grupo == "control"]["V_codigo"] > 0).sum()); c = int((fr[fr.Grupo == "experimental"]["V_codigo"] > 0).sum())
fe = stats.fisher_exact([[a, 50 - a], [c, 50 - c]])
res.append({"analisis": "Fisher exacto, fragmentos con hallazgo (ignora el agrupamiento)", "n": 100, "informativos": "",
            "estadistico": f"{a}/50 frente a {c}/50", "p": float(fe.pvalue)})
pd.DataFrame(res).to_csv(OUT / "pruebas_codigo.csv", index=False, encoding="utf-8-sig")

# 6) Magnitud de la diferencia con intervalos por remuestreo de escenarios
rng = np.random.default_rng(SEMILLA)
D = pp["control"].sub(pp["experimental"]).unstack("Iteracion").reindex(ESC).to_numpy(dtype=float)   # 10 x 5
P = (pp["control"].gt(0).astype(float) - pp["experimental"].gt(0).astype(float)).unstack("Iteracion").reindex(ESC).to_numpy()
idx = rng.integers(0, len(ESC), size=(N_BOOT, len(ESC)))
boot_d = D[idx].mean(axis=(1, 2)); boot_p = P[idx].mean(axis=(1, 2))
idx2 = rng.integers(0, D.size, size=(N_BOOT, D.size))
boot_d_frag = D.ravel()[idx2].mean(axis=1)
# correlación intraclase ICC(1) de las diferencias por escenario
kk = D.shape[1]; n = D.shape[0]
msb = kk * ((D.mean(axis=1) - D.mean()) ** 2).sum() / (n - 1)
msw = ((D - D.mean(axis=1, keepdims=True)) ** 2).sum() / (n * (kk - 1))
icc = (msb - msw) / (msb + (kk - 1) * msw)
ef = pd.DataFrame([
    {"indicador": "Diferencia media de hallazgos de código por par (control - experimental)", "valor": D.mean(),
     "ic95_inf": np.percentile(boot_d, 2.5), "ic95_sup": np.percentile(boot_d, 97.5), "metodo_ic": "bootstrap percentil remuestreando escenarios"},
    {"indicador": "Diferencia media de hallazgos de código por par (control - experimental)", "valor": D.mean(),
     "ic95_inf": np.percentile(boot_d_frag, 2.5), "ic95_sup": np.percentile(boot_d_frag, 97.5), "metodo_ic": "bootstrap percentil remuestreando pares (ignora el agrupamiento)"},
    {"indicador": "Diferencia en la proporción de fragmentos con hallazgo de código", "valor": P.mean(),
     "ic95_inf": np.percentile(boot_p, 2.5), "ic95_sup": np.percentile(boot_p, 97.5), "metodo_ic": "bootstrap percentil remuestreando escenarios"},
    {"indicador": "Correlación intraclase ICC(1) de las diferencias de código por escenario", "valor": icc, "ic95_inf": "", "ic95_sup": "", "metodo_ic": ""},
    {"indicador": "Número efectivo de pares", "valor": D.size / (1 + (kk - 1) * icc), "ic95_inf": "", "ic95_sup": "", "metodo_ic": ""},
    {"indicador": "Escenarios con diferencia distinta de cero", "valor": int(len(no_nulas)), "ic95_inf": "", "ic95_sup": "", "metodo_ic": ""},
    {"indicador": "Valor p bilateral mínimo alcanzable con esos escenarios", "valor": 2 / 2 ** len(no_nulas), "ic95_inf": "", "ic95_sup": "", "metodo_ic": ""},
])
ef.to_csv(OUT / "magnitud_codigo.csv", index=False, encoding="utf-8-sig")

pd.set_option("display.width", 250); pd.set_option("display.max_colwidth", 90)
for nombre in ["hallazgos_por_tipo", "severidad_por_tipo", "densidad_codigo_por_grupo", "pruebas_codigo", "magnitud_codigo"]:
    print("==", nombre); print(pd.read_csv(OUT / f"{nombre}.csv", encoding="utf-8-sig").to_string(index=False))
print("== por escenario (solo con hallazgos)")
print(t1[(t1.control + t1.experimental) > 0].to_string(index=False))
print("== codigo por escenario"); print(pe.T.to_string())
