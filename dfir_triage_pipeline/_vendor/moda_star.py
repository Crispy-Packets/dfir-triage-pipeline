"""VENDORED MODA*-G core, with one determinism patch.

Source : https://zenodo.org/records/19439683
         LuisJMarcanoVerde/MODA-Star-G v1.0.0, git commit b507a6a
License: MIT (Luis J. Marcano Verde, 2026) -- see _vendor/LICENSE.moda_star
Vendored 2026-09-21 for OD-01 Phase 5 (DFIR_ANOMALY_SCORER=moda_g).

WHY VENDORED, not pip-installed: MODA*-G has no PyPI package; it is a Zenodo
research artifact. Its dependencies (numpy/scipy/sklearn) are already present.

THE ONE CHANGE, marked << PATCH >> below: the upstream `_pena_directions` calls
`np.random.default_rng()` with no seed -- a fresh unseeded generator every call,
so scores differ between runs and the run.json manifest (which hashes bytes)
could never be reproduced. Replaced with a module RNG seeded by `moda_seed()`,
which the wrapper calls before scoring. `compute_mcd`'s `np.random.choice` uses
the global numpy RNG, also seeded by `moda_seed()`. No scoring logic is altered.
"""
# ruff: noqa
"""
MODA* — Mixed-Data Outlier Divergence Analysis (Extended)
Core implementation — Version 0.6  (MODA*-G, Softmax Gating)

Key innovation: Softmax Gating with temperature parameter k.

Instead of a fixed linear combination, MODA*-G computes observation-level
weights via a softmax transformation of the engine scores:

    w_i(x) = exp(k * S_i(x)) / sum_j exp(k * S_j(x))

    MODA*-G(x) = sum_i w_i(x) * S_i(x)

Properties of the Softmax gating:
  k -> 0 : weights converge to 0.25 (uniform average, like v0.3 equal weights)
  k = 3  : moderate amplification of the dominant engine
  k = 5  : strong amplification — dominant engine receives ~0.97 of total weight
             when it scores 0.95 and others score 0.02
  k -> inf: argmax — all weight to the highest-scoring engine

Why this solves O4:
  In O4, SDC(outlier) ~ 0.95, MCD(outlier) ~ 0.02.
  With k=5: w_sdc = exp(5*0.95) / (exp(5*0.95) + 3*exp(5*0.02))
           = 111.6 / (111.6 + 3.3) = 0.971  -> SDC dominates.
  The linear combination is replaced by a self-normalising attention
  mechanism that amplifies the signal where it exists.

Why O1-O3 are preserved:
  When multiple engines score high (O1: MCD=Pena=Gower~0.99),
  the softmax distributes weight roughly equally among them,
  while SDC (scoring ~0.48) is naturally suppressed.

Theoretical basis (Proposition 2):
  If S_k(x*) > S_j(x*) + delta for all j != k and some delta > 0,
  then w_k(x*) >= exp(k*delta) / (3 + exp(k*delta)) -> 1 as k -> inf,
  and MODA*-G(x*) -> S_k(x*).

Authors: Luis J. Marcano Verde
Working Paper v0.6 — March 2026
"""

import numpy as np

_MODA_RNG = np.random.default_rng(0)

def moda_seed(seed):
    "PATCH: seed both the global RNG (compute_mcd) and the module RNG (Pena)."
    global _MODA_RNG
    np.random.seed(seed)
    _MODA_RNG = np.random.default_rng(seed)
from scipy.stats import chi2


# ─── Normalization ────────────────────────────────────────────────────────────
def phi(d, kappa=3.0):
    d = np.asarray(d, dtype=float)
    return d / (d + kappa)


# ─── Robust statistics ────────────────────────────────────────────────────────
def robust_mad(arr):
    arr = np.asarray(arr, dtype=float)
    med = np.median(arr)
    val = float(np.median(np.abs(arr - med)))
    return val if val > 1e-10 else 1e-10

def robust_scale(arr):
    return 1.4826 * robust_mad(arr)


# ─── ENGINE I: MCD Robust Score ───────────────────────────────────────────────
def compute_mcd(X_num, h_frac=0.75):
    n, p = X_num.shape
    h    = min(max(p + 1, int(np.floor(n * h_frac))), n)
    best_det, best_T, best_Sinv = np.inf, None, None

    for _ in range(8):
        idx    = np.random.choice(n, h, replace=False)
        subset = X_num[idx].copy()
        for _ in range(10):
            T = np.mean(subset, axis=0)
            C = (np.cov(subset.T) if subset.shape[0] > 1
                 else np.eye(p)) + np.eye(p) * 1e-8
            try:
                Sinv = np.linalg.inv(C)
            except np.linalg.LinAlgError:
                break
            diff  = X_num - T
            dists = np.einsum('ij,jk,ik->i', diff, Sinv, diff)
            idx   = np.argsort(dists)[:h]
            subset = X_num[idx]
        T   = np.mean(subset, axis=0)
        C   = (np.cov(subset.T) if subset.shape[0] > 1
               else np.eye(p)) + np.eye(p) * 1e-8
        det = float(np.abs(np.linalg.det(C)))
        if 1e-30 < det < best_det:
            best_det = det
            best_T   = T.copy()
            try:
                best_Sinv = np.linalg.inv(C)
            except np.linalg.LinAlgError:
                pass

    if best_T is None or best_Sinv is None:
        best_T    = np.mean(X_num, axis=0)
        C         = np.cov(X_num.T) + np.eye(p) * 1e-8
        best_Sinv = np.linalg.inv(C)
    return best_T, best_Sinv


def score_mcd(X_num, h_frac=0.75):
    n, p    = X_num.shape
    kappa   = float(np.sqrt(chi2.ppf(0.975, df=max(p, 1))))
    T, Sinv = compute_mcd(X_num, h_frac)
    diff    = X_num - T
    dists   = np.sqrt(np.maximum(
                  np.einsum('ij,jk,ik->i', diff, Sinv, diff), 0.0))
    return phi(dists, kappa)


# ─── ENGINE II: Peña Kurtosis Score ───────────────────────────────────────────
def _pena_directions(X_num, n_dirs):
    n, p   = X_num.shape
    means  = np.mean(X_num, axis=0)
    stds   = np.std(X_num, axis=0)
    stds[stds < 1e-10] = 1.0
    Xstd   = (X_num - means) / stds
    dirs   = []
    for j in range(p):
        v = np.zeros(p); v[j] = 1.0; dirs.append(v)
    for j in range(p):
        for k in range(j + 1, p):
            if len(dirs) >= n_dirs * 2: break
            v = np.zeros(p)
            v[j] =  1/np.sqrt(2); v[k] =  1/np.sqrt(2)
            dirs.append(v.copy())
            v[k] = -1/np.sqrt(2)
            dirs.append(v.copy())
    rng = _MODA_RNG  # << PATCH: was np.random.default_rng() (unseeded)
    while len(dirs) < n_dirs * 2:
        v    = rng.standard_normal(p)
        norm = np.linalg.norm(v)
        if norm > 1e-10:
            dirs.append(v / norm)
    return dirs[:n_dirs * 2], Xstd


def score_pena(X_num, n_dirs=None):
    n, p   = X_num.shape
    if n_dirs is None:
        n_dirs = min(2 * p, 16)
    dirs, Xstd = _pena_directions(X_num, n_dirs)
    scores = np.zeros(n)
    for v in dirs:
        proj   = Xstd @ v
        med    = np.median(proj)
        mad    = robust_scale(proj)
        scores = np.maximum(scores, np.abs(proj - med) / mad)
    return phi(scores, kappa=3.0)


# ─── ENGINE III: Gower-MAD Distance Score ─────────────────────────────────────
def _gower_matrix(X_num, X_cat, mad_scales):
    n     = X_num.shape[0]
    p     = X_num.shape[1]
    q     = X_cat.shape[1] if (X_cat is not None and X_cat.ndim == 2) else 0
    total = max(p + q, 1)
    D     = np.zeros((n, n))
    for j in range(p):
        col   = X_num[:, j]
        scale = mad_scales[j] if mad_scales[j] > 1e-10 else 1.0
        D    += np.abs(col[:, None] - col[None, :]) / scale
    if q > 0:
        for k in range(q):
            col = X_cat[:, k]
            D  += (col[:, None] != col[None, :]).astype(float)
    return D / total


def score_gower(X_num, X_cat=None, k_neighbors=None):
    n = X_num.shape[0]
    if k_neighbors is None:
        k_neighbors = max(3, int(np.floor(np.sqrt(n))))
    k_neighbors = min(k_neighbors, n - 1)
    mad_scales  = np.array([robust_scale(X_num[:, j])
                             for j in range(X_num.shape[1])])
    X_cat_use   = (X_cat if (X_cat is not None and X_cat.ndim == 2)
                   else np.empty((n, 0), dtype=int))
    D = _gower_matrix(X_num, X_cat_use, mad_scales)
    D_knn = D.copy()
    np.fill_diagonal(D_knn, np.inf)
    knn_mean = np.array([np.mean(np.sort(D_knn[i])[:k_neighbors])
                         for i in range(n)])
    D_all = D.copy()
    np.fill_diagonal(D_all, 0.0)
    global_mean = D_all.sum(axis=1) / (n - 1)
    combined = np.maximum(knn_mean, global_mean * 0.5)
    return phi(combined * 5.0, kappa=1.0)


# ─── ENGINE IV: Categorical Entropy Score ─────────────────────────────────────
def score_sdc(X_cat):
    if X_cat is None or X_cat.ndim < 2 or X_cat.shape[1] == 0:
        n = X_cat.shape[0] if (X_cat is not None and X_cat.ndim >= 1) else 0
        return np.zeros(n)
    n, q      = X_cat.shape
    log_probs = np.zeros(n)
    for k in range(q):
        col            = X_cat[:, k]
        unique, counts = np.unique(col, return_counts=True)
        n_obs          = len(unique)
        freq           = {int(u): (c + 1.0) / (n + n_obs)
                          for u, c in zip(unique, counts)}
        p_unseen       = 1.0 / (n + n_obs + 1)
        for i in range(n):
            p_val         = freq.get(int(col[i]), p_unseen)
            log_probs[i] += np.log(max(p_val, 1e-15))
    geo_mean = np.exp(log_probs / q)
    return np.clip(1.0 - geo_mean, 0.0, 1.0)


# ─── SOFTMAX GATING (v0.6) ────────────────────────────────────────────────────
def softmax_gating(scores_matrix, k=3.0):
    """
    Compute observation-level softmax weights for each engine.

    Parameters
    ----------
    scores_matrix : ndarray (4, n)  — one row per engine
    k             : float  — temperature parameter
                    k=0  -> uniform weights (simple average)
                    k=3  -> moderate amplification
                    k=5  -> strong amplification
                    k=10 -> near-argmax behaviour

    Returns
    -------
    weights : ndarray (4, n)  — softmax weights, sum to 1 per column
    scores  : ndarray (n,)    — gated MODA* scores

    Algorithm:
      exp_kS = exp(k * S_i(x))
      w_i(x) = exp_kS_i / sum_j exp_kS_j
      MODA*-G(x) = sum_i w_i(x) * S_i(x)

    Numerical stability: subtract max before exp (standard log-sum-exp trick)
    """
    # scores_matrix shape: (4, n)
    S        = np.asarray(scores_matrix, dtype=float)   # (4, n)
    kS       = k * S
    kS_max   = kS.max(axis=0, keepdims=True)            # (1, n) — stability
    exp_kS   = np.exp(kS - kS_max)                      # (4, n)
    weights  = exp_kS / exp_kS.sum(axis=0, keepdims=True)  # (4, n)
    gated    = (weights * S).sum(axis=0)                 # (n,)
    return weights, gated


# ─── Default base weights (for linear fallback) ───────────────────────────────
def _default_weights(has_num, has_cat):
    if has_num and has_cat:
        return 0.30, 0.20, 0.15, 0.35
    elif has_num and not has_cat:
        return 0.40, 0.35, 0.25, 0.00
    else:
        return 0.00, 0.00, 0.20, 0.80


# ─── MODA*-G Combined Score ───────────────────────────────────────────────────
def moda_star(X_num, X_cat=None,
              alpha=None, beta=None, gamma=None, delta=None,
              h_frac=0.75, n_dirs=None, k_neighbors=None,
              k_temp=3.0,
              use_gating=True,
              return_components=False):
    """
    Compute MODA*-G scores for a mixed dataset.

    Parameters
    ----------
    X_num          : ndarray (n, p)
    X_cat          : ndarray (n, q) int-encoded, or None
    alpha,beta,gamma,delta : base weights for linear fallback
    h_frac         : MCD subset fraction (default 0.75)
    n_dirs         : Peña directions (default min(2p,16))
    k_neighbors    : kNN for Gower (default sqrt(n))
    k_temp         : Softmax temperature (default 3.0)
                     Tested values: 1, 2, 3, 5, 8, 10
    use_gating     : True  -> MODA*-G (softmax gating)
                     False -> base linear weights (v0.3)
    return_components : return engine scores and gating weights

    Returns
    -------
    scores         : ndarray (n,) in [0,1)
    [optional]     : s_mcd, s_pena, s_gow, s_sdc,
                     gating_weights (4, n), mean_weights (4,)
    """
    n = X_num.shape[0]
    if X_cat is None:
        X_cat = np.empty((n, 0), dtype=int)

    has_num = X_num.shape[1] > 0
    has_cat = X_cat.ndim == 2 and X_cat.shape[1] > 0

    if any(w is None for w in [alpha, beta, gamma, delta]):
        alpha, beta, gamma, delta = _default_weights(has_num, has_cat)

    assert abs(alpha+beta+gamma+delta - 1.0) < 1e-5

    # Compute engine scores
    s_mcd  = score_mcd(X_num, h_frac)                        if has_num else np.zeros(n)
    s_pena = score_pena(X_num, n_dirs)                       if has_num else np.zeros(n)
    s_gow  = score_gower(X_num, X_cat if has_cat else None,
                          k_neighbors)
    s_sdc  = score_sdc(X_cat)                                if has_cat else np.zeros(n)

    if use_gating:
        # MODA*-G: softmax gating
        S_mat = np.array([s_mcd, s_pena, s_gow, s_sdc])  # (4, n)
        gating_weights, scores = softmax_gating(S_mat, k=k_temp)
        mean_weights = gating_weights.mean(axis=1)        # (4,) mean over obs
    else:
        # Linear combination (v0.3)
        a, b, g, d  = alpha, beta, gamma, delta
        scores       = a*s_mcd + b*s_pena + g*s_gow + d*s_sdc
        gating_weights = np.tile(np.array([a,b,g,d])[:,None], (1,n))
        mean_weights   = np.array([a, b, g, d])

    if return_components:
        return scores, s_mcd, s_pena, s_gow, s_sdc, gating_weights, mean_weights
    return scores


# ─── Threshold & classification ───────────────────────────────────────────────
def adaptive_threshold(scores):
    return float(np.median(scores) + 3.0 * robust_mad(scores))

def classify(scores, tau=None):
    if tau is None:
        tau = adaptive_threshold(scores)
    return (scores >= tau).astype(int)
