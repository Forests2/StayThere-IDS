#!/usr/bin/env python3
"""
AMHS Sentinel_M16BR — 독립 관제 서버

데모스(demos_v1)와 완전 독립: 별도 프로세스, 별도 포트(기본 8989),
demos_v1 어떤 모듈도 import 하지 않는다.

실행:
    python server.py                 # 사내망 (로그프레소 실접속)
    LP_OFFLINE=1 python server.py    # 사외 (fixture 로 UI 확인)
"""
from __future__ import annotations

import json
import os
import threading
import time
import uuid
from datetime import datetime, timedelta

from flask import Flask, jsonify, request, send_from_directory, Response

import alarm_count
import http_cache
from lp_client import fab_codes, load_config, parse_dt, ping, sys_cfg
from lp_query import build, query
from report import build_report, feedback_status, save_feedback
from sentinel import CaseStore, alarm_floor, grade_cuts, scan_once

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CFG = load_config()

app = Flask(__name__, static_folder=os.path.join(BASE_DIR, "static"))


# ─────────────────────── 느린 요청 로그 ───────────────────────
# "저장이 오래 걸린다" 같은 말을 숫자로 바꾸기 위한 것. 개발 PC 에서는 4ms 인
# 요청이 현장에서 느리면, 원인이 코드가 아니라 그 서버의 무언가(디스크·수집
# 스레드·백신 등)라는 뜻이다. 어느 요청이 몇 초 걸렸는지 남겨야 좁힐 수 있다.
SLOW_MS = 1000                      # 이보다 오래 걸린 요청만 남긴다
SLOW_LOG: list = []                 # 최근 50건 (화면에서 볼 수 있게)


@app.before_request
def _t_start():
    request.environ["_t0"] = time.time()


@app.after_request
def _etag(resp):
    """나머지 /api GET 도 지문을 붙이고, 같으면 304 로 끝낸다.

    ★화면은 status·cases·kpi 를 3초마다 묻는데 내용은 대개 그대로다. 지문만
      맞춰 보면 본문을 아예 안 보낸다 — 느린 서버에서 이게 제일 크게 듣는다.
      (feed·fab/compare 는 이미 자기 캐시에서 지문을 붙여 오므로 건너뛴다.)
    ★GET · 200 · 다이렉트 패스스루가 아닌 것만. POST 는 손대지 않는다.
    """
    try:
        # ★정적 파일도 **늘 물어보고** 쓰게 한다. Flask 는 ETag·Last-Modified 만
        #   붙이고 Cache-Control 을 안 붙이는데, 그러면 브라우저가 휴리스틱
        #   캐시로 넘어가 **묻지도 않고** 옛 파일을 쓴다 — "서버는 바뀌었는데
        #   화면은 그대로". no-cache 는 '쓰지 마라' 가 아니라 '쓰기 전에
        #   물어봐라' 라서, 안 바뀌었으면 304 한 줄로 끝난다.
        if request.method == "GET" and request.path.startswith("/static/") \
                and not resp.headers.get("Cache-Control"):
            resp.headers["Cache-Control"] = "no-cache, must-revalidate"
        if (request.method != "GET" or resp.status_code != 200
                or resp.direct_passthrough or resp.headers.get("ETag")
                or not request.path.startswith("/api/")):
            return resp
        body = resp.get_data()
        if not body:
            return resp
        etag = http_cache.etag_of(body)
        resp.headers["ETag"] = etag
        resp.headers["Cache-Control"] = "no-cache"
        inm = request.headers.get("If-None-Match")
        if inm and etag in [t.strip() for t in inm.split(",")]:
            resp.set_data(b"")
            resp.status_code = 304
            return resp
        if len(body) >= http_cache.GZIP_MIN and \
                "gzip" in (request.headers.get("Accept-Encoding") or "").lower():
            gz = http_cache.gzipped(body)
            if len(gz) < len(body):
                resp.set_data(gz)
                resp.headers["Content-Encoding"] = "gzip"
                resp.headers["Vary"] = "Accept-Encoding"
    except Exception as e:                              # noqa: BLE001
        print(f"[ETag] ⚠️ 건너뜀: {type(e).__name__}: {e}")
    return resp


@app.after_request
def _t_end(resp):
    t0 = request.environ.get("_t0")
    if t0:
        ms = int((time.time() - t0) * 1000)
        resp.headers["X-Elapsed-ms"] = str(ms)
        if ms >= SLOW_MS and request.path.startswith("/api/"):
            rec = {"at": datetime.now().strftime("%H:%M:%S"),
                   "method": request.method, "path": request.full_path[:120],
                   "ms": ms}
            SLOW_LOG.append(rec)
            del SLOW_LOG[:-50]
            print(f"[느림] {rec['method']} {rec['path']} — {ms}ms")
    return resp


@app.route("/api/slow")
def api_slow():
    """최근 느린 요청 목록 — 현장에서 원인을 좁힐 때."""
    return jsonify({"threshold_ms": SLOW_MS, "items": list(reversed(SLOW_LOG)),
                    "caches": [c.stats() for c in (FEED_CACHE, CMP_CACHE, CASES_CACHE,
                                                   GRAPH_CACHE, _HTML_CACHE)]})


# ─────────────────────── 무거운 응답 캐시 ───────────────────────
# ★2026-09-18 현장 로그: feed 7~17초, fab/compare 18~20초. 재 보니 계산은
#   300ms 인데 (1) 화면이 3초마다 묻고 데이터는 60초에 한 번 바뀌며
#   (2) 화면 셋이 같은 순간 같은 것을 동시에 만들고 (3) 캐시가 적중해도
#   1.5MB 를 매번 다시 직렬화하고 있었다. http_cache 가 셋을 같이 막는다.
def _cached_json(cache, key: str, sig, build, ctype: str | None = None):
    """지문이 같으면 안 만들고, 브라우저가 이미 갖고 있으면 304 로 끝낸다.

    ctype 을 주면 그 타입으로 나간다 — 구간 그래프(SVG)·기여도(HTML)처럼
    JSON 이 아닌 응답도 같은 길을 쓴다 (build 가 bytes/str 을 돌려주면 된다).
    """
    e = cache.get_or_build(key, sig, build)
    code, body, hdr = http_cache.negotiate(
        e, request.headers.get("If-None-Match"),
        request.headers.get("Accept-Encoding"))
    if ctype:
        hdr["Content-Type"] = ctype
    return Response(body, status=code, headers=hdr)


def _days_sig(days, cfg) -> tuple | None:
    """그 날짜 파일들이 그대로인가 — (mtime, size) 묶음. 하나라도 없으면 None
    (캐시를 안 쓴다 — 없는 파일을 '그대로' 라고 하면 안 된다)."""
    from store_csv import day_path
    out = []
    for d in sorted(days):
        try:
            st = os.stat(day_path(d, cfg))
        except OSError:
            return None
        out.append((d, st.st_mtime_ns, st.st_size))
    return tuple(out)


# ─────────────────────── 시스템(FAB) 별 컨텍스트 ───────────────────────
# ALL(전체 통합) + FAB 별 화면이 **한 서버**에서 같이 돈다. 케이스 저장소·
# 폴링 상태·캐시가 시스템마다 따로 있어야 M14 화면이 ALL 케이스를 보는
# 사고가 안 난다. 설정은 sys_cfg() 의 얕은 뷰라 수집 주기 같은 공유 설정은
# 전 시스템에 즉시 반영된다.
def systems() -> list[str]:
    """관제 시스템 목록 — ALL + config.source.jupyter.fabs (주피터 모드일 때만).

    FAB 별 파일은 주피터에만 있다. 로그프레소 모드면 ALL 하나다.
    """
    from sentinel import source_mode
    if source_mode(CFG) != "jupyter":
        return ["ALL"]
    return ["ALL"] + [s for s in fab_codes(CFG) if s != "ALL"]


def _blank_state() -> dict:
    """폴링 상태 (대시보드 헤더의 STREAMING · latency 표시용)."""
    return {"last_scan": None, "latency_ms": None, "connected": False,
            "error": None, "amos_warn": None,
            "source": None,            # 데이터 출처 — logpresso / jupyter
            "scans": 0,
            "forecast": None}          # 선행 감지 결과 (forecast.predict)


CTX_LOCK = threading.Lock()
CTX: dict[str, dict] = {}


def get_ctx(sys: str | None = "ALL") -> dict:
    """시스템 컨텍스트 — 없으면 만든다. 모르는 코드는 ALL 로 (화면이 죽는
    것보다 전체 화면이 낫다)."""
    s = str(sys or "ALL").strip().upper() or "ALL"
    if s not in systems():
        s = "ALL"
    with CTX_LOCK:
        if s not in CTX:
            c = sys_cfg(CFG, s)
            store = CaseStore(c)
            # ★이 시스템 화면을 처음 열 때 한 번, 보관 기간(기본 30일)을 넘긴
            #   케이스를 보관 파일로 옮긴다. 안 치우면 화면이 3초마다 부르는
            #   /api/cases 가 날마다 무거워진다 (800건 = 2.9MB · 29ms).
            #   ★저장소를 **만드는 것만으로** 파일이 바뀌면 안 되므로
            #     (시험·도구가 그냥 만들어 볼 수 있다) 부르는 자리를 여기 둔다.
            try:
                store.prune(force=True)
            except Exception as e:                      # noqa: BLE001
                print(f"[케이스] ⚠️ 정리 건너뜀: {type(e).__name__}: {e}")
            CTX[s] = {
                "sys": s, "cfg": c, "store": store,
                "state": _blank_state(),
                "watched": 0.0,        # 마지막으로 이 시스템 화면이 물어본 시각
                # 빈 구간 메움(backfill) 진행 상태
                "backfill": {"running": False, "day": None, "started": None,
                             "result": None},
                # 선행 지표 분석 캐시 — 며칠치 CSV 를 훑어서 매 요청 재계산하면 느리다
                "leading": {"at": 0.0, "data": None, "key": ""},
                # 임계 격자 탐색은 며칠치를 수십 번 되감아 몇 초 걸린다 — 짧게 캐시
                "tune": {"at": 0.0, "data": None, "key": ""},
                "cmp": {"at": 0.0, "data": None, "key": ""},
            }
        return CTX[s]


def rctx() -> dict:
    """요청의 ?sys= 로 컨텍스트를 고른다 (없으면 ALL). 화면이 보고 있다는
    표시(watched)도 여기서 남긴다 — FAB 의 분당 LLM 은 보고 있을 때만 돈다."""
    c = get_ctx(request.args.get("sys"))
    c["watched"] = time.time()
    return c


# ────────────────────────────── 폴링 루프 ──────────────────────────────
def _bootstrap_today() -> None:
    """기동 시 **모든 시스템**의 오늘 하루치를 확보한다 (00:00 ~ 현재).

    중간에 서버가 꺼져 있던 구간까지 메운다. 이미 저장된 분은 중복으로 걸러지므로
    여러 번 돌려도 안전하다. 이후 수집은 폴링 루프가 증분으로 이어간다.
    FAB 파일이 아직 없는 날(404)은 경고만 남기고 계속 간다.
    """
    from sentinel import source_mode
    now = datetime.now()
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    day = now.strftime("%Y%m%d")
    jup = source_mode(CFG) == "jupyter"
    ss = systems()
    print(f"[기동] 오늘({day}) 00:00 ~ {now:%H:%M} 하루치 확보 중… "
          f"({'주피터 CSV' if jup else '로그프레소'} · {' '.join(ss)})")

    def one(sys):
        ctx = get_ctx(sys)
        t0 = time.time()
        tag = f"[기동:{sys}]"
        try:
            if jup:
                # ★출처가 주피터면 여기서도 주피터로 받는다. 예전엔 이 자리에서만
                #   collect()(=로그프레소)를 불러서, 설정을 바꿔도 기동 때 한 번은
                #   로그프레소를 치고 있었다.
                from jupyter_csv import fetch_day
                jr = fetch_day(day, ctx["cfg"], verbose=False)
                r = {"ok": jr.get("ok"), "error": jr.get("error"),
                     "rows": jr.get("rows", 0), "written": jr.get("written", 0),
                     "skipped": jr.get("skipped", 0), "files": jr.get("files") or [],
                     "minutes": jr.get("rows", 0)}
            else:
                from collect import collect
                r = collect(start.strftime("%Y%m%d%H%M%S"), now.strftime("%Y%m%d%H%M%S"),
                            ctx["cfg"], verbose=False)
            if not r.get("ok"):
                print(f"{tag} ⚠️ 확보 실패 — {r.get('error')}")
                ctx["state"]["bootstrap"] = {"ok": False, "error": r.get("error")}
                return
            print(f"{tag} ✅ {r['rows']}행({r['minutes']}분) 조회 · 신규 {r['written']}행 저장 · "
                  f"중복 {r['skipped']}"
                  + (f" → {', '.join(r['files'])}" if r.get("files") else "")
                  + f"  [{round(time.time()-t0,1)}초{_wire(ctx)}]")
            if r.get("warn"):
                print(f"{tag} ⚠️ {r['warn']}")
            ctx["state"]["bootstrap"] = {"ok": True, "minutes": r["minutes"],
                                         "written": r["written"],
                                         "at": datetime.now().isoformat()}
        except Exception as e:
            print(f"{tag} ⚠️ 확보 예외: {type(e).__name__}: {e}")
            ctx["state"]["bootstrap"] = {"ok": False, "error": str(e)}

    # ★여섯 시스템을 **같이** 받는다. 예전엔 한 줄로 세워 놓고 하나씩 받아서,
    #   한 파일에 2초면 기동에만 12초가 걸렸다. 서로 다른 파일·다른 저장소라
    #   기다릴 이유가 없다 (로그인 세션은 한 벌을 나눠 쓴다 — login 단일 비행).
    t_all = time.time()
    _fan_out(one, ss)
    print(f"[기동] 하루치 확보 끝 — 전체 {round(time.time() - t_all, 1)}초")


def _fan_out(fn, items) -> None:
    """시스템들을 **동시에** 돌린다 — 서로 다른 파일·저장소라 줄 세울 이유가 없다.

    하나가 터져도 나머지는 간다 (각 fn 이 자기 예외를 삼키게 되어 있다).
    """
    items = list(items)
    if len(items) < 2:
        for x in items:
            fn(x)
        return
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=min(len(items), 8),
                            thread_name_prefix="sys") as ex:
        list(ex.map(fn, items))


def _wire(ctx: dict) -> str:
    """이번에 실제로 몇 바이트를 받았나 — ' · 꼬리 12KB/1.5MB' 처럼 붙인다.

    ★'느리다' 는 말에 숫자를 붙이려고 남긴다. 통신량이 전체 그대로면 꼬리
      받기가 안 먹는 것이고, 꼬리만인데도 느리면 원인은 다른 데 있다.
    """
    try:
        from jupyter_csv import cfg_of, last_timing, wire_bytes
        _c = cfg_of(ctx["cfg"])
        got, tot = wire_bytes(_c)
        t = last_timing(_c)
    except Exception:                                   # noqa: BLE001
        return ""
    # ★어디서 시간이 갔는지 나눠 적는다. '받기' 가 대부분이면 주피터 쪽이고,
    #   '저장' 이 대부분이면 우리 쪽이다 — 이 한 줄이 그 판가름을 한다.
    if t:
        _br = " · ".join(f"{k}{v}s" for k, v in
                         (("받기 ", t.get("net")), ("파싱 ", t.get("parse")),
                          ("저장 ", t.get("save"))) if v is not None)
    else:
        _br = ""
    if not tot:
        return f" · {_br}" if _br else ""
    kb = lambda n: f"{n / 1024:.0f}KB" if n < 1024 * 1024 else f"{n / 1048576:.1f}MB"
    return (f" · 받음 {kb(got)}/{kb(tot)}" + ("" if got >= tot else " (꼬리)")
            + (f" · {_br}" if _br else ""))


def _llm_mode(sys: str) -> str:
    """이 시스템의 분당 판단 모드 — on / watched / off.

    정책 탭에서 시스템 6개를 따로 정한다 (llm.per_minute.by_sys). 지정이
    없으면 옛 전역 스위치(fab_minute)와 호환: ALL=on, FAB=fab_minute.
    """
    lc = CFG.get("llm", {})
    by = (lc.get("per_minute") or {}).get("by_sys") or {}
    mode = str((by.get(sys) or {}).get("mode", "")).strip().lower()
    if mode in ("on", "watched", "off"):
        return mode
    if sys == "ALL":
        return "on"
    return {"always": "on", "watched": "watched",
            "off": "off"}.get(str(lc.get("fab_minute", "always")).lower(), "on")


def _llm_on(ctx: dict, interval: int) -> bool:
    """이 시스템의 분당 LLM 판단을 돌릴까.

      · on(기본)  — 안 보고 있어도 돈다. 'LLM 판단 일치' 가 그 화면에 쌓인다.
        부하는 괜찮다 — 분당 판단은 accuracy._busy 락으로 **전 시스템이
        한 번에 하나씩만** 게이트웨이를 치고, 폴링 루프가 시스템마다 시작
        시차를 둔다 (4단계 병렬 분석과는 다른 가벼운 호출).
      · watched — 화면이 실제로 보고 있을 때만 (게이트웨이가 힘들 때)
      · off     — 안 돌린다
    데이터 수집·케이스 감지는 이 설정과 무관하게 전부 돈다.
    """
    mode = _llm_mode(ctx["sys"])
    if mode == "off":
        return False
    if mode == "watched":
        return (time.time() - ctx["watched"]) < max(300, interval * 3)
    return True


def _llm_work(ctx: dict, cases: list, llm_on: bool, order: int) -> None:
    """LLM 관련 후속 작업 — 수집 루프 밖에서 돈다 (수집을 절대 막지 않게)."""
    try:
        if cases:
            _auto_judge(ctx, cases)
        if llm_on:
            _minute_llm(ctx, delay=order * 4.0)
    except Exception as e:
        print(f"[LLM:{ctx['sys']}] ⚠️ 후속 작업 예외: {type(e).__name__}: {e}")


def _poll_loop() -> None:
    """수집 루프 — 매 회 모든 시스템을 돌고, 주기는 config 에서 다시 읽는다."""
    _bootstrap_today()                 # ① 하루치 먼저 확보
    while True:                        # ② 이후 증분 수집
        interval = max(5, int(CFG.get("query", {}).get("poll_interval_s", 60)))

        def scan(iv):
            i, sys = iv
            ctx = get_ctx(sys)
            st = ctx["state"]
            t0 = time.time()
            try:
                res = scan_once(ctx["store"], cfg=ctx["cfg"])
                st.update(
                    last_scan=datetime.now().isoformat(),
                    latency_ms=int((time.time() - t0) * 1000),
                    connected=bool(res.get("ok")),
                    error=None if res.get("ok") else res.get("error"),
                    amos_warn=res.get("amos_warn"),
                    source=res.get("source"),
                    scans=st["scans"] + 1,
                    window=CFG.get("query", {}).get("window", "10m"),
                    last_rows=res.pop("all_rows", None) or st.get("last_rows"),
                    saved=res.get("saved"),
                    gap_min=res.get("gap_min"),
                    source_latest=res.get("latest"),   # 원본 CSV 의 최신 행 시각
                )
                sv = res.get("saved") or {}
                if st["scans"] == 1 or sv.get("written"):
                    print(f"[수집:{sys}] {res.get('rows')}행 조회 · "
                          f"신규 {sv.get('written', 0)}행 저장"
                          + (f" → {sv['files'][0]}" if sv.get("files") else "")
                          + f"  [{round(time.time() - t0, 1)}초{_wire(ctx)}]")
                if res.get("ok"):
                    # ★데이터가 우선이다. 선행 감지는 가벼우니 바로 하고,
                    #   LLM(케이스 자동 판단·분당 판단)은 **별도 스레드**로
                    #   떼어 보낸다. 여기서 직접 부르면 게이트웨이가 느린 날
                    #   그만큼 다음 시스템 수집이 통째로 밀린다 — 화면 데이터가
                    #   몇 분씩 뒤처지는 원인이었다.
                    _update_forecast(ctx)
                    _fetch_ml(ctx)
                    cases = res.get("cases") or []
                    llm_on = _llm_on(ctx, interval)
                    if cases or llm_on:
                        threading.Thread(
                            target=_llm_work, args=(ctx, cases, llm_on, i),
                            daemon=True).start()
            except Exception as e:
                st.update(connected=False, error=f"{type(e).__name__}: {e}",
                          last_scan=datetime.now().isoformat())

        # ★여섯 시스템을 **같이** 돌린다. 예전엔 한 줄로 세워서, 한 시스템이
        #   2초 걸리면 한 바퀴에 12초가 갔다 — 주기가 60초라도 화면에 도착하는
        #   시각이 그만큼 계단처럼 밀렸고, 게이트웨이가 느린 날엔 주기를 통째로
        #   넘겼다. 서로 다른 파일·다른 저장소라 기다릴 이유가 없다.
        _fan_out(scan, list(enumerate(systems())))

        # 과거 파일 정리 — 하루 한 번만 실제로 돈다 (보관 기간이 0 이면 안 돈다)
        try:
            _retention_tick()
        except Exception as e:                          # noqa: BLE001
            print(f"[정리] ⚠️ 건너뜀: {type(e).__name__}: {e}")

        # 주기를 나눠 자며 변경을 빠르게 반영
        slept = 0
        while slept < interval:
            time.sleep(min(2, interval - slept))
            slept += 2
            if int(CFG.get("query", {}).get("poll_interval_s", 60)) != interval:
                break                       # 주기가 바뀌면 즉시 다음 수집으로


def _minute_llm(ctx: dict, delay: float = 0.0) -> None:
    """1분 추론 + 검증 창이 찬 과거 행 채점 — 수집 루프를 막지 않게 별도 스레드.

    delay: 시스템별 시작 시차(초). 여섯 시스템이 같은 순간에 몰리면
    accuracy._busy 락(skip_if_busy)에 걸려 한 놈만 돌고 나머지는 그 주기를
    건너뛴다 — 시차를 두면 락이 비어 있을 때 도착해 매 주기 고르게 돈다.
    (건너뛰어도 다음 주기에 과거로 거슬러 메우므로 영구 공백은 없다.)
    """
    rows = ctx["state"].get("last_rows") or []
    cfg, sys = ctx["cfg"], ctx["sys"]

    def work():
        try:
            if delay > 0:
                time.sleep(delay)
            from accuracy import run_minute, verify_day
            out = run_minute(rows, cfg)
            if out and out.get("오류"):
                print(f"[LLM/1분:{sys}] ⚠️ {out['datetime']} — {out['오류']}")
            v = verify_day(datetime.now().strftime("%Y%m%d"), cfg)
            if v.get("scored"):
                print(f"[검증:{sys}] {v['scored']}건 채점 (대기 {v['waiting']}건)")
        except Exception as e:
            print(f"[LLM/1분:{sys}] ⚠️ 예외: {type(e).__name__}: {e}")

    threading.Thread(target=work, daemon=True).start()


_LEVEL_ORD = {"경계": 1, "위험": 2, "초위험": 3}


def _auto_judge(ctx: dict, case_ids: list[str]) -> None:
    """실시간 감지 즉시 LLM 이 판단하게 한다 (신규·등급상향 케이스만)."""
    store, cfg = ctx["store"], ctx["cfg"]
    lc = cfg.get("llm", {})
    if not (lc.get("enabled", True) and lc.get("auto_judge", True)):
        return
    floor = _LEVEL_ORD.get(lc.get("auto_judge_min_level", "경계"), 1)

    for cid in case_ids:
        c = store.by_id(cid)
        if not c or not c.pop("_new", False):
            continue
        if _LEVEL_ORD.get(c.get("level"), 0) < floor:
            continue

        def work(case_id=cid):
            try:
                from llm_client import judge_case
                cc = store.by_id(case_id)
                if not cc:
                    return
                res, err = judge_case(cc, cfg)
                if err:
                    print(f"[LLM:{ctx['sys']}] ⚠️ {case_id} 자동 판단 실패: {err}")
                    return
                cc["llm"] = {**res, "at": datetime.now().isoformat(), "auto": True}
                store.save()
                print(f"[LLM:{ctx['sys']}] 🤖 {case_id} 자동 판단 완료 "
                      f"(확신도 {res.get('확신도')}%)")
            except Exception as e:
                print(f"[LLM:{ctx['sys']}] ⚠️ {case_id} 자동 판단 예외: {e}")

        threading.Thread(target=work, daemon=True).start()
    store.save()


def _fetch_ml(ctx: dict) -> None:
    """ML 조기예측 CSV 받아 두기 — ALL 에서만, 수집 루프 안에서 가볍게.

    ★같은 주피터 서버·같은 비밀번호라 파일 하나 더 받는 것뿐이다. 실패해도
      관제는 그대로 돌아야 하므로 조용히 넘어가고 상태만 남긴다.
    """
    if str(ctx["sys"]).upper() != str(CFG.get("ml", {}).get("sys", "ALL")).upper():
        return
    st = ctx["state"]
    try:
        import ml_feed
        if not ml_feed.enabled(CFG):
            st["ml"] = {"enabled": False}
            return
        res = ml_feed.fetch_day(cfg=CFG)
        st["ml"] = {"enabled": True, "rows": res["rows"], "added": res["added"],
                    "error": res["error"] or None,
                    "at": datetime.now().isoformat()}
        if res["added"]:
            print(f"[ML:{ctx['sys']}] 예측 {res['added']}행 추가 (누적 {res['rows']})")
    except Exception as e:
        st["ml"] = {"enabled": True, "error": f"{type(e).__name__}: {e}"}


def _update_forecast(ctx: dict) -> None:
    """선행 감지 — 최근 추세로 '임계 돌파 N분 전' 을 미리 띄운다.

    수집 루프에서 매 회 부른다. 계산은 최근 20분 점수만 쓰는 가벼운 회귀라
    수집을 지연시키지 않는다. 실패해도 관제는 계속돼야 하므로 조용히 넘어간다.
    """
    st = ctx["state"]
    try:
        from forecast import predict
        fc = predict(st.get("last_rows") or [], ctx["cfg"])
        prev = st.get("forecast") or {}
        st["forecast"] = fc
        # 경보가 새로 뜬 순간만 콘솔에 한 줄 (매분 도배 방지)
        if fc.get("warn") and not prev.get("warn"):
            print(f"[선행:{ctx['sys']}] ⚠️ {fc['eta_min']}분 뒤 임계 돌파 예상 "
                  f"— 현재 {fc['current']}점, 분당 {fc['slope']:+.2f}점 "
                  f"(확신 {fc['confidence']}%)")
    except Exception as e:
        st["forecast"] = {"ok": False, "warn": False,
                          "reason": f"{type(e).__name__}: {e}"}


# ─────────────────────── 추이 그래프 지표 목록 ───────────────────────
# 화면 위 '추이 그래프'에서 고를 수 있는 지표. config.ui.strip_metrics 로 갈아끼운다.
# 라벨·raw 컬럼명은 m16_hub_skills/발동이벤트_요약.py 와 동일하게 맞춘다.
#   key = 값이 들어있는 CSV 컬럼 / raw = 화면에 보여줄 AMOS 실제 컬럼명
_STRIP_DEFAULT = [
    {"key": "unified_risk_score", "raw": "unified_risk_score", "label": "스코어",
     "unit": "점", "color": "#3DDBE8", "max": 100, "bands": True},
    {"key": "M16HUB_ra", "raw": "M16HUB.QUE.TIME.AVGTOTALTIME1MIN",
     "label": "M16HUB 반송시간", "unit": "분", "color": "#FF6B5E"},
    {"key": "M16HUB_rd_fab", "raw": "M16HUB.STRATE.ALL.FABSTORAGERATIO",
     "label": "M16HUB FAB저장율", "unit": "%", "color": "#FFA53D", "max": 100},
    # ★2026-08 — R-D 판정에서 제외됐다. 값은 계속 기록하므로 그래프에는
    #   남기되, 이름에 '기록용' 을 박아 원인으로 읽히지 않게 한다.
    {"key": "M16HUB_stb_util", "raw": "M16HUB.STRATE.STB.3F_STORAGE_UTIL",
     "label": "M16HUB STB저장율 (기록용·판정 미사용)", "unit": "%",
     "color": "#F2C94C", "max": 100, "record_only": True},
    {"key": "M16HUB_rev_count", "raw": "M16HUB.QUE.LFT.3F_LFT_REVERSALCNT",
     "label": "M16HUB 리프터 정체", "unit": "회", "color": "#FF6FB5"},
]


def _clean_metrics(ms) -> list[dict]:
    out = []
    for m in ms or []:
        if isinstance(m, dict) and m.get("key"):
            out.append({"key": m["key"], "raw": m.get("raw") or m["key"],
                        "label": m.get("label") or m["key"],
                        "unit": m.get("unit") or "", "color": m.get("color") or "#3DDBE8",
                        "max": m.get("max"), "bands": bool(m.get("bands"))})
    return out


def metric_groups(cfg: dict) -> list[dict]:
    """지표 묶음 목록. config.ui.metric_groups → 없으면 ui.strip_metrics → 없으면 기본값."""
    ui = cfg.get("ui") or {}
    gs = ui.get("metric_groups")
    if isinstance(gs, list) and gs:
        out = []
        for i, g in enumerate(gs):
            if not isinstance(g, dict):
                continue
            ms = _clean_metrics(g.get("metrics"))
            if ms:
                out.append({"id": g.get("id") or f"g{i}", "name": g.get("name") or f"묶음{i+1}",
                            "desc": g.get("desc") or "", "metrics": ms})
        if out:
            return out
    ms = _clean_metrics(ui.get("strip_metrics")) or _STRIP_DEFAULT
    return [{"id": "amos", "name": "지표", "desc": "", "metrics": ms}]


def _num(v):
    try:
        s = str(v).strip()
        return float(s) if s not in ("", "-", "None", "nan", "NaN") else None
    except (TypeError, ValueError):
        return None


# ────────────────────────────── 화면 ──────────────────────────────
@app.route("/")
def index():
    """오프닝(시스템 선택) → 관제 화면.

    ★늘 **물어보고** 쓰게 한다(no-cache). 관제 화면은 한 번 띄우면 며칠씩
      그대로 떠 있고, 그 사이 dashboard.html 을 새로 올려도 브라우저가 예전
      걸 계속 쓴다 — 오프닝을 새로 넣었는데 "안 나온다" 였던 그것이다.

    ★예전에는 no-store 로 아예 못 쓰게 막았는데, 그러면 **안 바뀌었어도
      매번 354KB 를 통째로** 다시 받는다. no-cache 는 '쓰지 마라' 가 아니라
      '쓰기 전에 물어봐라' 다 — 안 바뀌었으면 304 한 줄(0 바이트)로 끝나고,
      바뀌었으면 새로 받는다. 새 화면이 안 나오는 사고는 그대로 막으면서
      여는 값만 없앤다. 그래서 ETag 를 **지우지 않는다**.
      (바뀐 날 첫 한 번은 gzip 으로 354KB → 138KB 로 나간다.)
    """
    path = os.path.join(app.static_folder, "dashboard.html")
    try:
        st = os.stat(path)
    except OSError:
        return send_from_directory(app.static_folder, "dashboard.html")
    sig = (st.st_mtime_ns, st.st_size)
    e = _HTML_CACHE.get_or_build("dashboard", sig,
                                 lambda: open(path, "rb").read())
    code, body, hdr = http_cache.negotiate(
        e, request.headers.get("If-None-Match"),
        request.headers.get("Accept-Encoding"))
    hdr["Content-Type"] = "text/html; charset=utf-8"
    hdr["Cache-Control"] = "no-cache, must-revalidate"
    hdr["Pragma"] = "no-cache"
    return Response(body, status=code, headers=hdr)


@app.route("/docs/fab-score")
def doc_fab_score():
    """FAB 별 위험도 스코어 설명 문서.

    ★없으면 그 자리에서 만든다. 현장에 파일 하나 더 챙겨 가라고 하면
      결국 아무도 안 본다. 만들기 실패해도 관제 화면은 안 죽는다.
    """
    import fab_score_doc
    path = fab_score_doc.OUT
    if not os.path.isfile(path):
        try:
            os.makedirs(fab_score_doc.DOC_DIR, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(fab_score_doc.build(CFG))
        except Exception as e:
            return (f"<h3>문서를 만들지 못했습니다</h3><pre>{type(e).__name__}: {e}"
                    f"</pre><p>real_time_amhs 폴더에서 "
                    f"<code>python fab_score_doc.py</code> 를 직접 돌려 보십시오.</p>"), 500
    resp = send_from_directory(fab_score_doc.DOC_DIR, os.path.basename(path))
    resp.headers["Cache-Control"] = "no-store"
    return resp


# 아바타가 5초마다 두드린다 — 매번 하루 CSV(1440×143)를 다시 읽으면
# 수집·LLM 과 겹칠 때 응답이 늘어져 저쪽에서 '끊김' 으로 보인다.
# ★예전엔 3초 TTL 이었다. 그런데 이걸 부르는 아바타는 **10초마다** 묻는다 —
#   즉 캐시가 한 번도 안 맞고 매번 하루치를 다시 계산했다 (재 보니 220ms,
#   현장에서는 다른 일과 겹쳐 18~20초). 이제 시간이 아니라 **원본 파일 지문**
#   으로 잡는다: 파일이 그대로면 몇 분이 지나도 다시 안 만든다.
CMP_CACHE = http_cache.JsonCache("fab_compare")


@app.route("/api/fab/compare")
def api_fab_compare():
    """한 시각을 잡고 다섯 FAB 을 나란히 세운다.

    /api/fab/compare?day=20260811&at=2026-08-11 00:02   (at 없으면 마지막 행)

    ★전체(ALL) CSV 를 읽는다. FAB 분리 파일은 자기 영역 컬럼만 있어서
      비교가 안 된다 — 화면의 ?sys= 를 따라가면 안 되는 이유다.
    """
    try:
        import fab_score
        from store_csv import day_path, latest_day, list_days, read_day
        cfg = get_ctx("ALL")["cfg"]
        day = "".join(ch for ch in (request.args.get("day") or "") if ch.isdigit())[:8]
        at_q = (request.args.get("at") or "").strip()
        # ── 어느 날을 '현재 상태' 로 볼 것인가 ────────────────────────
        # ★예전: days[-1] — list_days 는 **최신순**이라 이건 '가장 오래된 날'
        #   이다. 파일이 0728·0819 두 개일 때 8월 25일에 7월 28일을 현재
        #   상태로 보여 줬다 (실제 증상: "왜 자꾸 7월 28일 보냐").
        # ★지금: **오늘**을 먼저 본다. 오늘 수집이 없으면 최근 날로 물러서되
        #   물러섰다는 사실을 응답에 남긴다 — 옛 데이터를 현재라고 내놓는
        #   것이 이 시스템에서 제일 위험하다.
        fallback = None
        if not day:
            today = datetime.now().strftime("%Y%m%d")
            has_today = any(d["day"] == today and d["rows"] > 0
                            for d in list_days(cfg))
            day = today
            if not has_today:
                newest = latest_day(cfg)
                if newest:
                    fallback = {"asked_day": today, "used_day": newest}
                    day = newest
        # 원본 지문 — ALL 파일 + FAB 다섯 파일 + 등급 컷. 이게 그대로면
        # 몇 번을 물어도 같은 답이므로 다시 만들지 않는다.
        try:
            _st = os.stat(day_path(day, cfg))
            sig = (_st.st_mtime_ns, _st.st_size, fab_score.files_sig(day, cfg),
                   json.dumps(cfg.get("grade") or {}, sort_keys=True, ensure_ascii=False),
                   at_q)
        except OSError:
            sig = None                      # 원본을 못 읽었다 — 캐시하지 않는다

        def _build():
            rows = read_day(day, cfg)
            # day 를 넘겨야 FAB 분리 파일(data/{FAB}/{day}_TOTAL.CSV)의
            # area_score 를 그 FAB 점수로 쓴다
            out = fab_score.compare(rows, parse_dt(at_q or None), cfg, day=day)
            out["day"] = day
            if fallback:
                out["fallback_day"] = fallback
                out["warn"] = ("오늘({}) 수집 데이터가 없어 {} 자료를 보고 있습니다 "
                               "— 실시간이 아닙니다. 수집이 멈췄는지 확인하세요."
                               .format(fallback["asked_day"], fallback["used_day"]))
            return out

        return _cached_json(CMP_CACHE, f"{day}|{at_q}", sig, _build)
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500


TREND_CACHE = http_cache.JsonCache("fab_trend")


@app.route("/api/fab/trend")
def api_fab_trend():
    """UI대쉬보드 오른쪽 상황판 — FAB 마다 최근 N분 area_score 추이 + 지금 걸린 룰 한 줄.

    /api/fab/trend?minutes=60
    고객: "각 FAB 별 숫자 · 경계·위험·초위험 알리는 내용 팻말 그리고 각각 그래프가
    보이면 … 옆에 뭔가를 볼 수 있는 게 나와야 돼 · 간소하고 명확하게 · 실시간".
    ★FAB 분리 파일(data/{FAB}/…)을 읽는다 — 그 FAB 자기 점수(area_score)라 패널
      숫자(/api/fab/compare)와 같은 원본이다. 점수를 다시 계산하지 않는다.
    ★등급 이름·설명은 config.grade 의 것을 그대로 준다('확인필요'·'조치필요' …).
      화면은 패널과 같은 등급(compare 의 level)에 이 설명을 붙인다.
    ★오늘 파일이 없으면 가장 최근 날로 물러서되 그 날짜를 같이 준다 — 옛 자료를
      실시간이라고 내놓으면 안 된다.
    """
    try:
        minutes = max(10, min(360, int(request.args.get("minutes", 60))))
    except ValueError:
        minutes = 60
    try:
        from sentinel import _row_dt, _score
        try:
            from sentinel import fab_reason        # sentinel.py 가 옛것이면 걸린 룰만 빈다
        except ImportError:
            fab_reason = None
        from store_csv import latest_day, list_days, read_day
        today = datetime.now().strftime("%Y%m%d")
        plan = []
        for f in systems():
            if f == "ALL":
                continue
            cfg = get_ctx(f)["cfg"]
            has = any(d["day"] == today and d["rows"] > 0 for d in list_days(cfg))
            plan.append((f, today if has else (latest_day(cfg) or today), cfg))
        sig = tuple((f, d, _days_sig({d}, c)) for f, d, c in plan)
        if any(s is None for _f, _d, s in sig):
            sig = None                       # 원본을 못 읽었다 — 캐시하지 않는다
        g = CFG.get("grade") or {}
        sev = {"정상": "정상"}
        sev.update({b.get("level"): b.get("severity") or b.get("level")
                    for b in (g.get("bands") or []) if b.get("level")})

        def _build():
            out = []
            for f, day, cfg in plan:
                seq = []
                for r in read_day(day, cfg):
                    t = _row_dt(r)
                    if t is not None:
                        seq.append((t, r))
                if not seq:
                    out.append({"fab": f, "day": day, "points": []})
                    continue
                seq.sort(key=lambda x: x[0])
                t_end, last = seq[-1]
                t0 = t_end - timedelta(minutes=minutes)
                out.append({
                    "fab": f, "day": day, "at": t_end.strftime("%Y-%m-%d %H:%M"),
                    "score": round(_score(last), 1),
                    "why": (fab_reason(str(last.get("reason") or ""), f, last)
                            if fab_reason else ""),
                    "points": [[t.strftime("%H:%M"), round(_score(r), 1)]
                               for t, r in seq if t > t0],
                })
            return {"ok": True, "minutes": minutes, "severity": sev, "fabs": out}

        return _cached_json(TREND_CACHE, str(minutes), sig, _build)
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/fab/why")
def api_fab_why():
    """**이 점수는 어디서 온 숫자인가** — 한 FAB 을 놓고 끝까지 따진다.

    /api/fab/why?sys=M14[&day=20260831&at=2026-08-31 10:35]

    ★두 가지를 같이 답한다.
      ① **왜 이 점수가 나왔나** — 무엇이 몇 점씩 더해졌는지, 그때 실제 값이
         얼마였는지. "70 까지 올라갔는데 현장은 멀쩡했다. 왜인지 모르겠다"
         의 답은 여기 있다 — 사람이 용량을 내린 것도, 느슨한 조건 하나가
         걸린 것도, 같은 사건을 두 번 센 것도 다 점수로 올라온다.
      ② 이 숫자가 어디서 온 것인가. 갈릴 수 있는 자리가 셋이다:
        ① 어느 파일의 어느 컬럼을 읽었나 (FAB 분리 파일 vs 되계산)
        ② 지금 이 시스템의 등급 컷이 얼마인가 (정책 탭 · 시스템별)
        ③ 예측기가 적어 둔 등급과 지금 정책이 다른가 (등급은 예측기 값을
         그대로 쓴다 — 다르다는 사실만 알려 준다)
      셋 다 한 화면에 적어 준다. 숫자가 다르면 ①, 등급이 다르면 ②나 ③이다.
    """
    try:
        import fab_score
        from store_csv import latest_day, read_day
        cfg = get_ctx("ALL")["cfg"]
        want = (request.args.get("sys") or "").strip().upper()
        day = "".join(ch for ch in (request.args.get("day") or "")
                      if ch.isdigit())[:8] or datetime.now().strftime("%Y%m%d")
        rows = read_day(day, cfg)
        if not rows:
            day = latest_day(cfg) or day
            rows = read_day(day, cfg)
        at = parse_dt(request.args.get("at") or None)
        out = fab_score.compare(rows, at, cfg, day=day)
        _dt, raw_row = fab_score.row_at(rows, at)
        if not out.get("ok"):
            return jsonify({"ok": False, "day": day, "error": out.get("error")})
        got = [r for r in (out.get("rows") or [])
               if not want or str(r.get("fab") or "").upper() == want]
        if not got:
            return jsonify({"ok": False, "error": f"{want} 를 못 찾았습니다",
                            "systems": [r.get("fab") for r in out.get("rows") or []]})
        lines, detail, detail_extra = [], [], {}
        for r in got:
            f = r.get("fab")
            cuts = r.get("cuts") or out.get("cuts") or {}
            src = ("FAB 분리 파일 data/{}/{}_TOTAL.CSV 의 {} 컬럼"
                   .format(f, day, r.get("score_col"))
                   if r.get("source") == "fab_file"
                   else "통합 파일에서 되계산 ({})".format(r.get("score_col")))
            lines.append(
                "{} : {}점 → {}   (경계 {} · 위험 {} · 초위험 {})   ← {}"
                .format(f, r.get("score"), r.get("level"), cuts.get("warn"),
                        cuts.get("danger"), cuts.get("critical"), src))
            if r.get("level_note"):
                lines.append("      ※ {}".format(r["level_note"]))
            if r.get("file_value") is not None:
                lines.append("      ※ 분리 파일에는 {} = {} 가 있습니다 "
                             "(area_score 가 아니라서 점수로 쓰지 않았습니다)"
                             .format(r.get("file_col"), r.get("file_value")))
            # ── 왜 이 점수인가 — 무엇이 몇 점씩 더해졌나 ──────────────
            ex = fab_score.explain(raw_row, f, cfg) if raw_row else None
            if ex:
                lines.append("      계산  {}".format(ex["math"]))
                if ex["parts"]:
                    lines.append("      무엇이 더해졌나 (합 {:g}점)"
                                 .format(ex["raw"]))
                for pt in ex["parts"]:
                    v = "  ".join(
                        "{} = {}{} ({} {}{})".format(
                            x["amos"], x["value"], x["unit"],
                            "임계", x["thr"],
                            " 이상" if str(x["op"]).startswith(">") else " 이하")
                        for x in pt["values"]) or pt["when"]
                    lines.append("        {:>6.1f}점  {:<12} {}"
                                 .format(pt["pts"], pt["label"], v))
                for n in ex["notes"]:
                    lines.append("      ※ {}".format(n))
                detail_extra[f] = ex
            detail.append({
                "fab": f, "score": r.get("score"), "level": r.get("level"),
                "cuts": cuts, "source": r.get("source"),
                "score_col": r.get("score_col"), "measures": r.get("measures"),
                "file_level": r.get("file_level") or "",
                "policy_level": r.get("policy_level") or "",
                "level_note": r.get("level_note") or "",
                "file_value": r.get("file_value"), "file_col": r.get("file_col"),
                "area": r.get("area"), "saturated": r.get("saturated"),
                "why": detail_extra.get(f),
            })
        return jsonify({
            "ok": True, "day": day, "at": out.get("at"),
            "text": "\n".join(lines),
            "rows": detail,
            "help": ("점수가 왜 이만큼인지는 '무엇이 더해졌나' 를 보세요 — "
                     "사람이 한 일(운영자 용량변경)이나 느슨한 조건 하나로 "
                     "오른 것이면 현장이 멀쩡한 게 맞습니다. "
                     "숫자 자체가 현장과 다르면 ← 뒤의 '어디서 읽었나' 를, "
                     "숫자는 같은데 등급이 다르면 괄호 안의 컷(정책 탭)을 "
                     "보세요."),
        })
    except Exception as e:                              # noqa: BLE001
        import traceback; traceback.print_exc()
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/fab/columns")
def api_fab_columns():
    """FAB 별로 '실제 보고 있는 컬럼' 정의 — 룰·AMOS 컬럼·임계·CSV 컬럼.

    화면과 문서가 같은 곳을 보게 하려고 API 로도 낸다. 임계를 config 에서
    고치면 여기·문서·비교 계산이 한꺼번에 따라간다.
    """
    try:
        import fab_score
        cfg = get_ctx("ALL")["cfg"]
        warn, danger, crit = grade_cuts(cfg)

        def one(s):
            """★ALL 도 넣는다 — 화면이 여섯 시스템인데 다섯만 주면 안 된다.
            ALL 은 영역이 아니라서 영역 룰·단독 상한이 없지만, 융합 단계에서
            보는 컬럼(흐름 노드 10개 + 집계)은 분명히 있다."""
            d = {"watch": fab_score.watch(s, cfg),
                 "rules": fab_score.rules_of(s),
                 "screen": fab_score.screen_metrics(s, cfg),
                 "join": fab_score.join_columns(s, cfg),
                 "is_all": s == "ALL"}
            if s != "ALL":
                d.update({"weight": fab_score.area_weight(s, cfg),
                          "max_area": fab_score.max_area(s, cfg),
                          "solo": {m: fab_score.solo_ceiling(s, cfg, m)
                                   for m in ("typical", "max")}})
            return d

        return jsonify({
            "ok": True, "rules": fab_score.RULES, "all_rules": fab_score.ALL_RULES,
            "area_cap": fab_score.AREA_CAP, "raw_full": fab_score.RAW_FULL,
            "cuts": {"warn": warn, "danger": danger, "critical": crit},
            "systems": ["ALL"] + fab_score.fabs(cfg),
            "fabs": {s: one(s) for s in ["ALL"] + fab_score.fabs(cfg)},
            "doc": "/docs/fab-score",
        })
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/version")
def version():
    """지금 서버가 **어느 파일**을 내보내고 있는지 — 화면이 옛날 것 같을 때
    여기부터 본다. 브라우저 캐시 문제인지, 파일을 안 덮어쓴 것인지 갈린다."""
    p = os.path.join(app.static_folder, "dashboard.html")
    try:
        st = os.stat(p)
        with open(p, encoding="utf-8") as f:
            body = f.read()
    except OSError as e:
        return jsonify({"ok": False, "error": str(e), "path": p})
    return jsonify({
        "ok": True,
        "path": p,
        "bytes": st.st_size,
        "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        "오프닝화면": "const SYSTEMS" in body,      # 있으면 새 파일
        "AMOS표시등": "ch-amos" in body,            # 있으면 옛날 파일
        # 정책 탭 카드가 실제로 이 파일에 들어 있는지 — "정책에 안 보인다" 확인용
        "정책_스코어카드": 'id="sprows"' in body,
        "정책_LLM카드": 'id="lprows"' in body,
        "정책_재시도": "apiRetry" in body,
        # 서버 쪽 엔드포인트도 같이 (파일만 새것이고 서버가 옛날일 수 있다)
        "API_score_policy": any(str(r) == "/api/score_policy"
                                for r in app.url_map.iter_rules()),
        "API_llm_policy": any(str(r) == "/api/llm_policy"
                              for r in app.url_map.iter_rules()),
        "정책_보관기간카드": 'id="rtrow"' in body,
        "API_retention": any(str(r) == "/api/retention"
                             for r in app.url_map.iter_rules()),
        "업데이트내역탭": 'id="tab-updates"' in body,
        "API_updates": any(str(r) == "/api/updates"
                           for r in app.url_map.iter_rules()),
    })


@app.route("/favicon.ico")
def favicon():
    return ("", 204)


# ────────────────────────────── 상태 ──────────────────────────────
@app.route("/api/status")
def api_status():
    C = rctx()
    return jsonify({
        "state": C["state"],
        "alarm_floor": alarm_floor(C["cfg"]),
        "poll_interval_s": C["cfg"].get("query", {}).get("poll_interval_s", 30),
        "offline": os.getenv("LP_OFFLINE") == "1",
        "table": C["cfg"].get("table_name"),
        "base": C["cfg"].get("logpresso_base"),
        "model": C["cfg"].get("llm", {}).get("model"),
        "policy": C["cfg"].get("policy", {}),
        "evaluation": C["cfg"].get("evaluation", {}),
        "server_time": datetime.now().isoformat(),
        "sys": C["sys"],
        "systems": systems(),
        # ★설정상의 출처. state.source 는 '마지막 수집이 성공했을 때' 채워지므로,
        #   실패하면 비어서 화면이 '로그프레소' 로 떨어져 거짓말을 했다.
        "source_mode": __import__("sentinel").source_mode(C["cfg"]),
        # 이 시스템의 등급 컷 — 화면(gradeOf·추이 밴드·범례)이 이 값으로 그린다
        "cuts": dict(zip(("warn", "danger", "critical"), grade_cuts(C["cfg"]))),
        # 등급 카운터(알람) 설정 — 화면이 배지와 말풍선을 이 값으로 그린다
        "alarm": alarm_count.policy(C["cfg"]),
    })


@app.route("/api/ping")
def api_ping():
    ok, msg = ping()
    return jsonify({"ok": ok, "message": msg, "base": CFG.get("logpresso_base")})


def _persist_llm_policy() -> str:
    """지금 메모리의 분당 판단 설정을 config.json 에 그대로 적는다 → 오류 문자열.

    파일을 새로 읽어 llm 블록만 갈아끼우고 원자적으로 교체한다 — 파일에
    있는 다른 설정(사용자가 손으로 고친 것 포함)은 건드리지 않는다.
    """
    from lp_client import CONFIG_PATH
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
            disk = json.load(f)
        pm_mem = (CFG.get("llm", {}) or {}).get("per_minute") or {}
        pm = disk.setdefault("llm", {}).setdefault("per_minute", {})
        for k in ("enabled", "every_min", "max_per_cycle", "by_sys"):
            if k in pm_mem:
                pm[k] = pm_mem[k]
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(disk, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, CONFIG_PATH)
        return ""
    except Exception as e:
        return f"{type(e).__name__}: {e}"


def _persist_score_policy() -> str:
    """메모리의 시스템별 등급 컷(grade.by_sys)을 config.json 에 적는다 → 오류."""
    from lp_client import CONFIG_PATH
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
            disk = json.load(f)
        mem = (CFG.get("grade", {}) or {}).get("by_sys")
        g = disk.setdefault("grade", {})
        if mem:
            g["by_sys"] = mem
        else:
            g.pop("by_sys", None)
        # 등급 카운터(알람) — 컷과 같은 파일·같은 길로 적는다. 따로 두면
        # 한쪽만 저장되는 사고가 난다 (_apply_cuts 주석과 같은 뜻).
        for _k in ("alarm", "alarm_by_sys"):
            _v = (CFG.get("grade", {}) or {}).get(_k)
            if _v:
                g[_k] = _v
            else:
                g.pop(_k, None)
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(disk, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, CONFIG_PATH)
        return ""
    except Exception as e:
        return f"{type(e).__name__}: {e}"


# ─────────────────────── LLM 판단 모델 고르기 ───────────────────────
# ★2026-09-18 현장: config 의 모델 이름이 게이트웨이에서 내려가(혹은 이름이
#   바뀌어) 매분 이렇게 찍혔다 —
#     [LLM/1분:M14] ⚠️ HTTP 400: Invalid model name passed in model=...
#   하루 종일 'LLM 판단 일치' 가 통째로 비었는데, 화면에서는 무슨 이름을 써야
#   하는지도, 어디를 고쳐야 하는지도 알 수 없었다(config.json 을 직접 고치고
#   서버를 재시작해야 했다). 게이트웨이가 /v1/models 로 알려 주므로 그대로
#   보여 주고 고르게 한다. 고른 값은 config.json 에 적어 재시작해도 남는다.
def _persist_llm_model(model: str | None = None, roles: dict | None = None,
                       enabled: bool | None = None,
                       roles_on: dict | None = None) -> str:
    """고른 모델을 config.json 에 적는다 → 오류 글.

    · model    — llm.model (판단·리포트에 쓰는 한 개)
    · roles    — llm.analysis.roles.{p1,p2,p3,final}.model (4-LLM 파이프라인)
    · enabled  — llm.enabled (판단 모델 자체를 안 씀)
    · roles_on — llm.analysis.roles.{id}.enabled (그 단계만 안 씀)
    전부 같은 파일이라 **한 번에 읽고 한 번에 쓴다**. 따로 쓰면 뒤에 쓴 쪽이
    앞의 것을 덮는다 (실제로 그런 사고가 흔하다).
    """
    from lp_client import CONFIG_PATH
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
            disk = json.load(f)
        lc = disk.setdefault("llm", {})
        if model:
            lc["model"] = model
        if enabled is not None:
            lc["enabled"] = bool(enabled)
        if roles:
            rr = lc.setdefault("analysis", {}).setdefault("roles", {})
            for sid, m in roles.items():
                # ★통째로 갈아끼우지 않는다 — 각 단계의 _doc 설명이 날아간다
                rr.setdefault(sid, {})["model"] = m
        if roles_on:
            rr = lc.setdefault("analysis", {}).setdefault("roles", {})
            for sid, on in roles_on.items():
                rr.setdefault(sid, {})["enabled"] = bool(on)
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(disk, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, CONFIG_PATH)
        return ""
    except Exception as e:                              # noqa: BLE001
        return f"{type(e).__name__}: {e}"


def analysis_OFF() -> str:
    import analysis
    return analysis.OFF


def _apply_roles_on(roles_on: dict) -> None:
    """단계별 '사용 안 함' 을 메모리에 바로 적용 — 다음 분석부터 그대로 돈다."""
    if not roles_on:
        return
    rr = (CFG.setdefault("llm", {}).setdefault("analysis", {})
          .setdefault("roles", {}))
    for sid, on in roles_on.items():
        rr.setdefault(sid, {})["enabled"] = bool(on)


def _apply_roles(roles: dict) -> None:
    """메모리 CFG 에 단계 모델을 넣는다 (다음 분석부터 이 모델로 나간다)."""
    a = CFG.setdefault("llm", {}).setdefault("analysis", {})
    rr = a.setdefault("roles", {})
    for sid, m in roles.items():
        rr.setdefault(sid, {})["model"] = m


@app.route("/api/llm/model", methods=["GET", "POST"])
def api_llm_model():
    """LLM 판단에 쓸 모델 — 지금 값 + 게이트웨이가 받아 주는 목록 / 바꾸기.

    GET  → {"model", "url", "items":[{id, owned_by}], "error", "ok_now"}
    POST {"model": "이름", "save"?: true, "test"?: true}
      · 메모리에 즉시 적용 (다음 분 판단부터 이 모델로 나간다)
      · save=true 면 config.json 에도 적어 재시작해도 남는다
      · test=true 면 바꾸기 전에 한 번 불러 본다 — 400 이면 안 바꾼다
        (틀린 이름을 저장해 두면 또 하루를 날린다)
    """
    import llm_client
    lc = CFG.setdefault("llm", {})
    if request.method == "GET":
        items, err = llm_client.list_models(CFG,
                                            force=request.args.get("force") == "1")
        cur = lc.get("model") or ""
        names = [m["id"] for m in items]
        # 4-LLM 파이프라인 단계별 모델 (분석 탭). 단계 정의는 analysis.STAGES 에 있다
        import analysis
        roles = []
        for sid, st in analysis.STAGES.items():
            m = analysis._stage_model(CFG, sid)
            on = analysis._stage_on({**CFG, "llm": {**lc, "enabled": True}}, sid)
            roles.append({"id": sid, "name": st["name"], "icon": st["icon"],
                          "model": m,
                          # 이 단계에 LLM 을 쓰나 (고객: "1차,2차,3차,최종도 마찬가지")
                          "enabled": on,
                          # 그 모델이 지금 게이트웨이에 있나 — 없으면 화면이 빨갛게
                          # ★안 쓰는 단계는 따지지 않는다 — 없는 이름이어도 상관없다
                          "ok": None if not on else ((m in names) if names else None)})
        return jsonify({
            "model": cur, "url": lc.get("url") or "",
            "models_url": llm_client.models_url(CFG),
            "items": items, "error": err,
            # 화면 select 가 이 값을 '사용 안 함' 칸으로 쓴다 (서버·화면이 같은 말)
            "off_value": analysis.OFF,
            # 지금 값이 목록에 있나 — 없으면 화면이 빨갛게 알려 준다
            "ok_now": (cur in names) if names else None,
            "enabled": bool(lc.get("enabled", True)),
            "roles": roles,
        })

    b = request.get_json(silent=True) or {}

    # ── 4-LLM 파이프라인 단계별 모델만 바꾸는 요청 ──────────────────
    if b.get("roles") is not None:
        import analysis
        raw = b.get("roles") or {}
        if not isinstance(raw, dict):
            return jsonify({"error": "roles 는 {단계: 모델이름} 이어야 합니다"}), 400
        roles, roles_on = {}, {}
        for sid, m in raw.items():
            if sid not in analysis.STAGES:
                return jsonify({"error": f"모르는 단계: {sid}"}), 400
            m = str(m or "").strip()
            # ★'(사용안함)' 은 그 단계를 끄라는 뜻이다 (고객: "1차,2차,3차,최종도
            #   마찬가지야"). 모델 이름은 건드리지 않는다 — 다시 켤 때 쓰던 것이
            #   그대로 돌아온다.
            if m == analysis.OFF:
                roles_on[sid] = False
                continue
            if not m:
                return jsonify({"error": f"{sid} 모델이 비었습니다"}), 400
            if len(m) > 200:
                return jsonify({"error": f"{sid} 모델 이름이 너무 깁니다"}), 400
            roles[sid] = m
            roles_on[sid] = True
        if not roles and not roles_on:
            return jsonify({"error": "바꿀 단계가 없습니다"}), 400
        prev = {sid: analysis._stage_model(CFG, sid) for sid in roles}
        _apply_roles(roles)
        _apply_roles_on(roles_on)
        if b.get("test"):
            # ★서로 다른 모델을 **각각** 불러 본다. 하나만 확인하면 나머지가
            #   없어진 이름이어도 그대로 저장돼 그 단계만 매번 실패한다.
            #   ★끈 단계는 부르지 않는다 — 안 쓸 모델을 시험할 까닭이 없다.
            for sid, m in roles.items():
                _, err = llm_client.chat([{"role": "user", "content": "핑"}],
                                         {**CFG, "llm": {**lc, "model": m}}, max_tokens=8)
                if err:
                    _apply_roles(prev)      # 하나라도 안 되면 전부 되돌린다
                    return jsonify({"error": f"{analysis.STAGES[sid]['name']} — "
                                             f"{m} 로는 호출이 안 됩니다: {err}",
                                    "stage": sid, "applied": False}), 400
        saved, serr = False, ""
        if b.get("save", True):
            serr = _persist_llm_model(roles=roles, roles_on=roles_on)
            saved = not serr
        print("[LLM] 파이프라인 모델 → "
              + " · ".join([f"{k}={v}" for k, v in roles.items()]
                           + [f"{k}=사용안함" for k, on in roles_on.items() if not on])
              + (" · 저장됨" if saved else "")
              + (f" · 저장 실패: {serr}" if serr else ""))
        out = {"roles": roles, "roles_on": roles_on, "applied": True, "saved": saved}
        if serr:
            out["error"] = f"config.json 저장 실패 — {serr} (메모리에는 적용됨)"
            return jsonify(out), 500
        return jsonify(out)

    model = str(b.get("model") or "").strip()
    # ★'(사용안함)' 은 LLM 판단을 안 쓴다는 뜻이다 (고객: "정책에서 llm판단 모델
    #   사용안함 이라고 선택할수 있게해줘"). llm.enabled=false 는 llm_client.chat
    #   이 이미 보고 있던 스위치라, 분당 판단·리포트·4단계가 한꺼번에 멎는다.
    #   모델 이름은 그대로 둔다 — 다시 켤 때 쓰던 것이 돌아온다.
    if model == __import__("analysis").OFF:
        lc["enabled"] = False
        saved, serr = False, ""
        if b.get("save", True):
            serr = _persist_llm_model(enabled=False)
            saved = not serr
        print("[LLM] 판단 모델 → 사용안함" + (" · 저장됨" if saved else "")
              + (f" · 저장 실패: {serr}" if serr else ""))
        out = {"model": analysis_OFF(), "enabled": False, "applied": True, "saved": saved}
        if serr:
            out["error"] = f"config.json 저장 실패 — {serr} (메모리에는 적용됨)"
            return jsonify(out), 500
        return jsonify(out)
    if not model:
        return jsonify({"error": "model 이 비었습니다"}), 400
    if len(model) > 200:
        return jsonify({"error": "model 이름이 너무 깁니다"}), 400

    # 이름을 골랐다 = 다시 켠다
    lc["enabled"] = True
    prev = lc.get("model")
    lc["model"] = model                     # 먼저 메모리에 (시험도 이 값으로)
    if b.get("test"):
        txt, err = llm_client.chat(
            [{"role": "user", "content": "핑"}], CFG, max_tokens=8)
        if err:
            lc["model"] = prev              # ★되돌린다 — 틀린 이름을 남기지 않는다
            return jsonify({"error": f"이 모델로는 호출이 안 됩니다 — {err}",
                            "model": prev, "applied": False}), 400

    saved, serr = False, ""
    if b.get("save", True):
        serr = _persist_llm_model(model=model, enabled=True)
        saved = not serr
    print(f"[LLM] 모델 → {model}" + (" · 저장됨" if saved else "")
          + (f" · 저장 실패: {serr}" if serr else ""))
    out = {"model": model, "enabled": True, "applied": True, "saved": saved}
    if serr:
        out["error"] = f"config.json 저장 실패 — {serr} (메모리에는 적용됨)"
        return jsonify(out), 500
    return jsonify(out)


@app.route("/api/score_policy", methods=["GET", "POST"])
def api_score_policy():
    """스코어 등급 컷 — **시스템 6개 각각**. FAB 마다 점수 분포가 다르다.

    POST {"by_sys": {"M14": {"warn": 55, "danger": 70, "critical": 85}
                     또는 null(기본으로 되돌리기), …},
          "save"?: true}
    warn=경계 시작 / danger=위험 시작 / critical=초위험 시작.
    1 ≤ warn < danger < critical ≤ 100. warn 미만은 정상(무알람).
    ★메모리에 먼저 적용(등급·알람·케이스·그래프가 즉시 이 컷으로 계산)하고,
      save=true 면 config.json 에도 적는다.
    """
    g = CFG.setdefault("grade", {})
    saved = None
    if request.method == "POST":
        b = request.get_json(silent=True) or {}
        if "by_sys" in b:
            if not isinstance(b["by_sys"], dict):
                return jsonify({"error": "by_sys 는 {시스템: 설정|null} 객체"}), 400
            known = set(systems())
            sets, resets = {}, []
            for s_, row in b["by_sys"].items():
                s_ = str(s_).upper()
                if s_ not in known:
                    return jsonify({"error": f"모르는 시스템 {s_} (가능: {sorted(known)})"}), 400
                if row is None:
                    resets.append(s_)
                    continue
                try:
                    w = int(row.get("warn")); d_ = int(row.get("danger")); c = int(row.get("critical"))
                except (TypeError, ValueError):
                    return jsonify({"error": f"{s_}: warn/danger/critical 은 정수(점)"}), 400
                if not (1 <= w < d_ < c <= 100):
                    return jsonify({"error": f"{s_}: 1 ≤ 경계({w}) < 위험({d_}) < "
                                             f"초위험({c}) ≤ 100 이어야 합니다"}), 400
                sets[s_] = {"warn": w, "danger": d_, "critical": c}
            # ★객체 갈아끼우기 금지 — sys_cfg 뷰들이 grade 블록을 공유한다
            by = g.setdefault("by_sys", {})
            for s_ in resets:
                by.pop(s_, None)
            by.update(sets)
            if not by:
                g.pop("by_sys", None)
        # ── 등급 카운터(알람) — **시스템 6개 각각**. 등급 컷의 by_sys 와 같은 모양
        #    {"alarm_by_sys": {"M14": {...} | null(기본으로 되돌리기), …}}
        if "alarm_by_sys" in b:
            rows_ = b["alarm_by_sys"]
            if not isinstance(rows_, dict):
                return jsonify({"error": "alarm_by_sys 는 {시스템: 설정|null} 객체"}), 400
            known = set(systems())
            sets_, resets_ = {}, []
            for s_, row in rows_.items():
                s_ = str(s_).upper()
                if s_ not in known:
                    return jsonify({"error": f"모르는 시스템 {s_} (가능: {sorted(known)})"}), 400
                if row is None:
                    resets_.append(s_)
                    continue
                if not isinstance(row, dict):
                    return jsonify({"error": f"{s_}: 알람 설정은 객체"}), 400
                new_ = dict(alarm_count.policy(CFG, s_))
                if "enabled" in row:
                    new_["enabled"] = bool(row["enabled"])
                for k in ("window_min", *alarm_count.KEYS):
                    if k not in row:
                        continue
                    try:
                        n = int(row[k])
                    except (TypeError, ValueError):
                        return jsonify({"error": f"{s_}: 알람 {k} 는 정수"}), 400
                    lo, hi = alarm_count.LIMITS[k]
                    if not (lo <= n <= hi):
                        return jsonify({"error": f"{s_}: 알람 {k} 는 {lo}~{hi}"}), 400
                    new_[k] = n
                sets_[s_] = new_
            # ★객체 갈아끼우기 금지 — sys_cfg 뷰들이 grade 블록을 공유한다
            by_a = g.setdefault("alarm_by_sys", {})
            for s_ in resets_:
                by_a.pop(s_, None)
            for s_, v in sets_.items():
                by_a.setdefault(s_, {}).update(v)
            if not by_a:
                g.pop("alarm_by_sys", None)
        if b.get("save"):
            err = _persist_score_policy()
            saved = not err
            if err:
                return jsonify({"error": f"config.json 저장 실패 — {err} "
                                         f"(메모리에는 적용됨)", "applied": True}), 500
        rows = " · ".join(f"{s_}={'/'.join(map(str, grade_cuts(sys_cfg(CFG, s_))))}"
                          for s_ in systems())
        print(f"[정책] 스코어 컷 → {rows}" + (" · 저장됨" if saved else ""))
        _al = " · ".join(
            f"{a['sys']}={'' if a['enabled'] else '끔/'}"
            f"{a['window_min']}분:{a['warn']}/{a['danger']}/{a['critical']}"
            for a in alarm_count.table(CFG, systems()))
        print(f"[정책] 등급 카운터 → {_al}")
    by = g.get("by_sys") or {}
    out = []
    for s_ in systems():
        w, d_, c = grade_cuts(sys_cfg(CFG, s_))
        out.append({"sys": s_, "warn": w, "danger": d_, "critical": c,
                    "custom": s_ in by})
    return jsonify({"systems": out, "saved": saved,
                    # 등급 카운터 — 시스템 6개 각각 (컷의 systems 와 같은 모양)
                    "alarm_systems": alarm_count.table(CFG, systems()),
                    "alarm_default": dict(alarm_count.DEFAULTS)})


def _apply_cuts(sets: dict) -> str:
    """등급 컷을 메모리 + config.json 에 적는다 → 오류 글 (없으면 빈 글).

    ★화면의 '수동 변경' 과 LLM 자동 조정이 **같은 길**로 나가야 한다.
      두 길이 생기면 한쪽만 고쳐지는 사고가 난다 (메모리엔 반영됐는데
      config.json 엔 안 적혀 재시작하면 되돌아가는 식).
    """
    g = CFG.setdefault("grade", {})
    for s_, row in sets.items():
        w, d_, c = int(row["warn"]), int(row["danger"]), int(row["critical"])
        if not (1 <= w < d_ < c <= 100):
            return f"{s_}: 1 ≤ 경계({w}) < 위험({d_}) < 초위험({c}) ≤ 100"
    # ★객체 갈아끼우기 금지 — sys_cfg 뷰들이 grade 블록을 공유한다
    by = g.setdefault("by_sys", {})
    by.update({s_: {"warn": int(r["warn"]), "danger": int(r["danger"]),
                    "critical": int(r["critical"])} for s_, r in sets.items()})
    return _persist_score_policy()


@app.route("/api/score_policy/tune", methods=["GET", "POST"])
def api_score_tune():
    """등급 컷 자동 조정 — 최근 8시간 분포를 LLM 이 보고 유지/변경을 정한다.

    GET  → 설정 + 최근 기록 (변경 로그)
    POST → 지금 한 번 돌린다. body {hours?, apply?:true, by?}
           apply=false 면 **제안만** 보고 안 바꾼다 (눌러 보기 전에 확인용).
    """
    import score_tune
    tc = score_tune.cfg_of(CFG)
    if request.method == "GET":
        try:
            lim = max(1, min(200, int(request.args.get("limit", 30))))
        except ValueError:
            lim = 30
        return jsonify({
            "enabled": bool(tc["enabled"]), "hours": tc["hours"], "at": tc["at"],
            "max_step": tc["max_step"], "min_rows": tc["min_rows"],
            "shifts": [f"{a:02d}~{b:02d}" for a, b in score_tune.SHIFTS],
            "next": _tune_next_text(tc),
            "running": TUNE["running"],
            "model": tc.get("model") or "",
            # ★무엇을 물어보고 있는지 화면에서 볼 수 있어야 한다.
            #   지시문만으로는 부족해서 실제로 붙는 데이터까지 같이 준다.
            "prompt": score_tune.system_prompt(CFG),
            "prompt_custom": bool((tc.get("prompt") or "").strip()),
            "prompt_default": score_tune.SYSTEM,
            "history": score_tune.history(CFG, lim),
        })

    b = request.get_json(silent=True) or {}

    # 지금 누르면 무엇이 모델에게 가는가 — 눌러 보기 전에 확인
    if b.get("preview"):
        try:
            return jsonify(score_tune.preview(CFG, systems(),
                                              hours=b.get("hours")))
        except Exception as e:                          # noqa: BLE001
            return jsonify({"error": f"{type(e).__name__}: {e}"}), 500

    # 프롬프트만 바꾸는 호출 (빈 글이면 기본 프롬프트로 되돌린다)
    if "prompt" in b:
        pol = CFG.setdefault("policy", {}).setdefault("auto_tune", {})
        pol["prompt"] = str(b.get("prompt") or "").strip()
        err = _persist_auto_tune()
        return jsonify({"saved": not err, "error": err or "",
                        "custom": bool(pol["prompt"]),
                        "prompt": score_tune.system_prompt(CFG)})

    # 켜고 끄기만 바꾸는 호출
    if "enabled" in b and "hours" not in b and not b.get("run"):
        pol = CFG.setdefault("policy", {}).setdefault("auto_tune", {})
        pol["enabled"] = bool(b["enabled"])
        err = _persist_auto_tune()
        return jsonify({"enabled": pol["enabled"], "saved": not err,
                        "error": err or ""})

    if TUNE["running"]:
        return jsonify({"error": "이미 조정이 돌고 있습니다 — 끝나면 다시"}), 409
    try:
        hours = max(1, min(48, int(b.get("hours") or tc["hours"])))
    except (TypeError, ValueError):
        hours = tc["hours"]
    rec = _tune_once(hours, str(b.get("by") or "수동"),
                     apply_it=b.get("apply", True) is not False)
    code = 200 if not rec.get("error") else 502
    return jsonify(rec), code


def _persist_auto_tune() -> str:
    """policy.auto_tune 을 config.json 에 적는다 → 오류 글."""
    from lp_client import CONFIG_PATH
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
            disk = json.load(f)
        disk.setdefault("policy", {})["auto_tune"] = \
            (CFG.get("policy", {}) or {}).get("auto_tune") or {}
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(disk, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, CONFIG_PATH)
        return ""
    except Exception as e:                              # noqa: BLE001
        return f"{type(e).__name__}: {e}"


# 자동 조정 상태 — 두 번 겹쳐 돌지 않게, 그리고 화면에 '지금 도는 중' 을 준다
TUNE: dict = {"running": False, "last_slot": None}


def _tune_next_text(tc: dict) -> str:
    """다음 실행 시각 한 줄 — 화면이 '언제 도나' 를 물어보지 않아도 되게."""
    if not tc.get("enabled"):
        return "자동 꺼짐"
    now = datetime.now()
    for h in tc["at"]:
        if h > now.hour:
            return f"오늘 {h:02d}:00"
    return f"내일 {tc['at'][0]:02d}:00" if tc["at"] else "예정 없음"


def _tune_once(hours: int, by: str, apply_it: bool = True) -> dict:
    """한 번 돌리고 적용까지. 기록은 **적용 여부와 상관없이** 남긴다."""
    import score_tune
    TUNE["running"] = True
    try:
        rec = score_tune.run(CFG, systems(), hours=hours, by=by)
        rec["dry"] = not apply_it
        if apply_it and rec.get("applied") and not rec.get("error"):
            err = _apply_cuts(rec["applied"])
            rec["saved"] = not err
            if err:
                rec["error"] = f"적용 실패 — {err}"
            else:
                chg = " · ".join(
                    "{}={}/{}/{}".format(s_, r["warn"], r["danger"], r["critical"])
                    for s_, r in rec["applied"].items())
                print(f"[정책] LLM 자동 조정({by}) → {chg}")
        score_tune.record(rec, CFG)
        return rec
    except Exception as e:                              # noqa: BLE001
        rec = {"at": datetime.now().isoformat(timespec="seconds"), "by": by,
               "hours": hours, "rows": [], "applied": {},
               "error": f"{type(e).__name__}: {e}"}
        score_tune.record(rec, CFG)
        return rec
    finally:
        TUNE["running"] = False


def _tune_loop() -> None:
    """2시간마다(config.policy.auto_tune.at) 자동 조정.

    ★분 단위로 깨어나 '그 시각 슬롯을 이미 돌았나' 로 판단한다. sleep 으로
      다음 시각까지 재우면, 설정을 바꾸거나 서버가 잠깐 멈췄다 살아났을 때
      한 텀을 통째로 건너뛴다.
    """
    import score_tune
    while True:
        try:
            tc = score_tune.cfg_of(CFG)
            now = datetime.now()
            slot = now.strftime("%Y%m%d") + f"-{now.hour:02d}"
            if (tc.get("enabled") and now.hour in tc["at"] and now.minute < 5
                    and TUNE["last_slot"] != slot and not TUNE["running"]):
                TUNE["last_slot"] = slot
                print(f"[정책] 자동 조정 시작 — 최근 {tc['hours']}시간 기준")
                _tune_once(int(tc["hours"]), f"자동 {now.hour:02d}시")
        except Exception as e:                          # noqa: BLE001
            print(f"[정책] ⚠️ 자동 조정 루프 예외: {type(e).__name__}: {e}")
        time.sleep(60)


@app.route("/api/world")
def api_world():
    """구간 그래프에서 FAB 을 누르면 열 주소 — OHT 월드모델 **딱 1분** 재생.

    /api/world?at=2026-08-31T10:35:00  →
      FAB 다섯의 {테이블, 월드모델 FAB/prefix, from~to, 주소} + 월드모델 생사

    ★구간은 그 분의 00초부터 딱 1분이다 (10:35:47 을 눌러도 103500~103600).
      사람이 화면에서 본 '10:35 한 칸' 과 어긋나면 증거가 되지 않는다.
    ★조회는 우리가 안 한다. 월드모델(별도 프로세스 · 10005)이 주소만 보고
      스스로 로그프레소를 친다. 여기서 pandas 를 끌고 오면 관제가 무거워진다.
    """
    import world_link
    at = (request.args.get("at") or "").strip()
    label = (request.args.get("label") or "").strip()
    # ★화면이 보고 있는 host 를 그대로 쓴다. localhost 를 박으면 다른 PC 에서
    #   관제를 열었을 때 그 사람 PC 의 10005 를 찾아간다.
    host = request.host or ""
    c = world_link.cfg_of(CFG)
    if not c.get("enabled", True):
        return jsonify({"enabled": False, "links": [],
                        "note": "config.world_model.enabled=false"})
    try:
        rows = world_link.links(at, CFG, host, label) if at else []
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"enabled": True, "at": at, "minutes": c["minutes"],
                    "links": rows, "server": world_link.alive(CFG, host)})


@app.route("/api/ml")
def api_ml():
    """ML 조기예측 — 최근 상태 + 그 날 집계. ALL 화면의 'ML 조기예측' 탭용.

    ★우리 점수(0~100)와 눈금이 다르다(분 단위). 화면에서 같은 그래프에
      겹치지 말 것 — 별도 탭으로 두는 이유가 이것이다.
    """
    day = "".join(ch for ch in (request.args.get("day") or "") if ch.isdigit())[:8]
    try:
        import ml_feed
        s = ml_feed.summary(day, CFG)
        s["sys"] = str(CFG.get("ml", {}).get("sys", "ALL")).upper()
        s["p_on"] = float(CFG.get("ml", {}).get("p_on", 0.30))
        s["p_off"] = float(CFG.get("ml", {}).get("p_off", 0.20))
        s["state"] = (get_ctx(s["sys"])["state"].get("ml") or {})
        return jsonify(s)
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/ml/fetch", methods=["POST"])
def api_ml_fetch():
    """지금 바로 받아 보기 — 왜 비어 있는지 화면에서 답이 나오게.

    ★수집은 폴링 루프 안에서만 돌아서, 방금 켠 서버는 한 주기(기본 60초)를
      기다려야 첫 데이터가 생긴다. 그동안 화면은 '데이터가 아직 없습니다' 만
      띄우는데, 그게 '기다리는 중' 인지 '로그인 실패' 인지 구분이 안 됐다.
      여기서 실제로 받아 보고 **시도한 URL과 실패 사유를 그대로** 돌려준다.
    """
    day = "".join(ch for ch in (request.args.get("day") or "") if ch.isdigit())[:8]
    try:
        import ml_feed
        import jupyter_csv as jc
        c = ml_feed.cfg_of(CFG)
        d = day or datetime.now().strftime("%Y%m%d")
        try:
            url = jc.file_url(d, c)
        except Exception as e:
            url = f"(URL 조립 실패: {e})"
        if not ml_feed.enabled(CFG):
            return jsonify({"ok": False, "url": url, "day": d,
                            "error": "config 의 ml.enabled 가 꺼져 있거나 ml.path 가 비었습니다"})
        res = ml_feed.fetch_day(d, CFG)
        return jsonify({"ok": not res["error"], "url": url, "day": d,
                        "rows": res["rows"], "added": res["added"],
                        "error": res["error"] or None})
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/ml/export")
def api_ml_export():
    """기간 CSV 한 덩어리로 내려받기 — /api/ml/export?from=…&to=…

    ★하루씩 30번 눌러 한 달치를 모을 수는 없다. 분석에 바로 쓰라고
      원본 칸 그대로 이어 붙인다.
    """
    f = request.args.get("from") or ""
    t = request.args.get("to") or f
    try:
        import ml_feed
        days = ml_feed.day_range(f, t)
        if not days:
            return jsonify({"error": "from/to 날짜가 올바르지 않습니다 (YYYYMMDD)"}), 400
        body = ml_feed.export_csv(f, t, CFG)
        name = f"ML_{days[0]}_{days[-1]}.csv" if len(days) > 1 else f"{days[0]}_ML.csv"
        return Response(
            body.encode("utf-8-sig"), mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{name}"'})
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/ml/backfill", methods=["POST"])
def api_ml_backfill():
    """기간을 통째로 받아오기 (빠진 날 메우기) — {from, to, refetch?}

    ★이미 받아 둔 날은 건너뛴다. 한 달치를 다시 받느라 파일서버를 몇 십 번
      두드릴 이유가 없다. refetch=true 면 다시 받는다.
    """
    b = request.get_json(silent=True) or {}
    f = str(b.get("from") or request.args.get("from") or "")
    t = str(b.get("to") or request.args.get("to") or f)
    try:
        import ml_feed
        if not ml_feed.day_range(f, t):
            return jsonify({"error": "from/to 날짜가 올바르지 않습니다 (YYYYMMDD)"}), 400
        res = ml_feed.fetch_range(f, t, CFG,
                                  skip_existing=not bool(b.get("refetch")))
        print(f"[ML] 기간 수집 {f}~{t} — 받음 {res['fetched']}일 · "
              f"건너뜀 {res['skipped']}일 · 실패 {res['failed']}일 · 신규 {res['added']}행")
        return jsonify(res)
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/ml/rows")
def api_ml_rows():
    """그 날 예측 원본 행 (표·그래프용). 최근 것부터."""
    day = "".join(ch for ch in (request.args.get("day") or "") if ch.isdigit())[:8]
    try:
        limit = max(1, min(2000, int(request.args.get("limit", 240))))
    except (TypeError, ValueError):
        limit = 240
    try:
        import ml_feed
        rows = ml_feed.read_day(day or datetime.now().strftime("%Y%m%d"), CFG)
        rows.sort(key=lambda r: (r.get("datetime") or ""))
        return jsonify({"rows": rows[-limit:], "total": len(rows)})
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/ml/why")
def api_ml_why():
    """그 1분에 ML 이 왜 그렇게 판정했나 — 근거 + LLM 설명.

    /api/ml/why?at=2026-08-19 03:12  (&llm=0 이면 계산 근거만)

    ★근거를 먼저 계산하고 LLM 에게는 그것만 읽힌다. 원본 CSV 를 던지고
      '분석해 줘' 하면 숫자를 지어낸다.
    ★LLM 이 죽어도 근거는 그대로 돌려준다 — 설명이 없는 것과 아무것도 없는
      것은 다르다.
    """
    at = parse_dt(request.args.get("at"))
    if at is None:
        return jsonify({"ok": False, "error": "at (시각) 이 필요합니다"}), 400
    try:
        import ml_feed
        import ml_why
        # ★실시간 근거는 **ML 이 보는 시스템**(ml.sys, 기본 ALL)에서 읽는다.
        #   화면의 ?sys= 를 따라가면 M14 를 보다가 ML 을 열었을 때 엉뚱한
        #   시스템의 점수를 근거라고 들이밀게 된다.
        ml_sys = str(ml_feed.cfg_of(CFG).get("sys") or "ALL").upper()
        cfg = get_ctx(ml_sys)["cfg"]
        out = ml_why.explain(at, cfg,
                             use_llm=(request.args.get("llm", "1") != "0"),
                             model=(request.args.get("model") or "").strip())
        return jsonify(out)
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/avatar")
def api_avatar():
    """2D 감정캐릭터 앱이 어디 떠 있나 + 지금 살아 있나.

    ★이건 관제 시스템이 아니다. 따로 뜨는 앱이라 systems() 에 넣지 않는다
      (넣으면 수집 대상이 되고 test_fabs 의 두 목록도 어긋난다).
    ★죽어 있는지 미리 알려 준다. 안 그러면 눌렀을 때 빈 화면만 나오고,
      사용자는 관제 화면이 고장난 줄 안다.
    """
    av = (CFG.get("avatar") or {})
    url = str(av.get("url") or "").strip()
    port = int(av.get("port") or 8585)
    if not url:
        # 화면이 보고 있는 호스트를 그대로 쓴다 — 주소를 두 군데 적지 않으려고
        host = (request.host or "").split(":")[0] or "127.0.0.1"
        url = f"http://{host}:{port}/"

    alive, why = False, ""
    try:
        import urllib.error
        import urllib.request
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=1.0) as r:
            alive = 200 <= r.status < 400
    except Exception as e:
        why = f"{type(e).__name__}"
    return jsonify({"enabled": bool(av.get("enabled", True)), "url": url,
                    "alive": alive, "why": why,
                    "hint": "avatar_2d 폴더에서 python run.py 로 따로 띄웁니다"})


@app.route("/api/ml/why/models")
def api_ml_why_models():
    """ML 해석에 쓸 수 있는 모델 목록.

    ★어떤 모델이 답했는지 모르면, 답이 이상할 때 무엇을 바꿔야 할지 알 수
      없다. 고를 수 있게 하고, 쓴 모델을 화면에 적는다.
    """
    try:
        import ml_feed
        import ml_why
        ml_sys = str(ml_feed.cfg_of(CFG).get("sys") or "ALL").upper()
        cfg = get_ctx(ml_sys)["cfg"]
        return jsonify({"models": ml_why.models(cfg),
                        "default": ml_why.default_model(cfg)})
    except Exception as e:
        return jsonify({"models": [], "default": "",
                        "error": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/llm_policy", methods=["GET", "POST"])
def api_llm_policy():
    """분당 LLM 판단(=LLM 판단 일치의 재료) 설정 — 정책 탭, **시스템 6개 각각**.

    느리다는 체감의 주범이 이것이다: 시스템마다 매 주기 '아직 판단 안 한 분'
    을 최대 max_per_cycle 건씩 LLM 에 물어본다 (전 시스템 직렬화라 게이트웨이
    는 한 번에 하나지만, 큐가 길면 다른 LLM 호출이 밀린다).

    POST {"enabled"?: bool,
          "by_sys"?: {"M14": {"mode": "on|watched|off",
                              "every_min": 1, "max_per_cycle": 3}, …},
          "save"?: true}
    ★메모리에 먼저 적용(다음 주기부터 바로 반영)하고, save=true 면
      config.json 에도 적는다 — 저장 버튼 하나로 '즉시 반영 + 재시작 유지'.
    """
    lc = CFG.setdefault("llm", {})
    pm = lc.setdefault("per_minute", {})
    EV, CAP = (1, 2, 5, 10, 15), (1, 2, 3, 5, 10)
    saved = None
    if request.method == "POST":
        b = request.get_json(silent=True) or {}
        if "enabled" in b:
            pm["enabled"] = bool(b["enabled"])
        if "by_sys" in b:
            if not isinstance(b["by_sys"], dict):
                return jsonify({"error": "by_sys 는 {시스템: 설정} 객체"}), 400
            known = set(systems())
            clean = {}
            for s_, row in b["by_sys"].items():
                s_ = str(s_).upper()
                if s_ not in known:
                    return jsonify({"error": f"모르는 시스템 {s_} (가능: {sorted(known)})"}), 400
                row = row or {}
                mode = str(row.get("mode", "on")).strip().lower()
                if mode not in ("on", "watched", "off"):
                    return jsonify({"error": f"{s_}.mode 는 on|watched|off"}), 400
                try:
                    ev = int(row.get("every_min", pm.get("every_min", 1)))
                    cap = int(row.get("max_per_cycle", pm.get("max_per_cycle", 3)))
                except (TypeError, ValueError):
                    return jsonify({"error": f"{s_} 의 every_min/max_per_cycle 은 정수"}), 400
                if ev not in EV:
                    return jsonify({"error": f"{s_}.every_min 은 {list(EV)} 중 하나"}), 400
                if cap not in CAP:
                    return jsonify({"error": f"{s_}.max_per_cycle 은 {list(CAP)} 중 하나"}), 400
                clean[s_] = {"mode": mode, "every_min": ev, "max_per_cycle": cap}
            # ★객체를 갈아끼우지 않고 내용만 고친다 — sys_cfg 뷰들이 같은
            #   llm 블록을 참조하므로, 통째로 바꾸면 FAB 만 옛 설정으로 돈다.
            by = pm.setdefault("by_sys", {})
            by.update(clean)
        if b.get("save"):
            err = _persist_llm_policy()
            saved = not err
            if err:
                return jsonify({"error": f"config.json 저장 실패 — {err} "
                                         f"(메모리에는 적용됨)", "applied": True}), 500
        rows = " · ".join(f"{s_}={_llm_mode(s_)}" for s_ in systems())
        print(f"[정책] LLM 판단 → 전체 {pm.get('enabled', True)} · {rows}"
              + (" · 저장됨" if saved else ""))
    by = pm.get("by_sys") or {}
    return jsonify({
        "enabled": bool(pm.get("enabled", True)),
        "every_options": list(EV), "cap_options": list(CAP),
        "systems": [{
            "sys": s_,
            "mode": _llm_mode(s_),
            "every_min": int((by.get(s_) or {}).get("every_min",
                                                    pm.get("every_min", 1)) or 1),
            "max_per_cycle": int((by.get(s_) or {}).get("max_per_cycle",
                                                        pm.get("max_per_cycle", 3)) or 3),
        } for s_ in systems()],
        "saved": saved,
    })


# ─────────────────────── 과거 파일 정리 (보관 기간) ───────────────────────
# 고객: "주기적으로 데이터 삭제 필요하네" · "정책에서 과거 파일 정리 기간 해주라"
#       · "설정할수 있게".
# ★느린 원인이었던 '옛 파일 다시 읽기' 는 store_csv.list_days 에서 따로 고쳤다.
#   이것은 디스크가 끝없이 차는 것을 막는 쪽이다.
# ★config 의 storage.retention_days (일). 0 = 끔 (기본 — 설정 전에는 안 지운다).
#   하루 한 번(서버를 켤 때 + 날이 바뀐 뒤 첫 수집 때) ALL 과 FAB 전부에서
#   보관 기간을 넘긴 날짜 파일(원본 TOTAL · LLM 판단 · ML · raw)을 지운다.
#   저장한다고 바로 지우지 않는다 — 바로 지우려면 정책 탭의 '지금 정리'.
RETENTION_MIN, RETENTION_MAX = 7, 3650
_RET: dict = {"day": None, "last": None}
_RET_LOCK = threading.Lock()


def _retention_days() -> int:
    try:
        return max(0, int((CFG.get("storage", {}) or {}).get("retention_days", 0) or 0))
    except (TypeError, ValueError):
        return 0


def _retention_cfgs() -> list:
    """정리할 시스템 [(코드, 설정), …] — ALL + config 의 FAB 전부.

    ★수집 방식과 상관없이 FAB 폴더까지 본다 — 로그프레소로 바꾼 뒤에도 전에
      쌓인 FAB 파일은 남아 있다. 같은 폴더를 두 번 세지 않는다.
    """
    out, seen = [], set()
    for s_ in ["ALL"] + [x for x in fab_codes(CFG) if x != "ALL"]:
        c = sys_cfg(CFG, s_)
        d = os.path.normcase(os.path.abspath(
            str((c.get("storage") or {}).get("daily_csv_dir", "data"))))
        if d in seen:
            continue
        seen.add(d)
        out.append((s_, c))
    return out


def _persist_retention() -> str:
    """보관 기간(storage.retention_days)을 config.json 에 적는다 → 오류 글.

    파일을 새로 읽어 그 한 칸만 고친다 — 손으로 고친 다른 설정은 그대로 둔다.
    """
    from lp_client import CONFIG_PATH
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8-sig") as f:
            disk = json.load(f)
        st = disk.setdefault("storage", {})
        st["retention_days"] = _retention_days()
        st.setdefault("_retention_days_doc",
                      "과거 파일 정리 — 이 일수(오늘 포함)보다 오래된 날짜 파일"
                      "(TOTAL·LLM 판단·ML·raw)을 하루 한 번 지운다. 0 = 끔. "
                      "정책 탭에서 바꾼다.")
        tmp = CONFIG_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(disk, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, CONFIG_PATH)
        return ""
    except Exception as e:                              # noqa: BLE001
        return f"{type(e).__name__}: {e}"


def _run_retention(keep: int, why: str) -> dict:
    """모든 시스템에서 보관 기간을 넘긴 날짜 파일을 지운다 → 합계."""
    from store_csv import prune_days
    if not _RET_LOCK.acquire(blocking=False):
        return {"error": "이미 정리 중입니다 — 잠시 뒤 다시 보세요"}
    try:
        t0 = time.time()
        tot = {"files": 0, "bytes": 0, "failed": 0, "errors": [], "by_sys": {}}
        days: set = set()
        for s_, c in _retention_cfgs():
            try:
                r = prune_days(keep, c)
            except Exception as e:                      # noqa: BLE001
                r = {"files": 0, "bytes": 0, "failed": 1, "day_list": [],
                     "errors": [f"{type(e).__name__}: {e}"]}
            tot["files"] += r.get("files", 0)
            tot["bytes"] += r.get("bytes", 0)
            tot["failed"] += r.get("failed", 0)
            tot["errors"] += [f"{s_} {x}" for x in r.get("errors") or []][:5]
            days.update(r.get("day_list") or [])
            if r.get("files") or r.get("failed"):
                tot["by_sys"][s_] = {"files": r.get("files", 0),
                                     "bytes": r.get("bytes", 0),
                                     "failed": r.get("failed", 0)}
        from store_csv import keep_from
        tot.update(days=len(days), first=min(days) if days else None,
                   last=max(days) if days else None, keep=keep,
                   keep_from=keep_from(keep), why=why,
                   at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                   sec=round(time.time() - t0, 1))
        _RET["last"] = tot
        print(f"[정리] {why} · 보관 {keep}일({tot['keep_from']} 부터 남김) → "
              f"{tot['files']}개 · {tot['bytes'] / 1048576:.1f}MB 지움"
              + (f" ({tot['first']}~{tot['last']}, {tot['days']}일치)" if days else "")
              + (f" · 못 지움 {tot['failed']}개: {tot['errors'][0]}" if tot["failed"] else "")
              + f"  [{tot['sec']}초]")
        return tot
    finally:
        _RET_LOCK.release()


def _retention_tick() -> None:
    """수집 루프가 매 바퀴 부른다 — 하루 한 번만 실제로 정리한다.

    ★지우는 일은 **따로 떼어 보낸다**. 백신·네트워크 드라이브에서 지우기가
      느려도 수집이 밀리면 안 된다.
    """
    today = datetime.now().strftime("%Y%m%d")
    if _RET.get("day") == today:
        return
    _RET["day"] = today
    keep = _retention_days()
    if keep <= 0:
        return
    threading.Thread(target=_run_retention, args=(keep, "하루 한 번"),
                     daemon=True, name="retention").start()


@app.route("/api/retention", methods=["GET", "POST"])
def api_retention():
    """과거 파일 정리 — 보관 기간 (정책 탭).

    GET  ?days=N               → 지금 쌓인 것 + N일(없으면 저장된 값)이면 지울 것
    POST {"days": N, "save": true} → 보관 기간 바꾸기 (0 = 끔, 7~3650)
    POST {"run": true}             → 저장된 보관 기간으로 지금 바로 정리
    ★저장은 바로 지우지 않는다. 자동 정리는 하루 한 번이다.
    """
    from store_csv import keep_from, prune_days, usage
    st = CFG.setdefault("storage", {})
    ran = None
    if request.method == "POST":
        b = request.get_json(silent=True) or {}
        if "days" in b:
            try:
                n = int(b["days"])
            except (TypeError, ValueError):
                return jsonify({"error": "보관 기간은 숫자(일)로 넣으세요"}), 400
            if n != 0 and not (RETENTION_MIN <= n <= RETENTION_MAX):
                return jsonify({"error": f"보관 기간은 0(끔) 또는 "
                                         f"{RETENTION_MIN}~{RETENTION_MAX} 일입니다"}), 400
            st["retention_days"] = n
            if b.get("save"):
                err = _persist_retention()
                if err:
                    return jsonify({"error": f"config.json 저장 실패 — {err} "
                                             f"(메모리에는 적용됨)", "applied": True}), 500
            print(f"[정책] 과거 파일 정리 → 보관 {n}일" + (" (끔)" if n == 0 else "")
                  + (" · 저장됨" if b.get("save") else ""))
        if b.get("run"):
            keep = _retention_days()
            if keep <= 0:
                return jsonify({"error": "보관 기간이 0(끔)입니다 — 먼저 기간을 "
                                         "저장하세요"}), 400
            ran = _run_retention(keep, "지금 정리")
            if ran.get("error"):
                return jsonify(ran), 409
    keep = _retention_days()
    try:
        ask = int(request.args.get("days", keep))
    except (TypeError, ValueError):
        ask = keep
    have = {"files": 0, "bytes": 0, "days": set()}
    prev = {"files": 0, "bytes": 0, "days": set()}
    for _s, c in _retention_cfgs():
        u = usage(c)
        have["files"] += u["files"]
        have["bytes"] += u["bytes"]
        have["days"].update(u["day_list"])
        if ask > 0:
            p_ = prune_days(ask, c, dry_run=True)
            prev["files"] += p_["files"]
            prev["bytes"] += p_["bytes"]
            prev["days"].update(p_["day_list"])

    def _sum(x):
        d = sorted(x["days"])
        return {"files": x["files"], "bytes": x["bytes"], "days": len(d),
                "first": d[0] if d else None, "last": d[-1] if d else None}
    last = dict(_RET["last"]) if _RET.get("last") else None
    if last:
        last.pop("by_sys", None)
    return jsonify({
        "days": keep, "min": RETENTION_MIN, "max": RETENTION_MAX,
        "asked": ask, "keep_from": keep_from(ask) if ask > 0 else None,
        "have": _sum(have), "preview": _sum(prev),
        "last": last, "running": _RET_LOCK.locked(),
        "ran": ran,
    })


@app.route("/api/window", methods=["GET", "POST"])
def api_window():
    """실시간 수집 설정 조회/변경.

    · window          — 한 번에 가져올 데이터 구간 (1m ~ 60m)
    · poll_interval_s — 몇 초마다 가져올지 (수집 주기)
    둘은 별개다: '1분마다 최근 30분치' 같은 조합이 가능하다.
    """
    q = CFG.setdefault("query", {})
    wopts = q.get("window_options", ["1m", "5m", "10m", "20m", "30m", "40m", "50m", "60m"])
    popts = q.get("poll_options", [10, 30, 60, 300, 600])

    if request.method == "POST":
        b = request.get_json(silent=True) or {}
        if "window" in b:
            if b["window"] not in wopts:
                return jsonify({"error": f"window 는 {wopts} 중 하나여야 합니다"}), 400
            q["window"] = b["window"]
            print(f"[관제] 데이터 구간 → {b['window']}")
        if "poll_interval_s" in b:
            try:
                p = int(b["poll_interval_s"])
            except (TypeError, ValueError):
                return jsonify({"error": "poll_interval_s 는 정수(초)"}), 400
            if p not in popts:
                return jsonify({"error": f"poll_interval_s 는 {popts} 중 하나여야 합니다"}), 400
            q["poll_interval_s"] = p
            print(f"[관제] 수집 주기 → {p}초")
        # ★여기서 STATE 에 settings_changed_at 을 적던 줄을 뺐다. STATE 는 이 파일에
        #   없는 이름이라(accuracy.py 에만 있다) 값은 바뀌는데 응답이 500 으로
        #   끝났다 — 화면의 '수집 주기' 를 바꾸면 늘 실패로 떴다. 읽는 곳도 없었다.

    return jsonify({"window": q.get("window", "10m"), "window_options": wopts,
                    "poll_interval_s": q.get("poll_interval_s", 60), "poll_options": popts})


# /api/feed 응답 캐시 — {키: (원본표시, 응답)}
# 화면이 3초마다 부르는데 데이터는 1분에 한 번 바뀐다. 원본이 그대로면
# 같은 응답을 다시 만들 이유가 없다 (행 수백 개를 매번 가공·직렬화했다).
FEED_CACHE = http_cache.JsonCache("feed")
# 케이스 목록 — 3초마다 들어오는데 내용은 1분에 한 번 남짓 바뀐다 (위 api_cases 주석)
CASES_CACHE = http_cache.JsonCache("cases")
# 화면 HTML 한 장 — 파일이 그대로면 다시 읽지도, gzip 하지도 않는다
_HTML_CACHE = http_cache.JsonCache("dashboard_html")
# 행 더블클릭 → 구간 그래프(SVG). 같은 자리를 다시 열면 그대로다
GRAPH_CACHE = http_cache.JsonCache("graph")


# 이름표 → 그 이름표를 띄운 카운트의 키 (화면 almChip 과 같은 규칙)
_LVKEY = {"경계중": "warn", "위험중": "danger", "초위험중": "critical"}


# ── 오프닝 FAB 칸 — 지금 스코어 · 지금 알람 (2026-10-19) ─────────────────────
# ★처음엔 칸마다 /api/feed?sys=FAB 를 불렀다. 그러면 (1) 하루치 전체(케이스 매칭·지표·
#   OHT_MAP·FAB 점수)를 다섯 번 만들고 (2) rctx() 가 다섯 FAB 을 '보는 중' 으로 찍어
#   분당 LLM 까지 다섯 개가 돌았다 — 오프닝이 느려졌다(고객).
# ★여기서는: 컨텍스트를 안 만들고(sys_cfg 만) 보는 중 표시도 안 남긴다. 날짜 파일의
#   **끝부분만** 읽어 마지막 1분 스코어·등급과 등급 카운터 창(N분)만 센다.
#   점수·등급·카운터는 /api/feed 와 같은 함수(_score · grade · alarm_count.scan)다.
OPEN_NOW_TAIL = 400            # 끝에서 몇 행을 보나 — 카운터 창(최대 180분)보다 넉넉히
_OPEN_NOW: dict = {}           # {FAB: (파일 지문, 결과)} — 파일이 그대로면 다시 안 센다


def _tail_rows(path: str, n: int) -> list[dict]:
    """CSV 의 머리글 + 마지막 n 행만 읽는다 (하루치 전체를 안 읽는다).

    ★칸 안에 줄바꿈이 든 행(따옴표로 싼 reason 등)이 있으면 자른 자리가 그 칸 한가운데일
      수 있다 — 따옴표 짝이 어긋나면 뒤가 통째로 한 칸이 된다. 그래서 자른 뒤 줄 머리를
      하나씩 밀어 보며 **모든 행의 칸 수가 머리글과 같은** 자리에서 읽는다.
    """
    import csv
    import io
    with open(path, "rb") as f:
        head = f.readline()
        f.seek(0, 2)
        end = f.tell()
        size = 64 * 1024
        while True:
            start = max(len(head), end - size)
            f.seek(start)
            body = f.read(end - start)
            if start == len(head) or body.count(b"\n") > n + 50:
                break
            size *= 2
    hdr = next(csv.reader([head.decode("utf-8-sig", errors="replace")]), [])
    text = body.decode("utf-8", errors="replace")
    if start == len(head):
        cands = [0]                                  # 파일 전체 — 자른 데가 없다
    else:
        cands, p = [], -1                            # 잘린 첫 줄 뒤부터 줄 머리마다
        for _ in range(60):
            p = text.find("\n", p + 1)
            if p < 0:
                break
            cands.append(p + 1)
    for c0 in cands:
        try:
            recs = [r for r in csv.reader(io.StringIO(text[c0:])) if r]
        except csv.Error:
            continue
        if recs and all(len(r) == len(hdr) for r in recs):
            return [dict(zip(hdr, r)) for r in recs[-n:]]
    return []


def _open_now_one(code: str) -> dict:
    from sentinel import _row_dt, _score, grade
    from store_csv import day_path, latest_day
    c = sys_cfg(CFG, code)
    day = datetime.now().strftime("%Y%m%d")
    path = day_path(day, c)
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        old = latest_day(c)                  # 오늘이 비었으면 최근 날 (feed 와 같다)
        if not old:
            return {"ok": False}
        day, path = old, day_path(old, c)
    st = os.stat(path)
    sig = (path, st.st_mtime_ns, st.st_size,
           json.dumps(CFG.get("grade") or {}, sort_keys=True, ensure_ascii=False))
    hit = _OPEN_NOW.get(code)
    if hit and hit[0] == sig:
        return hit[1]
    seq = []
    for r in _tail_rows(path, OPEN_NOW_TAIL):
        dt = _row_dt(r)
        if dt is not None:
            seq.append((dt, _score(r)))
    seq.sort(key=lambda x: x[0])
    if not seq:
        out = {"ok": False}
    else:
        lv = [(t, grade(sc, c)["level"]) for t, sc in seq]
        a = alarm_count.scan(lv, c)[-1]          # 마지막 분 = 지금
        t, sc = seq[-1]
        g = grade(sc, c)
        out = {"ok": True, "day": day, "at": t.isoformat(),
               "datetime": t.strftime("%Y-%m-%d %H:%M"),
               "score": sc, "level": g["level"],
               "alarm": {"w": a["warn"], "d": a["danger"], "c": a["critical"],
                         "lv": a["label"], "min": a["window_min"], "on": a["enabled"],
                         "why": alarm_count.why(a, alarm_count.policy(c))}}
    _OPEN_NOW[code] = (sig, out)
    return out


@app.route("/api/open/now")
def api_open_now():
    """오프닝 FAB 칸 — FAB 마다 지금(마지막 1분) 스코어·등급 + 지금 등급 카운터(알람)."""
    fabs = {}
    for code in systems():
        if code == "ALL":
            continue
        try:
            fabs[code] = _open_now_one(code)
        except Exception as e:                              # noqa: BLE001
            fabs[code] = {"ok": False, "error": f"{type(e).__name__}: {e}"}
    return jsonify({"ok": True, "fabs": fabs})


@app.route("/api/feed")
def api_feed():
    """수집한 전체 데이터 — 정상 포함 4등급으로 분류해서 내려준다.

    경계 이상은 케이스(case_id)와 연결되고, 정상은 데이터 행 그대로 보여준다.
    """
    C = rctx()
    from sentinel import (_row_dt, _score, grade, hid_zones, reason_metrics,
                          summarize_reason)
    # 지금 보는 화면이 FAB 이면 그 코드 (ALL 이면 "") — 발동 룰·실제지표를 그 FAB 것만
    # ★배포가 파일 단위다 — sentinel.py 가 아직 옛것이면 예전 함수로 그대로 간다.
    try:
        from sentinel import fab_metrics, fab_reason
    except ImportError:
        fab_reason = fab_metrics = None
    _fab_sys = str(C.get("sys") or "").upper()
    _fab_sys = "" if (_fab_sys in ("", "ALL") or fab_reason is None) else _fab_sys

    # 오늘 쌓인 전체 데이터. 오늘이 아직 비었으면 가장 최근 날짜를 대신 보여준다.
    from store_csv import list_days, read_day
    asked = (request.args.get("day") or "").strip()   # 날짜를 콕 집어 물어본 경우
    day = asked or datetime.now().strftime("%Y%m%d")
    rows, shown_day, fallback = [], day, False
    try:
        rows = read_day(day, C["cfg"])
        if not rows and not asked:
            for d in list_days(C["cfg"]):                 # 최신순
                r2 = read_day(d["day"], C["cfg"])
                if r2:
                    rows, shown_day, fallback = r2, d["day"], True
                    break
    except Exception as e:
        print(f"[FEED] ⚠️ 읽기 실패: {e}")
    # 폴링 버퍼 폴백은 '오늘' 요청일 때만. 과거 날짜를 물었는데 없으면 없는 것이다
    # (안 그러면 7/25 를 물었는데 오늘 버퍼가 나와서 날짜가 뒤바뀐다)
    if not rows and not asked:
        rows = C["state"].get("last_rows") or []

    # ── OHT_MAP (HID_JAM · RET 레포트) — 주피터의 날짜별 OHT_MAP CSV ──────────
    # ★오늘은 뒤에서 받는다(3초 폴링을 주피터 왕복만큼 세우지 않는다). 지난 날은
    #   그 자리에서 받는다 — 과거 탭은 조회할 때 한 번만 묻는다.
    # ★전역 CFG 로 받는다 — FAB 화면마다 같은 파일을 따로 받지 않게 (주피터 설정은 같다).
    _om_sig = ""
    try:
        import oht_map
        oht_map.ensure(shown_day, CFG)
        _om_sig = oht_map.sig(shown_day)
    except Exception as e:                                  # noqa: BLE001
        print(f"[FEED] ⚠️ OHT_MAP — HID_JAM · RET 칸을 비웁니다: {e}")

    # ★원본이 그대로면 지난 응답을 그대로 준다 (아래 out 생성이 비싸다)
    try:
        import fab_score as _fab_score
        from store_csv import day_path
        _p = day_path(shown_day, C["cfg"])
        _st = os.stat(_p)
        _sig = (_st.st_mtime_ns, _st.st_size, len(C["store"].cases),
                request.args.get("limit"), C["sys"], shown_day,
                # ★OHT_MAP 도 따로 떨어지는 파일이다 — 새로 받으면 HID_JAM · RET 칸을 다시 만든다
                _om_sig,
                # ★등급 컷이 빠져 있었다. 정책 탭에서 컷을 바꾸면 메모리
                #   CFG 는 바로 바뀌는데 원본 파일은 그대로라 이 키가 같고,
                #   그래서 **옛 컷으로 계산한 응답**이 캐시에서 그대로 나갔다.
                #   컷은 level·counts·fab_cuts 를 전부 바꾸므로 —
                #   화면 글자색이 정책을 안 따라가는 게 여기서 났다.
                json.dumps(C["cfg"].get("grade") or {}, sort_keys=True,
                           ensure_ascii=False),
                # ★등급 카운터도 같은 이유로 키에 넣는다. grade 블록 안에
                #   있어 위 json.dumps 에 이미 섞이지만, 알람만 따로 들고
                #   있게 되는 날(예: by_sys 분리)을 대비해 지문을 박아 둔다.
                alarm_count.sig(C["cfg"]),
                # ★FAB 다섯 점수는 **분리 파일**에서 읽는다. 그 파일이 바뀌면
                #   지금 보는 파일이 그대로여도 다시 계산해야 한다 — 빼먹으면
                #   FAB 컬럼만 옛 값에 얼어붙는다 (수집이 파일마다 따로 떨어질
                #   수 있고, 오래된 값을 보여주는 게 안 보여주는 것보다 나쁘다).
                _fab_score.files_sig(shown_day, C["cfg"]))
    except OSError:
        _sig = None
    # ★여기서 바로 돌려주지 않는다. 아래 본문 전체를 build() 로 감싸 두고,
    #   지문이 같으면 **만들지도 않고** 지난 글자를 그대로 내준다. 브라우저가
    #   이미 같은 것을 갖고 있으면 304 한 줄로 끝난다 (3초 폴링의 열아홉 번).
    def _build():

        # 추이 그래프에서 고를 수 있는 지표 묶음 — 값을 같이 실어보낸다
        groups = metric_groups(C["cfg"])
        mkeys = sorted({m["key"] for g in groups for m in g["metrics"]})
        seen_keys = set()

        # FAB 다섯 점수 — **어느 화면에서든** 같이 내려준다. 원본이 FAB 분리
        # 파일(data/{FAB}/{day}_TOTAL.CSV)이라 M14 를 보는 중에도 다섯을 다
        # 읽어올 수 있다. 값을 모르는 FAB 은 area_table 이 빼고 주고, 화면은
        # 빈 칸으로 그린다 (0 으로 채우면 '그 FAB 정상' 으로 읽힌다).
        ftab = None
        try:
            import fab_score
            ftab = fab_score.area_table(rows, day=shown_day, cfg=C["cfg"])
        except Exception as e:                              # noqa: BLE001
            # FAB 점수가 없어도 목록 자체는 떠야 한다 (컬럼만 빈다)
            print(f"[FEED] ⚠️ FAB 점수 계산 실패 — 컬럼을 비웁니다: {e}")

        # 그 분의 OHT_MAP 줄 — FAB 화면이면 그 FAB 것만 ('HH:MM' → 줄 목록)
        try:
            _hid = oht_map.by_time(shown_day, C["sys"]) if _om_sig else {}
        except Exception:                                   # noqa: BLE001
            _hid = {}

        out = []
        for r in rows:
            dt, sc = _row_dt(r), _score(r)
            if dt is None:
                continue
            g = grade(sc, C["cfg"])
            area = (r.get("hot_area") or "").strip() or "UNKNOWN"
            bd = (r.get("BOTTLENECK_downward_anomaly_cols") or "").strip()
            bu = (r.get("BOTTLENECK_upward_anomaly_cols") or "").strip()
            qd = (r.get("QUEUE_downward_anomaly_cols") or "").strip()
            qu = (r.get("QUEUE_upward_anomaly_cols") or "").strip()
            bott = " ".join(x for x in (bd, bu) if x)
            items = " ".join(x for x in (qd, qu) if x).split()
            # 이 시각이 속한 케이스 찾기
            cid = None
            for c in C["store"].cases:
                if c["area"] == area and c["opened_at"] <= dt.isoformat() <= (
                        c.get("last_seen") or c["opened_at"]):
                    cid = c["id"]
                    break
            raw_reason = (r.get("reason") or "").strip()
            # FAB 다섯 점수 + 제일 높은 FAB (위 ftab 참고)
            fx = {}
            if ftab:
                _fr = ftab["rows"].get(dt.replace(second=0, microsecond=0).isoformat())
                if _fr:
                    fx = {"fab": _fr["s"], "hi_fab": _fr["hi"]}
                    if _fr.get("lv"):        # 예측기 등급이 컷 판정과 다른 것만
                        fx["fab_lv"] = _fr["lv"]
            m = {}
            for k in mkeys:
                v = _num(r.get(k))
                if v is not None:
                    m[k] = v
                    seen_keys.add(k)
            out.append({
                "m": m,
                "at": dt.isoformat(),
                "datetime": (r.get("datetime") or dt.strftime("%Y-%m-%d %H:%M")).strip(),
                "time": dt.strftime("%H:%M"), "area": area,
                "score": sc, "level": g["level"], "emoji": g["emoji"], "severity": g["severity"],
                # 원문 fallback 금지 — 요약이 비면 룰 코드·금지어가 그대로 새어
                # 나갔다. summarize_reason 이 항상 한글 한 줄을 돌려준다.
                # ★FAB 화면이면 **그 FAB 것만** (고객: "발동률도 각 FAB 에 해당하는
                #   것만, 실제지표도 마찬가지 · PIO_ERROR 몇 개인지") — sentinel.fab_*.
                #   ALL 은 예전 그대로다 (리포트·아바타가 같은 함수를 ALL 로 부른다).
                "reason": (fab_reason(raw_reason, _fab_sys, r) if _fab_sys
                           else summarize_reason(raw_reason, area)),
                "reason_raw": raw_reason,
                # 한글 요약 옆 '실제지표' 칸 — 그 룰이 실제로 보는 raw 컬럼명
                "metrics": [{"raw": x["raw"], "label": x["label"]}
                            for x in (fab_metrics(raw_reason, _fab_sys, r) if _fab_sys
                                      else reason_metrics(raw_reason, area, r))],
                "zones": hid_zones(bott), "items": items,
                # AMOS 4개 컬럼을 나눠서 그대로 (UI 표시용)
                "bott_down": hid_zones(bd), "bott_up": hid_zones(bu),
                "queue_down": qd.split(), "queue_up": qu.split(),
                "chain": (r.get("propagation_chain") or "").strip(),
                "case_id": cid,
                **fx,
            })
            # '실제지표' 옆 HID_JAM · RET(레포트) — 그 분에 OHT_MAP 줄이 있을 때만 싣는다
            if _hid and dt.strftime("%Y%m%d") == shown_day:
                _h = _hid.get(dt.strftime("%H:%M"))
                if _h:
                    out[-1]["hid"] = _h

        # ── 등급 카운터 — 최근 N분에 경계·위험·초위험이 몇 번 떴나 ──────────
        # ★**정렬 전**에 센다. out 은 아래에서 최신순으로 뒤집히는데, 창을 굴리려면
        #   시간 오름차순이어야 한다 (뒤집힌 뒤에 세면 창이 거꾸로 간다).
        # ★점수·등급을 만들지 않는다. 이미 매겨진 level 을 세기만 한다.
        # at 은 우리가 dt.isoformat() 으로 만든 글자라 fromisoformat 이 정확하다
        #   (parse_dt 는 사람이 친 글자를 너그럽게 읽는 함수다 — 여기 쓸 자리가 아니다)
        _ats = [datetime.fromisoformat(x["at"]) for x in out]
        _alm = alarm_count.scan(list(zip(_ats, (x["level"] for x in out))), C["cfg"])
        _apol = alarm_count.policy(C["cfg"])
        for _x, _a in zip(out, _alm):
            if _a.get("label"):
                _x["alm"] = {"lv": _a["label"], "w": _a["warn"], "d": _a["danger"],
                             "c": _a["critical"], "why": alarm_count.why(_a, _apol)}

        # ── ALL 화면에서는 FAB 다섯도 **각각** 센다 ──────────────────────────
        # ★ALL 의 종합점수만 세면 '어느 FAB 이 계속 나쁜가' 를 말하지 못한다.
        #   화면에 FAB 다섯 점수 칸이 이미 있는데, 그 중 무엇이 눌러앉아 있는지가
        #   안 보였다 (고객 지적: "ALL에서 ALL,FAB인지 그런 알람 내용이 없다").
        # ★FAB 마다 **자기 컷**으로 등급을 매기고 **자기 정책**으로 센다.
        #   컷은 FAB 별(grade.by_sys)이고 카운터도 FAB 별(grade.alarm_by_sys)이다.
        # ★점수·등급을 새로 만들지 않는다. area_table 이 이미 낸 FAB 점수를
        #   컷에 대보는 것뿐이다 (화면의 fabLv 와 같은 규칙 — 정책이 이긴다).
        _apol_fab = {}
        if C["sys"] == "ALL" and ftab:
            for _f in (ftab.get("fabs") or []):
                _fp = alarm_count.policy(CFG, _f)
                if not _fp["enabled"]:
                    continue            # 그 FAB 은 미적용 — 세지도 않는다
                _fcfg = sys_cfg(CFG, _f)
                _seq = []
                for _t, _x in zip(_ats, out):
                    _v = (_x.get("fab") or {}).get(_f)
                    # 값을 모르는 분은 '' — 정상으로 세면 없는 것을 괜찮다고 말하게 된다
                    _seq.append((_t, grade(_v, _fcfg)["level"] if _v is not None else ""))
                _fa = alarm_count.scan(_seq, CFG, _f)
                _hit = False
                for _x, _a in zip(out, _fa):
                    if _a.get("label"):
                        _x.setdefault("alm_fab", {})[_f] = {"lv": _a["label"],
                                                            "n": _a[_LVKEY[_a["label"]]]}
                        _hit = True
                if _hit:
                    # 말풍선 글은 화면이 만든다 — 행마다 실으면 하루치가 그만큼 무겁다
                    _apol_fab[_f] = _fp

        out.sort(key=lambda x: x["at"], reverse=True)
        counts = {lv: sum(1 for x in out if x["level"] == lv)
                  for lv in ("정상", "경계", "위험", "초위험")}
        # 지금(제일 최근 행)의 알람 상태 — 화면 머리에 한 줄로 띄운다
        alm_now = (out[0].get("alm") if out else None) or None
        # 기본은 하루치 전부 (1분 1행 = 1440행). 00:00 부터 다 보여야 한다.
        try:
            limit = max(1, min(5000, int(request.args.get("limit", 1500))))
        except ValueError:
            limit = 1500
        payload = {"rows": out[:limit], "counts": counts, "total": len(out),
                   # 등급 카운터 — 설정과 '지금' 상태. 화면이 배지를 이걸로 그린다
                   "alarm": _apol, "alarm_now": alm_now,
                   # FAB 카운터가 걸린 FAB 의 정책 — 화면이 말풍선을 이걸로 만든다
                   "alarm_fab": _apol_fab,
                        "shown": min(limit, len(out)),
                        # 실제로 값이 있는 지표만 선택지로 준다 (CSV 에 없는 컬럼은 뺀다)
                        "groups": [dict(g, metrics=[m for m in g["metrics"] if m["key"] in seen_keys])
                                   for g in groups
                                   if any(m["key"] in seen_keys for m in g["metrics"])],
                        "day": shown_day, "fallback": fallback,
                        "latest": out[0]["datetime"] if out else None,
                        "earliest": out[-1]["datetime"] if out else None,
                   "window": C["cfg"].get("query", {}).get("window", "10m"),
                   # FAB 마다 등급 컷이 다르다 — 화면이 이 컷으로 글자색을 칠한다.
                   # 행마다 싣지 않고 한 번만 준다 (하루 1440행이라 무거워진다).
                   "fabs": (ftab or {}).get("fabs") or [],
                   "fab_cuts": (ftab or {}).get("cuts") or {}}
        return payload

    return _cached_json(FEED_CACHE, C["sys"], _sig, _build)


@app.route("/api/oht_map/report")
def api_oht_map_report():
    """RET(레포트) — 그 분의 PROBLEM_MAP html 을 주피터에서 받아 내려준다.

    ?day=20261003&name=PROBLEM_MAP_M16HUB_20261003_2014_WARNING.html
    ★그 날 OHT_MAP CSV 에 적힌 파일만 내준다 (oht_map.report) — 화면이 준 경로로
      주피터에서 아무 파일이나 끌어오지 않는다.
    """
    import urllib.parse
    import oht_map
    rctx()
    day = "".join(ch for ch in (request.args.get("day") or "") if ch.isdigit())[:8]
    name = (request.args.get("name") or "").strip()
    raw, err = oht_map.report(day, name, CFG)
    if err:
        return jsonify({"ok": False, "error": err}), 404
    resp = Response(raw, mimetype="text/html")
    ascii_name = name.encode("ascii", "replace").decode().replace('"', "")
    resp.headers["Content-Disposition"] = (
        f'attachment; filename="{ascii_name}"; '
        f"filename*=UTF-8''{urllib.parse.quote(name)}")
    return resp


@app.route("/api/updates", methods=["GET", "POST"])
def api_updates():
    """업데이트 내역 — 날짜 · 버전 · 내용 ('UI대쉬보드' 옆 탭, updates.py 참고).

    GET                               → {"items": [...]} 날짜 최근이 위
    POST {date, version, content, pw} → 하나 저장
    POST {"delete": id, "pw": …}      → 하나 지움
    ★저장·지우기는 숨김 해제와 같은 비밀번호 — **서버가** 확인한다 (틀리면 403).
    """
    import updates
    if request.method == "POST":
        b = request.get_json(silent=True)
        b = b if isinstance(b, dict) else {}
        out, code = updates.delete(b, CFG) if b.get("delete") else updates.add(b, CFG)
        return jsonify(out), code
    items, err = updates.load(CFG)
    return jsonify({"ok": not err, "items": items, "error": err or None})


@app.route("/api/collect", methods=["POST"])
def api_collect():
    """수동 확보 — 오늘 하루 다시 훑거나(기본), 지정 날짜를 확보한다.

    {"date": "YYYYMMDD"} 또는 {} (오늘 00:00~현재)
    """
    C = rctx()
    b = request.get_json(silent=True) or {}
    from sentinel import source_mode
    try:
        # 주피터 CSV 모드는 로그프레소를 안 쓴다 — 그 날짜 파일을 받아 넣는다.
        if source_mode(C["cfg"]) == "jupyter":
            from jupyter_csv import backfill, fetch_day
            if b.get("back"):                     # 과거 N일 한꺼번에
                r = backfill(None, C["cfg"], back=int(b["back"]), verbose=False)
            elif b.get("from") and b.get("to"):   # 구간
                from datetime import timedelta
                d0 = parse_dt(b["from"]) or datetime.now()
                d1 = parse_dt(b["to"]) or datetime.now()
                span = [(d0 + timedelta(days=k)).strftime("%Y%m%d")
                        for k in range((d1 - d0).days + 1)]
                r = backfill(span, C["cfg"], verbose=False)
            else:
                r = fetch_day(b.get("date") or "", C["cfg"], verbose=False)
            return (jsonify(r), 200) if r.get("ok") else (jsonify(r), 502)

        from collect import collect, collect_day
        if b.get("date"):
            r = collect_day(b["date"], C["cfg"])
        else:
            now = datetime.now()
            r = collect(now.strftime("%Y%m%d000000"), now.strftime("%Y%m%d%H%M%S"),
                        C["cfg"], verbose=False)
        return (jsonify(r), 200) if r.get("ok") else (jsonify(r), 502)
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/graph")
def api_graph():
    """구간 그래프 SVG — 목록에서 더블클릭한 시각 기준 1시간.

    /api/graph?at=2026-07-28T08:11:00&minutes=60
    """
    C = rctx()
    from graphs import render, THEMES as GRAPH_THEMES
    from store_csv import read_day

    at = parse_dt(request.args.get("at")) or datetime.now()
    try:
        minutes = max(5, min(1440, int(request.args.get("minutes", 60))))
    except ValueError:
        minutes = 60

    days = {(at - timedelta(minutes=minutes)).strftime("%Y%m%d"),
            at.strftime("%Y%m%d"), (at + timedelta(minutes=minutes)).strftime("%Y%m%d")}
    rows = []
    for d in days:
        rows.extend(read_day(d, C["cfg"]))
    if not rows:
        rows = C["state"].get("last_rows") or []

    # 추이 그래프에서 체크한 FAB 을 그대로 받아 같이 그린다 (?fabs=M14,M16HUB).
    # 모르는 코드는 버린다 — 주소창으로 아무 이름이나 넣어도 그래프는 나와야 한다.
    import fab_score
    known = fab_score.fabs(C["cfg"])
    want = [f.strip().upper() for f in (request.args.get("fabs") or "").split(",")]
    picked = [f for f in known if f in want]

    # 화면 테마를 그대로 받아 같은 색으로 그린다. 모르는 값이면 다크 —
    # 예전 주소로 부르던 곳이 그대로 돌아간다.
    # ★넷 다 넘긴다(다크·화이트·네이비·고대비). 예전엔 light/dark 로만 좁혀
    #   보내서, 네이비·고대비를 골라도 그래프만 다크로 나왔다 — 남색 화면
    #   한가운데 다른 검정 상자가 박혔다. 고를 수 있는 값은 graphs.THEMES 가
    #   쥐고 있다(한쪽만 늘리면 또 어긋난다).
    theme = (request.args.get("theme") or "dark").strip().lower()
    theme = theme if theme in GRAPH_THEMES else "dark"
    # ★같은 그림을 두 번 그리지 않는다 (고객: "더블클릭할때 느려져").
    #   그리기 18.8ms + 응답 91KB 인데, 분 단위를 바꾸거나 같은 행을 다시
    #   열면 그대로 다시 그렸다. 원본 날짜 파일이 그대로면 결과도 그대로다.
    # ★날짜 파일이 하나라도 없으면 _days_sig 가 None 을 돌려주고, 그러면
    #   캐시를 안 쓴다 — 없는 파일을 '그대로' 라고 하면 안 된다.
    key = f'{C["sys"]}|{at.isoformat()}|{minutes}|{",".join(picked)}|{theme}|split'
    return _cached_json(
        GRAPH_CACHE, key, _days_sig(days, C["cfg"]),
        lambda: render(rows, at, minutes, cfg=C["cfg"], fabs=picked,
                       theme=theme, split=True).encode("utf-8"),
        ctype="image/svg+xml; charset=utf-8")


@app.route("/api/graph1")
def api_graph1():
    """구간 그래프의 **칸 하나만 크게** — 그래프 안에서 칸을 더블클릭하면 부른다.

    /api/graph1?at=2026-10-06T21:00:00&minutes=60&name=M16HUB.QUE.TIME.AVGTOTALTIME1MIN
    ★고객(2026-10-07): "그래프 더블클릭하고 … 다시 여기서 그래프 더블클릭하면 1개 크게
      확대해서 볼 수 있게". 칸 고르기는 /api/graph 와 같다(graphs.metric_sets).
    """
    C = rctx()
    from store_csv import read_day
    import graphs
    if not hasattr(graphs, "render_one"):
        # ★배포가 파일 단위다 — server.py 만 새것이고 graphs.py 가 옛것이면 길이 없다
        return Response("<div class='empty'>graphs.py 가 옛 판입니다 — 같이 바꿔 주세요</div>",
                        mimetype="text/html")
    at = parse_dt(request.args.get("at")) or datetime.now()
    try:
        minutes = max(5, min(1440, int(request.args.get("minutes", 60))))
    except ValueError:
        minutes = 60
    name = (request.args.get("name") or "").strip()
    days = {(at - timedelta(minutes=minutes)).strftime("%Y%m%d"),
            at.strftime("%Y%m%d"), (at + timedelta(minutes=minutes)).strftime("%Y%m%d")}
    rows = []
    for d in days:
        rows.extend(read_day(d, C["cfg"]))
    if not rows:
        rows = C["state"].get("last_rows") or []
    theme = (request.args.get("theme") or "dark").strip().lower()
    theme = theme if theme in graphs.THEMES else "dark"
    key = f'{C["sys"]}|{at.isoformat()}|{minutes}|one:{name}|{theme}'
    return _cached_json(
        GRAPH_CACHE, key, _days_sig(days, C["cfg"]),
        lambda: graphs.render_one(rows, at, name, minutes, cfg=C["cfg"],
                                  theme=theme).encode("utf-8"),
        ctype="image/svg+xml; charset=utf-8")


@app.route("/api/cause")
def api_cause():
    """그 분 발동 룰마다 원인 한 줄 — 그래프를 눌렀을 때 고정 칸에 '원인' 으로 뜬다.

    /api/cause?at=2026-10-06T21:00:00&sys=M16HUB
    → {"at": "...", "causes": [{"rule": "반송지연", "area": "M16HUB",
                                "text": "M16HUB 반송시간 10.4분 — 기준 9분 넘음"}, …]}
    ★고객(2026-10-07): "원인 내용 좀 적어 주라 — 룰이잖아 · 그래프 클릭하면 원인 내용".
      값은 그 분 reason · 그 행 CSV 에서, 기준은 컬럼흐름 상세도(fab_score.WATCH)에서.
    ★FAB 화면이면 그 FAB 블록만 — 표 '발동 룰' 칸(fab_reason)과 같은 기준이다.
    """
    C = rctx()
    from sentinel import _row_dt, rule_causes
    from store_csv import read_day
    at = parse_dt(request.args.get("at"))
    if not at:
        return jsonify({"at": "", "causes": [], "error": "at 이 없습니다"})
    at = at.replace(second=0, microsecond=0)
    row = None
    for r in read_day(at.strftime("%Y%m%d"), C["cfg"]):
        d = _row_dt(r)
        if d is not None and d.replace(second=0, microsecond=0) == at:
            row = r
            break
    if row is None:
        return jsonify({"at": at.isoformat(), "causes": [], "error": "그 분 자료가 없습니다"})
    fab = str(C.get("sys") or "").upper()
    fab = "" if fab in ("", "ALL") else fab
    causes = rule_causes((row.get("reason") or "").strip(), fab, row,
                         area=(row.get("hot_area") or "").strip())
    return jsonify({"at": at.isoformat(), "causes": causes, "llm": _llm_at(at, C["cfg"])})


def _llm_at(at, cfg) -> dict | None:
    """그 분의 1분 LLM 판단 — store_csv.llm_at (flask 없이 시험한다)."""
    try:
        from store_csv import llm_at
        return llm_at(at, cfg)
    except Exception as e:                                # noqa: BLE001 (원인은 그대로 나간다)
        print(f"[CAUSE] ⚠️ LLM 판단 읽기 실패: {e}")
        return None


@app.route("/api/contrib")
def api_contrib():
    """스코어 기여도 추정 — **화면에서 뺐다** (2026-10-07 고객: "기여도 추정 삭제해라 필요없어").

    ★길은 남기고 빈 글을 돌려준다. 관제 화면은 새로고침 없이 며칠씩 떠 있어서, 업데이트
      전에 연 화면이 더블클릭 때 아직 이 주소를 부른다 — 길을 없애면 그 화면 그래프 밑에
      'Not Found' 페이지가 통째로 박힌다. 빈 글이면 그 화면에서도 바로 사라진다.
    ★계산 자체(contrib.explain)는 ML 비교(ml_why)가 계속 쓴다.
    """
    return Response(b"", mimetype="text/html")


@app.route("/api/accuracy")
def api_accuracy():
    """1분 LLM 판단 + 사후검증 결과. ?day=YYYYMMDD (기본 오늘), ?rows=1 이면 행까지."""
    C = rctx()
    from accuracy import acc_cfg, summary, verify_day
    from store_csv import read_llm_day
    day = (request.args.get("day") or "").strip() or datetime.now().strftime("%Y%m%d")
    # 그 날짜를 열 때 채점을 한 번 돌린다 (과거 날짜도 판정이 채워지게)
    try:
        verify_day(day, C["cfg"])
    except Exception as e:
        print(f"[검증] ⚠️ {day} 채점 실패: {e}")
    out = summary(day, C["cfg"])
    out["backfill"] = dict(C["backfill"])
    try:
        from accuracy import backlog
        out["backlog"] = backlog(C["state"].get("last_rows") or [], C["cfg"])
    except Exception:
        out["backlog"] = None
    if request.args.get("rows"):
        rows = read_llm_day(day, C["cfg"])
        rows.sort(key=lambda r: r.get("datetime") or "", reverse=True)
        try:
            lim = max(1, min(2000, int(request.args.get("rows", 300))))
        except ValueError:
            lim = 300
        rows = rows[:lim]
        # 아직 판정이 안 된 행에 '몇 분 뒤에 채점되는지' 를 붙여준다
        win = acc_cfg(C["cfg"])["window_min"]
        now = datetime.now()
        for r in rows:
            if not (r.get("판정") or "").strip() and (r.get("실제이상") or "").strip():
                t0 = parse_dt(r.get("datetime"))
                if t0:
                    left = (t0 + timedelta(minutes=win) - now).total_seconds() / 60
                    r["대기분"] = max(0, int(left + 0.999))
        out["rows_data"] = rows
    return jsonify(out)


@app.route("/api/accuracy/backfill", methods=["POST"])
def api_accuracy_backfill():
    """그 날 아직 판단 안 한 분을 LLM 으로 메운다. {date, limit?}

    폴링은 최근 구간만 본다. 서버를 늦게 켰거나 꺼져 있던 구간은 이걸로 채운다.
    """
    C = rctx()
    b = request.get_json(silent=True) or {}
    day = "".join(ch for ch in str(b.get("date") or "") if ch.isdigit())[:8] \
        or datetime.now().strftime("%Y%m%d")
    try:
        limit = max(0, min(1500, int(b.get("limit", 0) or 0)))
    except (TypeError, ValueError):
        limit = 0

    if C["backfill"].get("running"):
        return jsonify({"ok": False, "error": "이미 메우는 중입니다", "state": C["backfill"]}), 409

    def work():
        C["backfill"].update(running=True, day=day, started=datetime.now().isoformat(), result=None)
        try:
            from accuracy import backfill_day
            C["backfill"]["result"] = backfill_day(day, C["cfg"], limit)
        except Exception as e:
            C["backfill"]["result"] = {"error": f"{type(e).__name__}: {e}"}
        finally:
            C["backfill"]["running"] = False

    threading.Thread(target=work, daemon=True).start()
    return jsonify({"ok": True, "started": True, "day": day, "limit": limit})


@app.route("/api/accuracy/backfill")
def api_accuracy_backfill_state():
    C = rctx()
    return jsonify(C["backfill"])


@app.route("/api/accuracy/verdict", methods=["POST"])
def api_accuracy_verdict():
    """운영자가 직접 누른 판정 — 자동 판정을 덮어쓴다. {datetime, verdict:정탐|오탐}"""
    C = rctx()
    from accuracy import set_human
    b = request.get_json(silent=True) or {}
    dt = (b.get("datetime") or "").strip()
    v = (b.get("verdict") or "").strip()
    if not dt or v not in ("정탐", "오탐"):
        return jsonify({"ok": False, "error": "datetime 과 verdict(정탐|오탐) 필요"}), 400
    day = "".join(ch for ch in dt if ch.isdigit())[:8]
    ok = set_human(day, dt, v, C["cfg"])
    return jsonify({"ok": ok})


@app.route("/api/data/days")
def api_data_days():
    """누적 저장된 날짜 CSV 목록 (20260727_TOTAL.CSV ...)."""
    C = rctx()
    from store_csv import data_dir, list_days
    return jsonify({"dir": data_dir(C["cfg"]), "days": list_days(C["cfg"])})


@app.route("/api/data/<day>.csv")
def api_data_csv(day):
    """저장된 날짜 CSV 원본 다운로드 — 직접 열어볼 수 있게.

    /api/data/20260729.csv      → 20260729_TOTAL.CSV (데이터)
    /api/data/20260729_LLM.csv  → 20260729_LLM.CSV   (1분 LLM 판단·판정)
    /api/data/20260819_ML.csv   → 20260819_ML.CSV    (ML 조기예측 원본)
    """
    C = rctx()
    from store_csv import day_path, llm_path
    d = "".join(ch for ch in day if ch.isdigit())[:8]
    up = day.upper()
    if "_ML" in up:                    # ★'LLM' 안에도 'LM' 이 있다 — 밑줄까지 봐야 안 헷갈린다
        import ml_feed
        p = ml_feed.ml_path(d, C["cfg"])
    elif "LLM" in up:
        p = llm_path(d, C["cfg"])
    else:
        p = day_path(d, C["cfg"])
    if not os.path.isfile(p):
        return jsonify({"error": f"{os.path.basename(p)} 없음"}), 404
    return send_from_directory(os.path.dirname(p), os.path.basename(p),
                               as_attachment=True)


def _recur_1h(ref: datetime, C: dict) -> dict:
    """재발률 — '50점(임계) 이상이 가라앉았다가 다시 올라왔나' 를 분단위 점수로 센다.

    최근 60분 점수를 보고 임계 이상 구간(런)을 끊는다. 임계 미만으로 내려간 뒤
    다시 올라오면 그게 재발이다.
        런 1개  → 재발 0회 → 0%
        런 3개  → 재발 2회 → 67%   (2/3)
    분모는 런 수, 분자는 재발 횟수(런 수 - 1). 최근 60분에 임계 이상이 아예
    없으면 rate 는 None (0% 로 굳어 보이지 않게).
    """
    from sentinel import _row_dt, _score
    floor = alarm_floor(C["cfg"])
    rows = C["state"].get("last_rows") or []
    try:                                      # 폴링 구간이 60분보다 짧으면 저장분으로 보충
        from store_csv import read_day
        saved = read_day(ref.strftime("%Y%m%d"), C["cfg"])
        if saved:
            seen_dt = {(r.get("datetime") or "") for r in rows}
            rows = list(rows) + [r for r in saved
                                 if (r.get("datetime") or "") not in seen_dt]
    except Exception:
        pass

    win = []
    for r in rows:
        d = _row_dt(r)
        if d and 0 <= (ref - d).total_seconds() / 60 <= 60:
            win.append((d, _score(r)))
    win.sort(key=lambda x: x[0])

    runs, over, minutes = 0, False, 0
    for _, s in win:
        if s >= floor:
            minutes += 1
            if not over:
                runs += 1                     # 임계 아래에서 위로 올라온 순간 = 런 시작
            over = True
        else:
            over = False
    recur = max(0, runs - 1)
    return {"rate": round(100 * recur / runs, 1) if runs else None,
            "runs": runs, "recur": recur, "minutes": minutes, "floor": floor}


# ── 🧪 4-LLM 병렬 분석 (분석 탭) ──
# 실행은 스레드 1개만 — 4-LLM 호출이 겹치면 게이트웨이에 부담이라 동시 1건 제한.
ANALYSIS: dict = {"running": False, "progress": {}, "last_id": None,
                  "cancel": None}


@app.route("/api/analysis/run", methods=["POST"])
def api_analysis_run():
    """4-LLM 병렬 분석 시작 — 백그라운드. body: {day, start?, end?} (HH:MM)."""
    C = rctx()
    if ANALYSIS["running"]:
        return jsonify({"error": "이미 분석이 돌고 있습니다 — 끝나면 다시 시도"}), 409
    body = request.get_json(silent=True) or {}
    day = "".join(ch for ch in str(body.get("day") or "") if ch.isdigit())[:8]
    if len(day) != 8:
        return jsonify({"error": "day(YYYYMMDD) 필요"}), 400
    start = str(body.get("start") or "")[:5]
    end = str(body.get("end") or "")[:5]

    # 단계별 모델 지정 — 안 고르면 config.llm.analysis.roles 기본값을 쓴다.
    # 이번 실행에만 적용하고 config.json 은 건드리지 않는다.
    from analysis import STAGES
    picked = body.get("models") or {}
    cfg = C["cfg"]
    over = {sid: str(picked.get(sid) or "").strip()
            for sid in STAGES if str(picked.get(sid) or "").strip()}
    if over:
        import copy
        cfg = copy.deepcopy(C["cfg"])
        a_cfg = cfg.setdefault("llm", {}).setdefault("analysis", {})
        roles = a_cfg.setdefault("roles", {})
        for sid, mdl in over.items():
            roles.setdefault(sid, {})["model"] = mdl

    ANALYSIS.update(running=True, progress={"stage": "start", "done": False},
                    sys=C["sys"],
                    day=day, span=f"{start or '00:00'}~{end or '24:00'}",
                    models=over, cancel=threading.Event())

    def work():
        try:
            from analysis import run_analysis
            r = run_analysis(day, cfg, start, end, progress=ANALYSIS["progress"],
                             cancel=ANALYSIS["cancel"])
            ANALYSIS["last_id"] = r.get("id")
            if not r.get("ok"):
                ANALYSIS["progress"].update(done=True, error=r.get("error"))
        except Exception as e:
            ANALYSIS["progress"].update(done=True, error=f"{type(e).__name__}: {e}")
        finally:
            ANALYSIS["running"] = False

    threading.Thread(target=work, daemon=True).start()
    return jsonify({"ok": True, "started": True})


@app.route("/api/analysis/stop", methods=["POST"])
def api_analysis_stop():
    """분석 중지 — 다음 단계 경계에서 멈춘다.

    이미 나간 LLM 호출은 응답이 올 때까지 못 끊는다(블로킹 소켓). 그래서
    '즉시 중단' 이 아니라 '진행 중인 호출이 끝나는 대로 중단' 이다.
    그때까지 나온 단계 결과는 그대로 저장된다.
    """
    ev = ANALYSIS.get("cancel")
    if not ANALYSIS.get("running") or ev is None:
        return jsonify({"ok": True, "running": False, "msg": "돌고 있는 분석이 없습니다"})
    ev.set()
    ANALYSIS["progress"]["cancelling"] = True
    return jsonify({"ok": True, "running": True,
                    "msg": "중지 요청됨 — 진행 중인 LLM 호출이 끝나면 멈춥니다"})


@app.route("/api/analysis/status")
def api_analysis_status():
    ev = ANALYSIS.get("cancel")
    return jsonify({"running": ANALYSIS["running"], "progress": ANALYSIS["progress"],
                    "last_id": ANALYSIS["last_id"],
                    "cancelling": bool(ev is not None and ev.is_set()
                                       and ANALYSIS["running"]),
                    "day": ANALYSIS.get("day"), "span": ANALYSIS.get("span")})


@app.route("/api/analysis/models")
def api_analysis_models():
    """게이트웨이가 이 키에 허용한 모델 목록 (/v1/models).

    모델 이름이 바뀌면 400/403 으로 단계가 통째로 죽는다. 화면에서 바로
    확인할 수 있어야 config 를 고칠 수 있다.
    """
    C = rctx()
    import urllib.error
    import urllib.request
    lc = C["cfg"].get("llm", {}) or {}
    base = str(lc.get("url", "")).split("/chat/completions")[0]
    if not base:
        return jsonify({"error": "llm.url 없음"}), 400
    headers = {}
    try:
        from llm_client import _api_key
        key = _api_key(C["cfg"])
        if key:
            headers["Authorization"] = f"Bearer {key}"
    except Exception:
        pass
    try:
        req = urllib.request.Request(base + "/models", headers=headers)
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        return jsonify({"error": f"HTTP {e.code}",
                        "detail": e.read()[:400].decode("utf-8", "replace")}), 502
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 502
    ids = [m.get("id") for m in (data.get("data") or []) if m.get("id")]
    used = {sid: (((lc.get("analysis") or {}).get("roles") or {}).get(sid) or {}).get("model")
            for sid in ("p1", "p2", "p3", "final")}
    return jsonify({"models": ids, "gaia": [m for m in ids if str(m).lower().startswith("gaia")],
                    "used": used,
                    "missing": [f"{k}={v}" for k, v in used.items() if v and v not in ids]})


@app.route("/api/analysis/list")
def api_analysis_list():
    C = rctx()
    try:
        from analysis import list_analyses
        return jsonify({"items": list_analyses(C["cfg"])})
    except Exception as e:
        return jsonify({"items": [], "error": f"{type(e).__name__}: {e}"})


@app.route("/api/analysis/delete", methods=["POST"])
def api_analysis_delete():
    """분석 기록 삭제 — body: {ids: [...]} (여러 건 한 번에)."""
    C = rctx()
    ids = (request.get_json(silent=True) or {}).get("ids") or []
    if not isinstance(ids, list) or not ids:
        return jsonify({"error": "ids 필요"}), 400
    try:
        from analysis import delete_analyses
        return jsonify(delete_analyses(ids, C["cfg"]))
    except Exception as e:
        return jsonify({"error": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/analysis/<aid>")
def api_analysis_get(aid):
    C = rctx()
    from analysis import get_analysis
    r = get_analysis(aid, C["cfg"])
    if not r:
        return jsonify({"error": "없는 분석"}), 404
    return jsonify(r)


# ── 이어 묻기에 얹는 스킬 ──────────────────────────────────────────────
# ★대화하다 보면 "이 문서 보고 답해" 가 필요해진다. 서버가 들고 있다가
#   질문마다 프롬프트에 얹는다. 뺄 수도 있어야 한다 — 한 번 올린 문서가
#   대화 끝까지 따라다니면, 다른 것을 물을 때 그게 방해가 된다.
ASK_SKILLS = []                 # [{id, name, chars, body}]
ASK_SKILL_MAX = 20000           # 한 파일 상한 (글자)
ASK_SKILL_KEEP = 8              # 최대 개수


@app.route("/api/analysis/skills", methods=["GET"])
def api_ask_skills():
    """지금 얹혀 있는 스킬 목록 (본문은 안 준다 — 목록에 다 보낼 이유가 없다)."""
    return jsonify({"ok": True, "skills": [
        {"id": s_["id"], "name": s_["name"], "chars": s_["chars"]}
        for s_ in ASK_SKILLS]})


@app.route("/api/analysis/skills", methods=["POST"])
def api_ask_skill_add():
    """md/txt 를 올려 이 대화에 얹는다. 같은 이름이면 바꿔 끼운다."""
    f = (request.files or {}).get("file")
    if f is None or not (f.filename or "").strip():
        return jsonify({"ok": False, "error": "파일이 없습니다"}), 400
    name = os.path.basename(f.filename).strip()
    if os.path.splitext(name)[1].lower() not in (".md", ".markdown", ".txt"):
        return jsonify({"ok": False, "error": "md 또는 txt 만 됩니다"}), 400
    try:
        body = f.read().decode("utf-8-sig", "replace").strip()
    except Exception as e:                                  # noqa: BLE001
        return jsonify({"ok": False, "error": f"읽기 실패: {e}"}), 400
    if not body:
        return jsonify({"ok": False, "error": "내용이 비었습니다"}), 400
    cut = len(body) > ASK_SKILL_MAX
    body = body[:ASK_SKILL_MAX]
    # 같은 이름은 바꿔 끼운다 — 고쳐서 다시 올리는 게 보통이다
    global ASK_SKILLS
    ASK_SKILLS = [s_ for s_ in ASK_SKILLS if s_["name"] != name]
    ASK_SKILLS.append({"id": uuid.uuid4().hex[:12], "name": name,
                       "chars": len(body), "body": body})
    ASK_SKILLS = ASK_SKILLS[-ASK_SKILL_KEEP:]
    return jsonify({"ok": True, "name": name, "chars": len(body),
                    "cut": cut, "count": len(ASK_SKILLS)})


@app.route("/api/analysis/skills/<sid>", methods=["DELETE"])
def api_ask_skill_del(sid):
    """하나 뺀다. sid 가 'all' 이면 전부."""
    global ASK_SKILLS
    before = len(ASK_SKILLS)
    ASK_SKILLS = [] if sid == "all" else [s_ for s_ in ASK_SKILLS if s_["id"] != sid]
    return jsonify({"ok": True, "removed": before - len(ASK_SKILLS),
                    "count": len(ASK_SKILLS)})


@app.route("/api/analysis/<aid>/ask", methods=["POST"])
def api_analysis_ask(aid):
    """끝난 분석을 두고 이어서 묻는다.

    body: {q, history?: [{role,content}...], model?}
    ★분석이 본 원자료(overview)를 근거로 답한다 — 리포트 본문만 되씹으면
      본문에 없는 것을 물었을 때 숫자를 지어낸다.
    """
    C = rctx()
    b_ = request.get_json(silent=True) or {}
    q = str(b_.get("q") or "").strip()
    if not q:
        return jsonify({"ok": False, "error": "q(질문) 필요"}), 400
    try:
        from analysis import ask
        r = ask(aid, q, b_.get("history") or [], C["cfg"],
                str(b_.get("model") or "").strip(),
                str(b_.get("prompt") or ""),
                skills=list(ASK_SKILLS))
        r["skills_used"] = [s_["name"] for s_ in ASK_SKILLS]
        return jsonify(r), (200 if r.get("ok") else 400)
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/forecast")
def api_forecast():
    """선행 감지 — 지금 추세로 본 임계 돌파 예보.

    수집 루프가 매 회 계산해 C["state"] 에 넣어 둔 것을 그대로 준다(요청마다 재계산
    안 함). 아직 한 번도 안 돌았으면 그 자리에서 한 번 계산한다.
    """
    C = rctx()
    fc = C["state"].get("forecast")
    if fc is None:
        _update_forecast(C)
        fc = C["state"].get("forecast")
    return jsonify(fc or {"ok": False, "warn": False, "reason": "아직 수집 전"})


@app.route("/api/forecast/score")
def api_forecast_score():
    """선행 감지 사후 채점 — 낸 경보가 맞았나. ?day= 하루, 없으면 최근 여러 날.

    저장된 CSV 를 1분씩 되감아 그때 예보를 다시 돌린다(판정 규칙은 실시간과
    같은 forecast._decide 하나를 공유). 적중/오보/놓침을 세고 실제 선행분을 낸다.
    """
    C = rctx()
    from forecast import score, score_days
    day = (request.args.get("day") or "").strip()
    try:
        if day:
            return jsonify(score(day, C["cfg"]))
        limit = max(1, min(30, int(request.args.get("limit", 14) or 14)))
        return jsonify(score_days(None, C["cfg"], None, limit))
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500


@app.route("/api/forecast/compare")
def api_forecast_compare():
    """다지표 선행 감지 A/B — 기존(점수 기울기만) vs 다지표를 같은 날로 채점.

    바꿨는데 좋아졌는지 모르면 안 바꾼 것만 못하다. 자동으로 갈아타지 않고
    숫자만 보여준다 — 켜고 끄는 건 config.forecast.multi.enabled.
    """
    C = rctx()
    import time as _t
    limit = max(1, min(30, int(request.args.get("limit", 14) or 14)))
    key = f"cmp|{limit}"
    now = _t.time()
    if (C["cmp"]["data"] and C["cmp"]["key"] == key
            and now - C["cmp"]["at"] < 60):
        return jsonify({**C["cmp"]["data"], "cached": True})
    try:
        from forecast import compare
        t0 = _t.time()
        data = compare(None, C["cfg"], limit)
        data["took_s"] = round(_t.time() - t0, 1)
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500
    C["cmp"].update(at=now, data=data, key=key)
    return jsonify({**data, "cached": False})


@app.route("/api/forecast/tune")
def api_forecast_tune():
    """임계 격자 탐색 — 지금 값보다 나은 min_slope·sustain_min 이 있나.

    격자를 다 돌아야 해서 몇 초 걸린다. 60초 캐시.
    """
    C = rctx()
    import time as _t
    limit = max(1, min(30, int(request.args.get("limit", 7) or 7)))
    key = f"tune|{limit}"
    now = _t.time()
    if (C["tune"]["data"] and C["tune"]["key"] == key
            and now - C["tune"]["at"] < 60):
        return jsonify({**C["tune"]["data"], "cached": True})
    try:
        from forecast import tune
        t0 = _t.time()
        data = tune(None, C["cfg"], limit=limit)
        data["took_s"] = round(_t.time() - t0, 1)
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500
    C["tune"].update(at=now, data=data, key=key)
    return jsonify({**data, "cached": False})


@app.route("/api/forecast/leading")
def api_forecast_leading():
    """선행 지표 — 과거 사건에서 어느 지표가 몇 분 먼저 움직였나.

    저장된 날짜 CSV 를 훑으므로 60초 캐시. days= 로 날짜를 직접 줄 수 있다.
    """
    C = rctx()
    import time as _t
    days = [d for d in (request.args.get("days", "") or "").split(",") if d.strip()]
    look = max(10, min(int(request.args.get("lookback", 60) or 60), 240))
    key = f"{','.join(days)}|{look}"
    now = _t.time()
    if (C["leading"]["data"] and C["leading"]["key"] == key
            and now - C["leading"]["at"] < 60):
        return jsonify({**C["leading"]["data"], "cached": True})
    try:
        from forecast import leading
        data = leading(days or None, C["cfg"], lookback_min=look)
    except Exception as e:
        return jsonify({"ok": False, "error": f"{type(e).__name__}: {e}"}), 500
    C["leading"].update(at=now, data=data, key=key)
    return jsonify({**data, "cached": False})


@app.route("/api/kpi")
def api_kpi():
    """상단 지표 — 실제 계산 가능한 값만. 근거 없는 수치는 null 로 둔다."""
    C = rctx()
    act = C["store"].active()

    def _dt(s):
        try:
            return datetime.fromisoformat(s)
        except Exception:
            return None

    # ★기준 시각 = '데이터의 최신 시각'. 벽시계로 재면 로그프레소가 몇 분 밀리거나
    #   과거 날짜를 재생할 때 모든 케이스가 '1시간 밖' 이 돼 재발률이 늘 0% 로 굳는다.
    seen = [d for d in (_dt(c.get("last_seen") or c.get("opened_at"))
                        for c in C["store"].cases) if d]
    ref = max(seen) if seen else datetime.now()

    def age_min(c, field="opened_at"):
        d = _dt(c.get(field) or c.get("opened_at"))
        return (ref - d).total_seconds() / 60 if d else 0

    unack = [c for c in act if not c.get("acked_at")]
    new30 = [c for c in act if age_min(c) <= 30]

    rc = _recur_1h(ref, C)

    # LLM 판단 일치 — 1분 추론의 사후검증 결과 (★정탐률이 아니다)
    try:
        from accuracy import summary as acc_summary
        acc = acc_summary(None, C["cfg"])
    except Exception as e:
        acc = {"error": f"{type(e).__name__}: {e}"}

    return jsonify({
        "active": len(act),
        "active_new_30m": len(new30),
        "unack": len(unack),
        "unack_over_5m": len([c for c in unack if age_min(c) >= 5]),
        "detect_latency_ms": C["state"].get("latency_ms"),
        "recur_rate_1h": rc["rate"],
        "recur_base": rc["runs"],
        "recur_events": rc["recur"],
        "recur_minutes": rc["minutes"],
        "recur_floor": rc["floor"],
        "recur_ref": ref.isoformat(),
        "llm_match": acc,
        "by_level": {lv: len([c for c in act if c["level"] == lv])
                     for lv in ("경계", "위험", "초위험")},
        "alarm_floor": alarm_floor(C["cfg"]),
    })


# ────────────────────────────── 케이스 ──────────────────────────────
@app.route("/api/cases")
def api_cases():
    """★화면이 **3초마다** 부른다. 캐시가 없어서 부를 때마다 케이스 전부를
    다시 직렬화하고 지문까지 내고는, 대개 304 라 그대로 버렸다.

    재 본 값 (케이스 800건 = 2.9MB):
        직렬화 25.7ms + 지문 3.4ms = 29.1ms  × 20회/분 × 사람 수
        → 혼자면 0.6초/분, 다섯이면 2.9초/분, 열이면 5.8초/분을
          **오직 이것 하나에** 쓴다. 그동안 GIL 을 쥐므로 다른 요청이 밀린다.
        고객: "여러명이 들어오면 느려져" — 여기가 그 자리다.

    이제 판번호(store.rev)가 그대로면 만들지도, 지문을 내지도 않는다.
    케이스는 1분에 한 번 남짓 바뀌는데 20번씩 다시 만들 이유가 없다.
    """
    C = rctx()
    st = C["store"]
    allf = request.args.get("all") == "1"
    return _cached_json(CASES_CACHE, f'{C["sys"]}|{"all" if allf else "act"}',
                        (st.rev, len(st.cases)),
                        lambda: {"cases": st.cases if allf else st.active()})


@app.route("/api/cases/<cid>")
def api_case(cid):
    C = rctx()
    c = C["store"].by_id(cid)
    return (jsonify(c), 200) if c else (jsonify({"error": "없는 케이스"}), 404)


@app.route("/api/cases/<cid>/<action>", methods=["POST"])
def api_case_action(cid, action):
    """확인 처리 / 이상 없음(재확인 예약만 갱신) / 종결."""
    C = rctx()
    body = request.get_json(silent=True) or {}
    who, note = body.get("who", "운영자"), body.get("note", "")
    fn = {"ack": C["store"].ack, "normal": C["store"].mark_normal, "close": C["store"].close}.get(action)
    if not fn:
        return jsonify({"error": "ack | normal | close 만 가능"}), 400
    c = fn(cid, who, note)
    if c is None:
        return jsonify({"error": "없는 케이스"}), 404
    if isinstance(c, dict) and c.get("error"):
        return jsonify(c), 409
    return jsonify(c)


@app.route("/api/cases/<cid>/judge", methods=["POST"])
def api_case_judge(cid):
    """LLM 판단 (스킬 4종 기반)."""
    C = rctx()
    c = C["store"].by_id(cid)
    if not c:
        return jsonify({"error": "없는 케이스"}), 404
    try:
        from llm_client import judge_case
        res, err = judge_case(c, C["cfg"])
    except Exception as e:
        res, err = None, f"{type(e).__name__}: {e}"
    if err:
        return jsonify({"error": err}), 502
    c["llm"] = {**res, "at": datetime.now().isoformat()}
    C["store"].save()
    return jsonify(c["llm"])


@app.route("/api/scan", methods=["POST"])
def api_scan():
    C = rctx()
    return jsonify(scan_once(C["store"], cfg=C["cfg"]))


# ────────────────────────────── 리포트 ──────────────────────────────
def _parse_dt(s: str | None, default: datetime) -> datetime:
    if not s:
        return default
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return default


@app.route("/api/report", methods=["POST"])
def api_report():
    """구간 지정 → 평가 실행."""
    C = rctx()
    """구간 리포트 — 기본은 로그프레소를 날짜로 직접 조회(관제와 분리).

    {"date": "2026-07-27"}                      → 그 날 하루 전체
    {"start": "...", "end": "..."}              → 지정 구간
    {"source": "store"}                         → 실시간 케이스 저장소 기준
    """
    b = request.get_json(silent=True) or {}
    if b.get("date"):
        try:
            d = datetime.strptime(b["date"][:10], "%Y-%m-%d")
        except ValueError:
            return jsonify({"error": "date 형식은 YYYY-MM-DD"}), 400
        # ★ 날짜 지정 = 하루 사건 리포트 (데모스 개인 에이전트 '사건발생 보고서' 와 같은 5섹션)
        if b.get("kind", "day") == "day":
            from report import build_day_report
            return jsonify(build_day_report(d.strftime("%Y%m%d"), C["cfg"],
                                            use_llm=b.get("use_llm", True)))
        start, end = d, d.replace(hour=23, minute=59, second=59)
    else:
        end = _parse_dt(b.get("end"), datetime.now())
        start = _parse_dt(b.get("start"), end - timedelta(minutes=30))

    rep = build_report(C["store"], start, end, C["cfg"],
                       use_llm=b.get("use_llm", True),
                       source=b.get("source", "query"))
    return jsonify(rep)


@app.route("/api/report/day.html")
def api_report_day_html():
    """하루 사건 리포트를 데모스 개인 에이전트와 같은 인터랙티브 HTML 로.

    /api/report/day.html?date=20260728  (없으면 오늘)
    체크박스 표·시간 시분 분리·O/X 판정·수동 기입·저장 툴바가 들어간다.
    """
    C = rctx()
    from report import build_day_report, day_report_html, load_day_report
    d = "".join(ch for ch in (request.args.get("date") or "") if ch.isdigit())[:8] \
        or datetime.now().strftime("%Y%m%d")
    use_llm = request.args.get("llm", "1") != "0"
    # 이미 생성해 둔 보고서가 있으면 그대로 연다 (다시 뽑으면 LLM 문장이 달라지므로)
    rep = (None if request.args.get("fresh") == "1" else load_day_report(d, C["cfg"])) \
        or build_day_report(d, C["cfg"], use_llm=use_llm)
    html = day_report_html(rep, C["cfg"])
    resp = app.response_class(html, mimetype="text/html; charset=utf-8")
    if request.args.get("download") == "1":
        # ★파일명에 한글을 쓰려면 RFC 5987 인코딩 — HTTP 헤더는 latin-1 만 담긴다
        from urllib.parse import quote as _q
        name = f"M16BR_사건발생보고서_{d}.html"
        resp.headers["Content-Disposition"] = (
            f'attachment; filename="M16BR_report_{d}.html"; '
            f"filename*=UTF-8''{_q(name)}")
    return resp


@app.route("/api/reports")
def api_reports():
    C = rctx()
    d = os.path.join(BASE_DIR, C["cfg"].get("storage", {}).get("reports", "data/reports"))
    if not os.path.isdir(d):
        return jsonify({"reports": []})
    out = []
    for fn in sorted(os.listdir(d), reverse=True)[:30]:
        if fn.endswith(".json"):
            try:
                with open(os.path.join(d, fn), "r", encoding="utf-8") as f:
                    r = json.load(f)
                s = r.get("summary") or {}
                out.append({"id": r["id"], "generated_at": r["generated_at"],
                            "kind": r.get("kind", "span"), "day": s.get("day", ""),
                            "span": s.get("span", ""), "count": s.get("count", 0)})
            except Exception:
                continue
    out.sort(key=lambda r: r.get("generated_at", ""), reverse=True)
    return jsonify({"reports": out})


@app.route("/api/reports/<rid>")
def api_report_get(rid):
    C = rctx()
    p = os.path.join(BASE_DIR, C["cfg"].get("storage", {}).get("reports", "data/reports"), rid + ".json")
    if not os.path.isfile(p):
        return jsonify({"error": "없는 리포트"}), 404
    with open(p, "r", encoding="utf-8") as f:
        return jsonify(json.load(f))


# ────────────────────────────── 피드백 ──────────────────────────────
@app.route("/api/feedback", methods=["POST"])
def api_feedback():
    C = rctx()
    b = request.get_json(silent=True) or {}
    res = save_feedback(b.get("report_id", ""), b.get("verdict", ""),
                        b.get("missed", ""), b.get("comment", ""),
                        b.get("who", "운영자"), C["cfg"])
    return (jsonify(res), 400) if res.get("error") else jsonify(res)


@app.route("/api/feedback/status")
def api_feedback_status():
    C = rctx()
    return jsonify(feedback_status(C["cfg"]))


# ────────────────────────────── 로그프레소 조회 ──────────────────────────────
@app.route("/api/query", methods=["POST"])
def api_query():
    """대시보드에서 직접 LPQL 조회 (읽기 전용 — lp_client 가 강제)."""
    b = request.get_json(silent=True) or {}
    lpql = (b.get("lpql") or "").strip()
    if not lpql:
        lpql = build(b.get("table"), duration=b.get("duration"),
                     from_dt=b.get("from"), to_dt=b.get("to"),
                     search=b.get("search"), limit=b.get("limit") or 100)
    rows, err = query(lpql)
    if err:
        return jsonify({"error": err.get("reason"), "lpql": lpql,
                        "preview": err.get("response_preview")}), 502
    return jsonify({"lpql": lpql, "count": len(rows), "rows": rows[: int(b.get("limit") or 100)]})


def _open_browser(url: str, delay: float = 1.2) -> None:
    """서버가 뜬 직후 대시보드를 브라우저로 자동 실행."""
    def go():
        time.sleep(delay)
        try:
            import webbrowser
            if webbrowser.open(url):
                print(f"  🌐 브라우저 실행: {url}")
                return
        except Exception:
            pass
        # 브라우저가 없는 환경(서버/원격) — 주소만 안내
        print(f"  ℹ️ 브라우저 자동 실행 실패 — 직접 여세요: {url}")
    threading.Thread(target=go, daemon=True).start()


def _lan_ips() -> list[str]:
    """이 PC 의 사내망 IP 목록 (외부에서 접속할 주소 안내용)."""
    import socket
    ips = set()
    try:
        # 기본 경로로 나가는 인터페이스의 IP (실제로 밖에서 보이는 주소)
        sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sk.connect(("8.8.8.8", 80))
            ips.add(sk.getsockname()[0])
        finally:
            sk.close()
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    return sorted(ip for ip in ips if not ip.startswith("127."))


if __name__ == "__main__":
    s = CFG.get("server", {})
    threading.Thread(target=_poll_loop, daemon=True).start()
    threading.Thread(target=_tune_loop, daemon=True).start()
    print("=" * 62)
    print("  AMHS Sentinel_M16BR — 독립 LLM 관제 시스템 (데모스 비의존)")
    from sentinel import source_mode
    if source_mode(CFG) == "jupyter":
        from jupyter_csv import cfg_of, file_url
        _jc = cfg_of(CFG)
        try:
            _ju = file_url(datetime.now().strftime("%Y%m%d"), _jc)
        except Exception as _e:
            _ju = f"(URL 설정 오류: {_e})"
        print(f"  데이터원   : 주피터 CSV (로그프레소 미사용)")
        print(f"               {_ju}")
    else:
        print(f"  로그프레소 : {CFG.get('logpresso_base')}  table={CFG.get('table_name')}")
        print(f"  AMOS      : {CFG['amos']['bottleneck']['table']} + {CFG['amos']['queue']['table']}")
    print(f"  모델       : {CFG.get('llm', {}).get('model')}")
    print(f"  폴링       : {CFG.get('query', {}).get('poll_interval_s')}초"
          + ("   [OFFLINE fixture 모드]" if os.getenv("LP_OFFLINE") == "1" else ""))
    host = s.get("host", "0.0.0.0")
    port = s.get("port", 8989)
    url = f"http://localhost:{port}/"
    print(f"  대시보드   : {url}")
    if host in ("0.0.0.0", "::"):
        # 외부(사내망)에서 접속할 주소를 그대로 알려준다 — 그냥 나눠주면 된다
        for ip in _lan_ips():
            print(f"             : http://{ip}:{port}/   ← 외부 접속용")
        print(f"  ℹ️ 외부에서 안 열리면 방화벽에서 TCP {port} 인바운드를 열어야 합니다")
    else:
        print(f"  ⚠️ host={host} — 이 PC 에서만 열립니다. 외부 공개는 config.server.host=0.0.0.0")
    print("=" * 62)

    # 실행하면 대시보드가 바로 뜨게 (config.server.auto_open=false 로 끌 수 있음)
    if s.get("auto_open", True) and os.getenv("NO_BROWSER") != "1":
        _open_browser(url)

    app.run(host=s.get("host", "0.0.0.0"), port=port, threaded=True, debug=False)
