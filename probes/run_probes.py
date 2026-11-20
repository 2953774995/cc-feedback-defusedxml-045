#!/usr/bin/env python3
"""验收探针：XML 解析安全审计（6 条契约）。全部离线，样本现场构造。"""
import sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
RESULTS = []

def probe(name):
    def deco(fn):
        try:
            fn()
        except AssertionError as exc:
            RESULTS.append((name, False, str(exc) or "断言失败"))
        except Exception as exc:
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            RESULTS.append((name, True, ""))
        return fn
    return deco

def audit():
    from defusedxml.audit import scan_documents
    return scan_documents

SAFE = b'<?xml version="1.0"?><root><item id="1">ok</item></root>'
BILLION = b'''<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>
<lolz>&lol3;</lolz>'''
XXE = b'''<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>'''
DEEP = b"<a>" * 400 + b"</a>" * 400

@probe("P01 批量入口与正常文档")
def p01():
    fn = audit(); out = fn([SAFE])
    assert hasattr(out, "items") and hasattr(out, "stats"), "需返回 items 与 stats"
    item = out.items[0]
    for k in ("index", "ok", "reason", "doctype", "entities", "issues"):
        assert k in item, f"item 缺字段 {k}"
    assert item["ok"] and item["reason"] == "ok", f"正常 XML 应 ok，实际 {item['reason']}"
    assert item["doctype"] is False and item["entities"] == [], f"不该有 DTD/实体：{item['doctype']}/{item['entities']}"

@probe("P02 实体膨胀")
def p02():
    fn = audit(); item = fn([BILLION]).items[0]
    assert item["reason"] == "entity_expansion", f"应为 entity_expansion，实际 {item['reason']}"
    assert not item["ok"] and item["entities"], "应列出实体名"

@probe("P03 外部实体")
def p03():
    fn = audit(); item = fn([XXE]).items[0]
    assert item["reason"] == "external_entity", f"应为 external_entity，实际 {item['reason']}"
    assert "file:///etc/passwd" in " ".join(str(x) for x in item.get("details", []) + item["issues"]), "应指出外部实体 URI"

@probe("P04 深嵌套")
def p04():
    fn = audit(); item = fn([DEEP]).items[0]
    assert item["reason"] == "deep_nesting", f"应为 deep_nesting，实际 {item['reason']}"

@probe("P05 坏文档隔离")
def p05():
    fn = audit(); out = fn([b"<a><b></a>", SAFE])
    assert out.items[0]["reason"] == "malformed", f"应为 malformed，实际 {out.items[0]['reason']}"
    assert out.items[1]["ok"], "坏样本之后应继续"

@probe("P06 统计、空输入与批量性能")
def p06():
    fn = audit(); out = fn([SAFE, XXE, b"<bad>"])
    st = out.stats
    assert st["ok"] == 1 and st["bad"] == 2, f"ok/bad 不对：{st}"
    assert st["by_reason"].get("external_entity") == 1, f"by_reason 不对：{st['by_reason']}"
    empty = fn([]); assert empty.items == [] and empty.stats["ok"] == 0, "空输入应返回空结构"
    docs = [SAFE, XXE, BILLION] * 300
    t0 = time.perf_counter(); out2 = fn(docs); cost = time.perf_counter() - t0
    assert len(out2.items) == 900 and cost < 3.0, f"900 条耗时 {cost:.2f}s 超过 3s"

def main():
    print("=" * 60); print("验收探针：XML 解析安全审计（6 条契约）"); print("=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, detail in RESULTS:
        print(f"PASS  {name}" if ok else f"FAIL  {name}\n      {detail}")
    print("-" * 60); print(f"探针结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1

if __name__ == "__main__":
    sys.exit(main())
