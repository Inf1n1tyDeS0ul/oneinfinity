#!/usr/bin/env bash
# =============================================================================
# verify_masterplan.sh — End-to-end verification of all Phase 0-3 features
# =============================================================================
REPO=/home/ubuntu/oneinfinity
REPORT=$REPO/logs/verification_report.txt
TARGET=http://testphp.vulnweb.com
API_KEY=ER93gkkRTyPz0qgru1kc1fFc4OtpgbVJ_xmQ-xKdC4E
BACKEND=http://localhost:3000

cd $REPO

{
echo ""
echo "============================================================"
echo " oneinfinity Enhancement Masterplan — Verification Report"
echo " Started: $(date)"
echo "============================================================"

# 0. Stop stuck scans
echo "[SETUP] Stopping stuck scans..."
curl -s -X POST -H "X-API-Key: $API_KEY" \
  "$BACKEND/api/god-mode/7e0c6982-e5dd-4e3a-8091-19af51798216/stop" > /dev/null 2>&1 || true
docker stop dvwa-test 2>/dev/null || true
sleep 2

# 1. Quality gates
echo ""
echo "=== [1/8] QUALITY GATES ==="
venv/bin/python -m compileall src/oneinfinity/ web/backend/ -q 2>&1 && echo "  G1 COMPILE: PASS" || echo "  G1 COMPILE: FAIL"
venv/bin/python -c "
import sys; sys.path.insert(0,'src'); sys.path.insert(0,'web/backend')
from oneinfinity.core.db_manager import get_db_manager
from oneinfinity.findings.finding_judge import get_judge
from oneinfinity.orchestration.god_mode_engine import GodModeSession,SCAN_TIER_MAX_TIME
from oneinfinity.core.benchmark_engine import OIBench,KNOWN_BENCH_TARGETS
from oneinfinity.core.deduplicator import SemanticDeduplicator
from oneinfinity.intelligence.application_intelligence import ApplicationIntelligenceEngine,AppModel
from oneinfinity.findings.post_scan_verifier import PostScanVerifier
from oneinfinity.learning.knowledge_distiller import CrossTargetKnowledgeDistiller
from oneinfinity.attack.nuclei_template_generator import auto_generate_from_confirmed
from oneinfinity.scan.second_order_tracker import SecondOrderTracker
from oneinfinity.scan.graphql_scan_engine import GraphQLScanEngine
from oneinfinity.scan.ssrf_scanner import SSRFScanner,_CLOUD_METADATA_TARGETS
from oneinfinity.orchestration.model_orchestrator import EnsembleScanOrchestrator
from oneinfinity.ai_security.indirect_prompt_injection_mapper import IndirectPromptInjectionMapper
from oneinfinity.pipeline.canonical import PHASE_MAP
from oneinfinity.scan.unified_scan_engine import UnifiedScanEngine
from oneinfinity.infra.llm_provider import LLMProviderFactory
from oneinfinity.attack_graph_core.risk_analyzer import RiskAnalyzer
print('  G2 IMPORTS: PASS')
" 2>&1
curl -s -o /dev/null -w "  G3 HEALTH: HTTP %{http_code}\n" "$BACKEND/health"
bash scripts/check_process_hygiene.sh > /dev/null 2>&1 && echo "  G4 HYGIENE: PASS" || echo "  G4 HYGIENE: FAIL"

# 2. Phase 0 checks
echo ""
echo "=== [2/8] PHASE 0 — Verified Finding Architecture ==="
venv/bin/python -c "
import sys,os; sys.path.insert(0,'src')
os.environ['POSTGRES_URL']='postgresql://oneinfinity:oneinfinity123@localhost:5432/oneinfinity'
os.environ['DISTRIBUTED_MODE']='true'
from oneinfinity.findings.finding_judge import FindingJudge,TIER_CONFIRMED,TIER_INFERRED,TIER_CANDIDATE
j=FindingJudge()
v1=j._heuristic_verdict({'finding_id':'x','vuln_type':'sqli','confidence':0.95,'severity':'critical'},TIER_CONFIRMED)
v2=j._heuristic_verdict({'finding_id':'y','vuln_type':'xss','confidence':0.65,'severity':'medium'},TIER_INFERRED)
assert v1.tier==TIER_CONFIRMED and v2.tier==TIER_INFERRED
print('  FindingJudge heuristic tier: PASS')
import asyncio
async def schema():
    from oneinfinity.core.db_manager import get_db_manager
    db=await get_db_manager()
    rows=await db.pg_execute_read(\"SELECT column_name FROM information_schema.columns WHERE table_name='findings' AND column_name IN ('confirmed_tier','discovered_by','judge_ran_at') ORDER BY column_name\")
    cols=[r['column_name'] for r in rows]
    assert 'confirmed_tier' in cols,'confirmed_tier missing'
    print(f'  DB schema {cols}: PASS')
asyncio.run(schema())
from oneinfinity.orchestration.offensive_router import MODEL_ROUTING_TABLE
assert 'finding_verification' in MODEL_ROUTING_TABLE
print('  MODEL_ROUTING_TABLE: PASS')
from oneinfinity.findings.result_ingestion_engine import NormalizedFinding
f=NormalizedFinding(scan_id='x',target='t',title='T',severity='high',vuln_type='sqli',evidence='e',tool='s',confirmed_tier='CONFIRMED',discovered_by=['claude'])
d=f.to_dict()
assert d['confirmed_tier']=='CONFIRMED'
print('  NormalizedFinding confirmed_tier: PASS')
" 2>&1

# 3. Phase 1 checks
echo ""
echo "=== [3/8] PHASE 1 — Core Coverage Gaps ==="
venv/bin/python -c "
import sys; sys.path.insert(0,'src')
import logging; logging.disable(logging.CRITICAL)
from oneinfinity.intelligence.application_intelligence import AppModel
m=AppModel(target='t',intent_built=True,primary_flows=[{'name':'login','steps':['/login'],'invariants':['auth required']}],trust_boundaries={'public':['/'],'authenticated':['/account'],'privileged':['/admin']})
d=m.to_dict()
m2=AppModel.from_dict(d)
assert m2.intent_built and len(m2.primary_flows)==1 and 'authenticated' in m2.trust_boundaries
print('  AppModel intent fields (flows/invariants/trust_boundaries): PASS')
from oneinfinity.scan.second_order_tracker import SecondOrderTracker
t=SecondOrderTracker('https://t.com','s1')
src=t._discover_data_sources(['https://t.com/profile','https://t.com/admin','https://t.com/docs/x','https://t.com/messages'])
assert len(src)>0,f'no sources found'
print(f'  SecondOrderTracker discover_data_sources: PASS ({len(src)} sources)')
from oneinfinity.core.deduplicator import SemanticDeduplicator
sd=SemanticDeduplicator()
f2=[{'vuln_type':'sqli','url':'/u/1','parameter':'id','confidence':0.9},{'vuln_type':'sqli','url':'/u/2','parameter':'id','confidence':0.8},{'vuln_type':'xss','url':'/s','parameter':'q','confidence':0.7}]
out=sd.cluster_root_causes(f2,use_llm=False)
sqli=[x for x in out if x['vuln_type']=='sqli'][0]
assert sqli['instance_count']==2 and len(sqli['affected_urls'])==2
print(f'  SemanticDeduplicator: PASS (3 findings -> {len(out)} clusters, sqli instance_count=2)')
from oneinfinity.orchestration.god_mode_engine import SCAN_TIER_MAX_TIME
from oneinfinity.core.scan_profiles import PROFILES
assert SCAN_TIER_MAX_TIME['quick']==1800 and SCAN_TIER_MAX_TIME['marathon']==86400
assert 'standard' in PROFILES and 'marathon' in PROFILES
print('  Scan tiers quick/standard/deep/marathon: PASS')
" 2>&1

# 4. Phase 2 checks
echo ""
echo "=== [4/8] PHASE 2 — New Attack Surfaces ==="
venv/bin/python -c "
import sys; sys.path.insert(0,'src')
from oneinfinity.orchestration.model_orchestrator import EnsembleScanOrchestrator
e=EnsembleScanOrchestrator(); assert hasattr(e,'run')
print('  EnsembleScanOrchestrator: PASS')
from oneinfinity.ai_security.indirect_prompt_injection_mapper import IndirectPromptInjectionMapper
m=IndirectPromptInjectionMapper('https://t.com','s1')
s=m._discover_data_sources(['https://t.com/api/users/1','https://t.com/profile','https://t.com/messages/1','https://t.com/webhooks'])
assert len(s)>0
print(f'  IndirectPromptInjectionMapper: PASS ({len(s)} sources)')
from oneinfinity.scan.graphql_scan_engine import GraphQLScanEngine
g=GraphQLScanEngine('https://t.com')
assert all(hasattr(g,m) for m in ['test_batch_credential_stuffing','test_subscription_idor','test_persisted_query_enum','test_type_confusion_injection'])
print('  GraphQLScanEngine 4 new methods: PASS')
from oneinfinity.scan.ssrf_scanner import _CLOUD_METADATA_TARGETS,_INTERNAL_SERVICE_TARGETS,SSRFScanner
assert 'aws_imdsv2' in _CLOUD_METADATA_TARGETS and 'kubernetes_api' in _INTERNAL_SERVICE_TARGETS
assert hasattr(SSRFScanner.__new__(SSRFScanner),'test_imdsv2')
print('  Cloud SSRF (IMDSv2/ECS/K8s): PASS')
from oneinfinity.mobile.backend_differential_analyzer import MobileBackendDifferentialAnalyzer,_MOBILE_HEADERS_ANDROID
assert 'X-App-Version' in _MOBILE_HEADERS_ANDROID
print('  MobileBackendDifferentialAnalyzer: PASS')
from oneinfinity.scan.supply_chain_attack_engine import SupplyChainAttackEngine
s2=SupplyChainAttackEngine()
assert hasattr(s2,'test_sri_audit') and hasattr(s2,'test_third_party_script_behavior')
print('  SupplyChainAttackEngine (SRI+CDN): PASS')
from oneinfinity.scan.websocket_scanner import WebSocketScanner
assert hasattr(WebSocketScanner.__new__(WebSocketScanner),'test_auth_state_divergence')
print('  WebSocketScanner.test_auth_state_divergence: PASS')
from oneinfinity.scan.cache_deception_scanner import CacheDeceptionScanner
cc=CacheDeceptionScanner.__new__(CacheDeceptionScanner)
assert hasattr(cc,'test_fat_get') and hasattr(cc,'test_web_cache_deception_path')
print('  CacheDeceptionScanner (fat_get/wcd_path): PASS')
" 2>&1

# 5. Phase 3 checks
echo ""
echo "=== [5/8] PHASE 3 — Self-Improvement ==="
venv/bin/python -c "
import sys; sys.path.insert(0,'src')
from oneinfinity.core.benchmark_engine import OIBench,KNOWN_BENCH_TARGETS
assert all(t in KNOWN_BENCH_TARGETS for t in ['juice_shop','dvwa','webgoat'])
bench=OIBench()
findings=[{'finding_id':'f1','vuln_type':'sqli','url':'/vulnerabilities/sqli/?id=1','confidence':0.9},{'finding_id':'f2','vuln_type':'xss_reflected','url':'/vulnerabilities/xss_r/','confidence':0.85},{'finding_id':'f3','vuln_type':'cmdi','url':'/vulnerabilities/exec/','confidence':0.8}]
result=bench.score_from_findings(findings,'dvwa',scan_id='test')
assert result.found_count==3 and result.recall>0
print(f'  OIBench dvwa: PASS recall={result.recall:.0%} ({result.found_count}/{result.known_count})')
from oneinfinity.learning.hitl_rl_engine import HITLRLEngine
assert hasattr(HITLRLEngine,'update_prompt_strategy') and hasattr(HITLRLEngine,'get_best_prompt_strategy')
key=HITLRLEngine._tech_stack_key(['React','JWT','Node.js'])
assert key=='jwt,node.js,react'
print(f'  HITL prompt strategy (tech_stack_key={key}): PASS')
from oneinfinity.findings.post_scan_verifier import PostScanVerifier
v=PostScanVerifier()
assert v.sample_rate==0.20 and v.verify_scan('x','https://t.com')==[]
print('  PostScanVerifier: PASS')
from oneinfinity.learning.knowledge_distiller import CrossTargetKnowledgeDistiller
d=CrossTargetKnowledgeDistiller()
stats=d._aggregate_vuln_stats([{'vuln_type':'sqli','cvss':9.0,'tool':'sqlmap','confirmed_tier':'CONFIRMED'},{'vuln_type':'sqli','cvss':8.0,'tool':'sqlmap'}])
assert stats['sqli']['count']==2 and stats['sqli']['avg_cvss']==8.5
print('  CrossTargetKnowledgeDistiller: PASS')
from oneinfinity.attack.nuclei_template_generator import auto_generate_from_confirmed
assert auto_generate_from_confirmed({'confirmed_tier':'CANDIDATE','vuln_type':'sqli','url':'https://t.com'}) is None
assert auto_generate_from_confirmed({'confirmed_tier':'CONFIRMED','vuln_type':'sqli','url':''}) is None
print('  nuclei auto_generate_from_confirmed guards: PASS')
" 2>&1

# 6. Live scan
echo ""
echo "=== [6/8] LIVE SCAN — testphp.vulnweb.com ==="
echo "  Launching God Mode (quick tier = 30 min)..."
SCAN_RESP=$(curl -s -X POST "$BACKEND/api/scan/god-mode" \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target":"http://testphp.vulnweb.com","scan_tier":"quick","app_context":"Acunetix deliberately vulnerable PHP application. Expected findings: sqli, xss, cmdi, path_traversal, file_upload."}')
SCAN_ID=$(echo "$SCAN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('scan_id',''))" 2>/dev/null)
echo "  scan_id: $SCAN_ID"
echo "$SCAN_ID" > /tmp/verify_scan_id.txt
if [ -z "$SCAN_ID" ]; then
  echo "  FAIL: $SCAN_RESP"
else
  echo "  Polling every 30s for up to 20 min..."
  for i in $(seq 1 40); do
    sleep 30
    STATE_FILE="/home/ubuntu/.oneinfinity/god-mode-$SCAN_ID.json"
    if [ -f "$STATE_FILE" ]; then
      INFO=$(python3 -c "
import json,sys
d=json.load(open('$STATE_FILE'))
phases=','.join(d.get('phases_complete',[])[:5])
n=d.get('finding_count',0)
t=round(d.get('elapsed',0)/60,1)
term=d.get('terminated_by','running')
print(f'phases={phases} findings={n} elapsed={t}min term={term}')
" 2>/dev/null)
      echo "  [${i}x30s] $INFO"
      if echo "$INFO" | grep -qE "term=(convergence|stop|error)"; then
        echo "  Scan complete"
        break
      fi
    fi
  done
fi

# 7. Score + judge check
echo ""
echo "=== [7/8] OI-BENCH + FINDINGS VERIFICATION ==="
SCAN_ID=$(cat /tmp/verify_scan_id.txt 2>/dev/null || echo "")
if [ -n "$SCAN_ID" ]; then
venv/bin/python << PYEOF
import os,sys,asyncio
sys.path.insert(0,'src')
os.environ['POSTGRES_URL']='postgresql://oneinfinity:oneinfinity123@localhost:5432/oneinfinity'
os.environ['DISTRIBUTED_MODE']='true'
async def main():
    from oneinfinity.core.db_manager import get_db_manager
    db=await get_db_manager()
    rows=await db._pg_get_findings(scan_id='$SCAN_ID',limit=200)
    total=len(rows)
    tiers={}
    for r in rows:
        ct=str(r.get('confirmed_tier') or 'UNJUDGED')
        tiers[ct]=tiers.get(ct,0)+1
    print(f'  Total findings: {total}')
    print(f'  By confirmed_tier: {tiers}')
    for r in rows[:15]:
        ct=r.get('confirmed_tier') or 'UNJUDGED'
        print(f'    {str(r.get("vuln_type","")):<28} {str(r.get("severity","")):<8} {ct:<12} conf={float(r.get("confidence") or 0):.2f}')
    from oneinfinity.core.benchmark_engine import OIBench
    bench=OIBench()
    bench.add_custom_target(name='testphp',url='http://testphp.vulnweb.com',known_vulns=[
        {'vuln_type':'sqli','url_pattern':'/listproducts','severity':'critical'},
        {'vuln_type':'xss','url_pattern':'/search','severity':'medium'},
        {'vuln_type':'path_traversal','url_pattern':'/showimage','severity':'high'},
        {'vuln_type':'cmdi','url_pattern':'/','severity':'critical'},
        {'vuln_type':'file_upload','url_pattern':'/userinfo','severity':'high'},
    ])
    result=bench.score(scan_id='$SCAN_ID',target_name='testphp')
    print(f'  OI-Bench testphp: {result.summary()}')
    print(f'  Coverage by category: {result.coverage_by_category}')
asyncio.run(main())
PYEOF
fi

# 8. Final state
echo ""
echo "=== [8/8] DISTILLATION + NUCLEI TEMPLATES ==="
venv/bin/python << PYEOF
import os,sys,asyncio
sys.path.insert(0,'src')
os.environ['POSTGRES_URL']='postgresql://oneinfinity:oneinfinity123@localhost:5432/oneinfinity'
os.environ['DISTRIBUTED_MODE']='true'
async def main():
    from oneinfinity.core.db_manager import get_db_manager
    db=await get_db_manager()
    try:
        rows=await db.pg_execute_read("SELECT tool_name,vuln_type,findings_total FROM tool_performance ORDER BY findings_total DESC LIMIT 8")
        print(f'  tool_performance rows: {len(rows)}')
        for r in rows[:5]:
            print(f'    {str(r.get("tool_name","")):<20} {str(r.get("vuln_type","")):<25} findings={r.get("findings_total",0)}')
    except Exception as e:
        print(f'  tool_performance: {e}')
    import os as _os
    d=_os.path.expanduser('~/.oneinfinity/nuclei-templates')
    if _os.path.isdir(d):
        dirs=list(_os.listdir(d))
        from pathlib import Path
        yamls=list(Path(d).rglob('*.yaml'))
        print(f'  Nuclei templates: {len(dirs)} vuln-type dirs, {len(yamls)} .yaml files')
        for y in yamls[:5]:
            print(f'    {y.name}')
    else:
        print('  Nuclei templates: none yet (need CONFIRMED findings to auto-generate)')
    try:
        migs=await db.pg_execute_read("SELECT migration_id FROM migrations_registry ORDER BY applied_at")
        print(f'  Migrations: {[str(r.get("migration_id","")) for r in migs]}')
    except Exception as e:
        print(f'  migrations_registry: {e}')
asyncio.run(main())
PYEOF

echo ""
echo "============================================================"
echo " VERIFICATION COMPLETE: $(date)"
echo " Report: $REPORT"
echo "============================================================"
} 2>&1 | tee "$REPORT"
