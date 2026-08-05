import sys, os, asyncio
sys.path.insert(0, 'src')
os.environ['POSTGRES_URL'] = 'postgresql://oneinfinity:oneinfinity123@localhost:5432/oneinfinity'
os.environ['DISTRIBUTED_MODE'] = 'true'

results = []

def check(name, fn):
    try:
        fn()
        results.append(('PASS', name))
        print('  PASS  ' + name)
    except Exception as e:
        results.append(('FAIL', name, str(e)[:120]))
        print('  FAIL  ' + name + ': ' + str(e)[:120])

# Phase 0
def p0_judge():
    from oneinfinity.findings.finding_judge import FindingJudge, TIER_CONFIRMED, TIER_INFERRED, TIER_CANDIDATE
    j = FindingJudge()
    assert j._heuristic_verdict({'finding_id':'x','vuln_type':'sqli','confidence':0.95,'severity':'h'}, TIER_CONFIRMED).tier == TIER_CONFIRMED
    assert j._heuristic_verdict({'finding_id':'y','vuln_type':'xss','confidence':0.65,'severity':'m'}, TIER_INFERRED).tier  == TIER_INFERRED
    assert j._heuristic_verdict({'finding_id':'z','vuln_type':'i','confidence':0.3,'severity':'l'}, TIER_CANDIDATE).tier   == TIER_CANDIDATE

def p0_schema():
    async def _():
        from oneinfinity.core.db_manager import get_db_manager
        db = await get_db_manager()
        rows = await db.pg_execute_read("SELECT column_name FROM information_schema.columns WHERE table_name='findings' AND column_name IN ('confirmed_tier','discovered_by','judge_ran_at') ORDER BY column_name")
        cols = [r['column_name'] for r in rows]
        assert set(cols) == {'confirmed_tier','discovered_by','judge_ran_at'}, 'Missing: ' + str(cols)
    asyncio.run(_())

def p0_routing():
    from oneinfinity.orchestration.offensive_router import MODEL_ROUTING_TABLE
    assert 'finding_verification' in MODEL_ROUTING_TABLE
    assert MODEL_ROUTING_TABLE['finding_verification']['preferred_task_type'] == 'judge'
    assert 'xss_payload_generation' in MODEL_ROUTING_TABLE

def p0_normalized_finding():
    from oneinfinity.findings.result_ingestion_engine import NormalizedFinding
    f = NormalizedFinding(scan_id='x',target='t',title='T',severity='h',vuln_type='sqli',evidence='e',tool='s',confirmed_tier='CONFIRMED',discovered_by=['claude'])
    d = f.to_dict()
    assert d['confirmed_tier'] == 'CONFIRMED'
    assert d['discovered_by'] == ['claude']

# Phase 1
def p1_app_model():
    from oneinfinity.intelligence.application_intelligence import AppModel
    import logging; logging.disable(logging.CRITICAL)
    m = AppModel(target='t', intent_built=True,
                 primary_flows=[{'name':'checkout','steps':['/cart'],'invariants':['auth required']}],
                 trust_boundaries={'public':['/'],'authenticated':['/account'],'privileged':['/admin']},
                 sensitive_objects=[{'name':'Order','owner_field':'user_id','endpoints':['/orders']}])
    d = m.to_dict()
    m2 = AppModel.from_dict(d)
    assert m2.intent_built and len(m2.primary_flows)==1 and 'authenticated' in m2.trust_boundaries

def p1_second_order():
    from oneinfinity.scan.second_order_tracker import SecondOrderTracker
    t = SecondOrderTracker('https://t.com','s1')
    grid = t.build_observation_grid(['https://t.com/admin','https://t.com/profile','https://t.com/export/data','https://t.com/messages'])
    assert len(grid) >= 4
    roles = {obs.role for obs in grid}
    assert 'admin' in roles and 'authenticated' in roles

def p1_semantic_dedup():
    from oneinfinity.core.deduplicator import SemanticDeduplicator
    sd = SemanticDeduplicator()
    findings = [
        {'vuln_type':'sqli','url':'/u/1','parameter':'id','confidence':0.9},
        {'vuln_type':'sqli','url':'/u/2','parameter':'id','confidence':0.8},
        {'vuln_type':'sqli','url':'/u/3','parameter':'id','confidence':0.7},
        {'vuln_type':'xss', 'url':'/s',  'parameter':'q', 'confidence':0.7},
    ]
    out = sd.cluster_root_causes(findings, use_llm=False)
    sqli = next(f for f in out if f['vuln_type']=='sqli')
    assert sqli['instance_count'] == 3 and len(sqli['affected_urls']) == 3
    assert len(out) == 2

def p1_scan_tiers():
    from oneinfinity.orchestration.god_mode_engine import SCAN_TIER_MAX_TIME
    from oneinfinity.core.scan_profiles import PROFILES
    assert SCAN_TIER_MAX_TIME == {'quick':1800,'standard':7200,'deep':21600,'marathon':86400}
    assert all(t in PROFILES for t in ['quick','standard','deep','marathon','research','swarm','stealth'])

# Phase 2
def p2_ensemble():
    from oneinfinity.orchestration.model_orchestrator import EnsembleScanOrchestrator
    e = EnsembleScanOrchestrator()
    assert callable(e.run) and callable(e._build_model_tasks)

def p2_ipi():
    from oneinfinity.ai_security.indirect_prompt_injection_mapper import IndirectPromptInjectionMapper, _CANARY_INSTRUCTIONS
    m = IndirectPromptInjectionMapper('https://t.com','s1')
    sources = m._discover_data_sources(['https://t.com/api/users/1','https://t.com/profile','https://t.com/messages/1','https://t.com/admin/webhooks'])
    assert len(sources) >= 3
    assert len(_CANARY_INSTRUCTIONS) >= 3

def p2_graphql():
    from oneinfinity.scan.graphql_scan_engine import GraphQLScanEngine
    g = GraphQLScanEngine('https://t.com')
    for m in ['test_batch_credential_stuffing','test_subscription_idor','test_persisted_query_enum','test_type_confusion_injection']:
        assert hasattr(g, m), 'missing: ' + m

def p2_cloud_ssrf():
    from oneinfinity.scan.ssrf_scanner import _CLOUD_METADATA_TARGETS, _INTERNAL_SERVICE_TARGETS, SSRFScanner
    assert 'aws_imdsv2' in _CLOUD_METADATA_TARGETS
    assert 'aws_ecs' in _CLOUD_METADATA_TARGETS
    assert any('169.254.170.2' in u for u in _CLOUD_METADATA_TARGETS['aws_ecs'])
    assert 'kubernetes_api' in _INTERNAL_SERVICE_TARGETS
    assert 'ecs_task_metadata' in _INTERNAL_SERVICE_TARGETS
    assert hasattr(SSRFScanner.__new__(SSRFScanner), 'test_imdsv2')

def p2_mobile():
    from oneinfinity.mobile.backend_differential_analyzer import MobileBackendDifferentialAnalyzer, _MOBILE_HEADERS_ANDROID, _MOBILE_HEADERS_IOS
    assert 'X-App-Version' in _MOBILE_HEADERS_ANDROID and 'X-Platform' in _MOBILE_HEADERS_IOS
    m = MobileBackendDifferentialAnalyzer('https://t.com','s1')
    assert callable(m.run)

def p2_supply_chain():
    from oneinfinity.scan.supply_chain_attack_engine import SupplyChainAttackEngine
    s = SupplyChainAttackEngine()
    assert hasattr(s,'test_sri_audit') and hasattr(s,'test_third_party_script_behavior')

def p2_websocket():
    from oneinfinity.scan.websocket_scanner import WebSocketScanner
    w = WebSocketScanner.__new__(WebSocketScanner)
    assert hasattr(w,'test_auth_state_divergence') and hasattr(w,'test_cswsh')

def p2_cache():
    from oneinfinity.scan.cache_deception_scanner import CacheDeceptionScanner
    c = CacheDeceptionScanner.__new__(CacheDeceptionScanner)
    assert hasattr(c,'test_fat_get') and hasattr(c,'test_web_cache_deception_path')

# Phase 3
def p3_oibench():
    from oneinfinity.core.benchmark_engine import OIBench, KNOWN_BENCH_TARGETS
    assert all(t in KNOWN_BENCH_TARGETS for t in ['juice_shop','dvwa','webgoat'])
    bench = OIBench()
    findings = [
        {'finding_id':'f1','vuln_type':'sqli',         'url':'/vulnerabilities/sqli/?id=1','confidence':0.9},
        {'finding_id':'f2','vuln_type':'xss_reflected', 'url':'/vulnerabilities/xss_r/','confidence':0.85},
        {'finding_id':'f3','vuln_type':'cmdi',          'url':'/vulnerabilities/exec/','confidence':0.8},
        {'finding_id':'f4','vuln_type':'file_upload',   'url':'/vulnerabilities/upload/','confidence':0.75},
    ]
    r = bench.score_from_findings(findings,'dvwa',scan_id='test')
    assert r.found_count == 4 and r.recall >= 0.57

def p3_hitl():
    from oneinfinity.learning.hitl_rl_engine import HITLRLEngine
    assert hasattr(HITLRLEngine,'update_prompt_strategy')
    assert hasattr(HITLRLEngine,'get_best_prompt_strategy')
    assert HITLRLEngine._tech_stack_key(['React','JWT','Node.js']) == 'jwt,node.js,react'
    assert HITLRLEngine._tech_stack_key([]) == ''

def p3_verifier():
    from oneinfinity.findings.post_scan_verifier import PostScanVerifier
    v = PostScanVerifier(sample_rate=0.20)
    assert v.sample_rate == 0.20 and v.max_findings == 50
    assert v.verify_scan('nonexistent','https://t.com') == []

def p3_distiller():
    from oneinfinity.learning.knowledge_distiller import CrossTargetKnowledgeDistiller
    d = CrossTargetKnowledgeDistiller()
    stats = d._aggregate_vuln_stats([
        {'vuln_type':'sqli','cvss':9.0,'tool':'sqlmap','confirmed_tier':'CONFIRMED'},
        {'vuln_type':'sqli','cvss':8.0,'tool':'sqlmap'},
        {'vuln_type':'xss', 'cvss':6.5,'tool':'dalfox'},
    ])
    assert stats['sqli']['count']==2 and stats['sqli']['avg_cvss']==8.5 and stats['sqli']['confirmed']==1
    assert stats['xss']['best_tool'] == 'dalfox'

def p3_nuclei():
    from oneinfinity.attack.nuclei_template_generator import auto_generate_from_confirmed
    assert auto_generate_from_confirmed({'confirmed_tier':'CANDIDATE','vuln_type':'sqli','url':'https://t.com'}) is None
    assert auto_generate_from_confirmed({'confirmed_tier':'CONFIRMED','vuln_type':'sqli','url':''}) is None
    assert auto_generate_from_confirmed({'confirmed_tier':'CONFIRMED','vuln_type':'','url':'https://t.com/x'}) is None

def p3_db_confirmed_tier():
    async def _():
        from oneinfinity.core.db_manager import get_db_manager
        db = await get_db_manager()
        rows = await db._pg_get_findings(limit=300)
        judged = [r for r in rows if r.get('confirmed_tier')]
        assert len(judged) > 0, 'No judged findings in DB'
        tiers = set(str(r.get('confirmed_tier')) for r in judged)
        assert tiers <= {'CONFIRMED','INFERRED','CANDIDATE'}, 'Unexpected tiers: ' + str(tiers)
        print('    ' + str(len(judged)) + ' findings judged, tiers: ' + str(sorted(tiers)))
    asyncio.run(_())

def p3_nuclei_templates_on_disk():
    import os
    d = os.path.expanduser('~/.oneinfinity/nuclei-templates')
    assert os.path.isdir(d), 'nuclei-templates dir missing'
    from pathlib import Path
    yamls = list(Path(d).rglob('*.yaml'))
    assert len(yamls) > 0, 'No .yaml files'
    print('    ' + str(len(yamls)) + ' nuclei templates in ' + d)

# Run
print('=== Phase 0 — Verified Finding Architecture ===')
for fn in [p0_judge, p0_schema, p0_routing, p0_normalized_finding]:
    check(fn.__name__[3:], fn)

print()
print('=== Phase 1 — Core Coverage Gaps ===')
for fn in [p1_app_model, p1_second_order, p1_semantic_dedup, p1_scan_tiers]:
    check(fn.__name__[3:], fn)

print()
print('=== Phase 2 — New Attack Surfaces ===')
for fn in [p2_ensemble, p2_ipi, p2_graphql, p2_cloud_ssrf, p2_mobile, p2_supply_chain, p2_websocket, p2_cache]:
    check(fn.__name__[3:], fn)

print()
print('=== Phase 3 — Self-Improvement ===')
for fn in [p3_oibench, p3_hitl, p3_verifier, p3_distiller, p3_nuclei, p3_db_confirmed_tier, p3_nuclei_templates_on_disk]:
    check(fn.__name__[3:], fn)

print()
passed = sum(1 for r in results if r[0]=='PASS')
failed = [r for r in results if r[0]=='FAIL']
print('=== RESULT: ' + str(passed) + '/' + str(len(results)) + ' PASS ===')
if failed:
    print('FAILURES:')
    for r in failed:
        print('  ' + r[1] + ': ' + r[2])
else:
    print('ALL CHECKS PASSED')
