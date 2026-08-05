import sys, os, asyncio, uuid
sys.path.insert(0,'src')
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path('.env'), override=True)
os.environ.setdefault('POSTGRES_URL','postgresql://oneinfinity:oneinfinity123@localhost:5432/oneinfinity')
os.environ.setdefault('DISTRIBUTED_MODE','true')

TEST_ID = 'judge-test-' + uuid.uuid4().hex[:8]

async def main():
    from oneinfinity.core.db_manager import get_db_manager
    db = await get_db_manager()

    finding = {
        'finding_id': TEST_ID,
        'scan_id': 'judge-test-scan',
        'target': 'http://testphp.vulnweb.com',
        'title': 'SQL Injection in listproducts.php',
        'severity': 'critical',
        'vuln_type': 'sqli',
        'url': 'http://testphp.vulnweb.com/listproducts.php',
        'tool': 'sqlmap',
        'confidence': 0.92,
        'evidence': "SQL syntax error near 1'' at line 1. Data returned: user@host",
        'payload': "1'",
        'source_type': 'tool',
    }
    await db.save_finding(finding)
    print('Finding saved:', TEST_ID)

    from oneinfinity.findings.finding_judge import get_judge
    judge = get_judge()
    verdict = judge.evaluate(finding)
    print('--- Judge verdict ---')
    print('  tier:       ', verdict.tier)
    print('  confidence: ', round(verdict.confidence, 3))
    print('  fp_risk:    ', verdict.fp_risk)
    print('  model_used: ', verdict.model_used)
    print('  reasoning:  ', verdict.reasoning[:150])

    await db.update_finding_judge(
        finding_id=TEST_ID,
        confirmed_tier=verdict.tier,
        judge_verdict=verdict.to_dict(),
    )

    rows = await db._pg_get_findings(scan_id='judge-test-scan', limit=5)
    for r in rows:
        if r.get('finding_id') == TEST_ID:
            ct = r.get('confirmed_tier')
            jv = r.get('judge_verdict') or {}
            model = jv.get('model_used','') if isinstance(jv,dict) else ''
            print('--- DB verification ---')
            print('  confirmed_tier:', ct)
            print('  judge model:   ', model)

asyncio.run(main())
