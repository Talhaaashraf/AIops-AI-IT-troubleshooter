"""Provider integration contracts; all HTTP is mocked and samples are synthetic bytes."""
import asyncio
import hashlib
import io
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request
from starlette.datastructures import UploadFile

from backend import auth, intelligence as intel, intelligence_jobs as jobs, intelligence_secrets as vault
from backend import security_samples as samples, security_store as store

SHA = 'a' * 64
CONTENT = b'Synthetic inert test data, never a real sample.'
FILE_SHA = hashlib.sha256(CONTENT).hexdigest()
KEY = 'k' * 64


def enable(provider='virustotal', **extra):
    return intel.configure(provider, dict(api_key=KEY, enabled=True, business_authorized=True,
        use_basis='Synthetic permission for mocked tests only', upload_authorized=True, **extra))


def request():
    return Request({'type': 'http', 'scheme': 'https', 'server': ('sentinel.test', 443), 'path': '/', 'headers': []})


@pytest.fixture
def transport(monkeypatch):
    client = httpx.Client
    calls = []
    response = {'status': 200, 'json': {'data': {'id': SHA, 'attributes': {'last_analysis_stats': {'malicious': 1}}}}}
    def handle(req):
        calls.append(req)
        if response.get('error'):
            raise response['error']
        return httpx.Response(response['status'], json=response.get('json'), headers=response.get('headers', {}))
    monkeypatch.setattr(intel.httpx, 'Client', lambda **kwargs: client(transport=httpx.MockTransport(handle), **kwargs))
    return calls, response


def test_credentials_encrypted_rotation_deletion_and_no_echo(monkeypatch):
    monkeypatch.setenv('SENTINEL_INTELLIGENCE_MASTER_KEY', Fernet.generate_key().decode())
    result = enable()
    assert KEY not in json.dumps(result)
    with store.connect() as db:
        ciphertext = db.execute('SELECT ciphertext FROM intelligence_credentials').fetchone()[0]
    assert KEY not in ciphertext
    monkeypatch.setattr(vault, '_cipher', None)
    assert vault.get('virustotal') == KEY
    intel.configure('virustotal', {'api_key': 'z'*64})
    assert vault.get('virustotal') == 'z'*64
    intel.configure('virustotal', {'api_key': ''})
    assert vault.get('virustotal') is None
    with store.connect() as db:
        assert not db.execute('SELECT * FROM intelligence_credentials').fetchall()
        assert KEY not in str([tuple(row) for row in db.execute('SELECT * FROM intelligence_audit')])


def test_memory_credentials_are_encrypted_and_restart_loses_them(monkeypatch):
    enable()
    assert vault._memory['virustotal'] != KEY
    with store.connect() as db:
        assert not db.execute('SELECT * FROM intelligence_credentials').fetchall()
    monkeypatch.setattr(vault, '_memory', {})
    assert not intel.allowed('virustotal')


@pytest.mark.parametrize('payload', [{'api_key': 'short'}, {'api_key': 123}, {'enabled': 'yes'}, {'enabled': True}, {'business_authorized': True, 'use_basis': 'key'}, {'per_minute': 0}, {'per_day': True}])
def test_invalid_configuration(payload):
    with pytest.raises(HTTPException): intel.configure('virustotal', payload)


def test_authentication_origin_and_https(monkeypatch):
    monkeypatch.setenv('DASHBOARD_PASSWORD', 'test-password')
    app = FastAPI(); app.include_router(intel.router); app.include_router(samples.router)
    with TestClient(app, base_url='https://sentinel.test') as client:
        assert client.post('/api/threat-intelligence/virustotal/settings', json={'api_key': KEY}).status_code == 401
        client.cookies.set(auth.SESSION_COOKIE_NAME, auth.session_token())
        assert client.post('/api/threat-intelligence/virustotal/settings', headers={'Origin':'https://attacker.test'}, json={'api_key':KEY}).status_code == 403
        assert client.post('/api/threat-intelligence/virustotal/settings', headers={'Sec-Fetch-Site':'cross-site'}, json={}).status_code == 403
        assert client.post('/api/threat-intelligence/virustotal/settings', json={'api_key':KEY}).status_code == 200
    with TestClient(app, base_url='http://192.0.2.1') as client:
        client.cookies.set(auth.SESSION_COOKIE_NAME, auth.session_token())
        assert client.post('/api/threat-intelligence/virustotal/settings', json={}).status_code == 400


def test_disabled_provider_never_calls_network(transport):
    intel.configure('virustotal', {'api_key':KEY})
    with pytest.raises(HTTPException): intel.lookup('virustotal', SHA)
    assert transport[0] == []


@pytest.mark.parametrize('status,expected', [(401,401),(403,403),(429,429),(500,502),(302,502)])
def test_provider_errors(transport, status, expected):
    enable(); calls, response=transport; response.update(status=status, headers={'Retry-After':'70'})
    with pytest.raises(HTTPException) as caught: intel.lookup('virustotal', SHA)
    assert caught.value.status_code == expected
    assert KEY not in str(caught.value.detail)
    if status == 429:
        with pytest.raises(HTTPException): intel.lookup('virustotal', SHA)
        assert len(calls)==1


@pytest.mark.parametrize('error',[httpx.ReadTimeout('timeout'),httpx.ConnectError('offline')])
def test_timeouts_and_outages(transport,error):
    enable(); transport[1]['error']=error
    with pytest.raises(HTTPException) as caught: intel.lookup('virustotal', SHA)
    assert caught.value.status_code == 502


@pytest.mark.parametrize('stats,classification', [({'malicious':3},'malicious'),({'suspicious':2},'suspicious'),({'undetected':70},'no_detections_reported'),({},'unknown')])
def test_vt_classification(transport,stats,classification):
    enable(); transport[1]['json']={'data':{'id':SHA,'attributes':{'last_analysis_stats':stats,'last_analysis_results':{'engine':{'category':'malicious','result':'Example'}}}}}
    result=intel.lookup('virustotal',SHA)
    assert result['classification']==classification and result['provenance']=='external-sandbox-or-reputation'
    assert result['detections'][0]['engine']=='engine'


def test_unknown_cache_expiration_and_headers(transport):
    enable(); calls,response=transport; response['status']=404
    assert intel.lookup('virustotal',SHA)['classification']=='unknown'
    assert intel.lookup('virustotal',SHA)['cached']
    cached=store.state_get('report:virustotal:'+SHA); cached['expires']=0; store.state_set('report:virustotal:'+SHA,cached)
    intel.lookup('virustotal',SHA)
    assert len(calls)==2 and calls[0].headers['x-apikey']==KEY and calls[0].url.scheme=='https'


def test_quota_and_concurrent_single_flight(transport):
    enable(per_minute=1)
    with ThreadPoolExecutor(8) as pool:
        results=list(pool.map(lambda _:intel.lookup('virustotal',SHA),range(12)))
    assert len(results)==12 and len(transport[0])==1
    with pytest.raises(HTTPException) as caught: intel.lookup('virustotal','b'*64)
    assert caught.value.status_code==429


def test_jobs_are_deduplicated_and_recovered(transport):
    enable(); identity=jobs.enqueue('virustotal',SHA)
    assert jobs.enqueue('virustotal',SHA)==identity
    jobs.tick(); jobs.tick()
    assert jobs.job(identity)['state']=='completed' and len(transport[0])==1
    with store.connect() as db: db.execute("UPDATE intelligence_jobs SET state='running' WHERE id=?",(identity,))
    jobs.recover(); assert jobs.job(identity)['state']=='retry'


def test_hybrid_probe_continues_without_repeating_auth(transport):
    enable('hybrid_analysis'); calls,response=transport; response['json']={'auth_level':1,'is_active':True}
    identity=jobs.enqueue('hybrid_analysis','','capability'); jobs.tick()
    assert jobs.job(identity)['state']=='retry' and len(calls)==1
    assert store.state_get('capabilities:hybrid_analysis')['phase']=='environments'
    with store.connect() as db:
        db.execute('DELETE FROM intelligence_usage')
        db.execute('UPDATE intelligence_jobs SET due=0 WHERE id=?',(identity,))
    response['json']=[{'id':120,'description':'Windows'}]; jobs.tick()
    assert jobs.job(identity)['state']=='completed'
    assert calls[1].url.path=='/api/v2/system/environments' and calls[0].headers['api-key']==KEY


@pytest.mark.parametrize('verdict,classification',[('malicious','malicious'),('suspicious','suspicious'),('no specific threat','no_detections_reported'),('unknown','unknown')])
def test_hybrid_lookup_and_summary(transport,verdict,classification):
    enable('hybrid_analysis'); calls,response=transport
    raw={'sha256':SHA,'job_id':'b'*24,'verdict':verdict,'threat_score':80,'state':'SUCCESS','domains':['example.invalid'],'processes':[{'name':'sample.exe'}]}
    response['json']=[raw]
    result=intel.lookup('hybrid_analysis',SHA)
    assert result['classification']==classification and calls[0].method=='POST' and b'hash=' in calls[0].content
    assert jobs.summary(raw,SHA)['behaviour']['domains']==['example.invalid']
    with pytest.raises(HTTPException): jobs.summary(raw,'c'*64)


def stage(monkeypatch):
    enable(); store.state_set('capabilities:virustotal',{'verified':True})
    monkeypatch.setattr(intel,'lookup',lambda p,s:{'found':False,'sha256':s,'status':'unknown'})
    return samples.stage('virustotal',CONTENT)


def test_upload_requires_separate_approval_and_rejects_replay(monkeypatch):
    item=stage(monkeypatch); calls=[]
    monkeypatch.setattr(intel,'request',lambda *a,**kw: calls.append((a,kw)) or {'data':{'id':'analysis-id'}})
    token=item['upload_token']
    with pytest.raises(HTTPException): samples.upload('virustotal',token,{},request())
    assert not calls
    result=samples.upload('virustotal',token,{'approved':True},request())
    assert result['analysis_token']==token and len(calls)==1
    with pytest.raises(HTTPException): samples.upload('virustotal',token,{'approved':True},request())
    with pytest.raises(HTTPException): samples.stage('virustotal',CONTENT)


@pytest.mark.parametrize('change',['expired','changed','rotated','disabled','upload_disabled'])
def test_stale_upload_refused(monkeypatch,change):
    item=stage(monkeypatch); token=item['upload_token']
    if change=='expired': samples._stages[token]['expires']=0
    if change=='changed': samples._stages[token]['bytes']=b'changed'
    if change=='rotated': intel.configure('virustotal',{'api_key':'r'*64})
    if change=='disabled': intel.configure('virustotal',{'enabled':False})
    if change=='upload_disabled': intel.configure('virustotal',{'upload_authorized':False})
    monkeypatch.setattr(intel,'request',lambda *a,**kw:pytest.fail('must not contact provider'))
    with pytest.raises(HTTPException): samples.upload('virustotal',token,{'approved':True},request())


def test_ambiguous_upload_never_resubmits_and_reconciles(monkeypatch):
    item=stage(monkeypatch); token=item['upload_token']
    def fail(*a,**kw): raise HTTPException(502,'Network outcome unknown')
    monkeypatch.setattr(intel,'request',fail)
    with pytest.raises(HTTPException): samples.upload('virustotal',token,{'approved':True},request())
    assert samples.analysis('virustotal',token)['status']=='outcome_unknown'
    with pytest.raises(HTTPException): samples.stage('virustotal',CONTENT)
    record=store.state_get('submission:'+token); record['state']='submitting'; store.state_set('submission:'+token,record)
    samples.reconcile(restarting=True)
    assert samples.analysis('virustotal',token)['status']=='outcome_unknown'


def test_pending_sample_restart_expiry_and_cancel(monkeypatch):
    token=stage(monkeypatch)['upload_token']; samples.reconcile(restarting=True)
    assert samples.analysis('virustotal',token)['status']=='expired' and token not in samples._stages
    token=samples.stage('virustotal',CONTENT)['upload_token']; samples.cancel('virustotal',token)
    assert samples.analysis('virustotal',token)['status']=='cancelled'


def test_size_hash_validation_and_missing_key():
    for sha in ('short','x'*64, None):
        with pytest.raises(HTTPException): intel.valid_hash(sha)
    with pytest.raises(HTTPException): samples.stage('virustotal',b'')
    with pytest.raises(HTTPException): intel.lookup('virustotal',SHA)


def test_device_observations_stay_separate():
    jobs.observe('first',[{'sha256':SHA,'path':'first.exe'}])
    jobs.observe('second',[{'sha256':SHA,'path':'second.exe'}])
    with store.connect() as db:
        rows=db.execute('SELECT body FROM intelligence_observations WHERE device=?',('first',)).fetchall()
        assert len(rows)==1 and 'second.exe' not in rows[0][0]
        assert db.execute('SELECT COUNT(*) FROM intelligence_jobs').fetchone()[0]==2


def test_ai_unavailable_reports_honestly(monkeypatch):
    from backend import ai_technician
    store.state_set('report:virustotal:'+SHA,{'expires':time.time()+100,'report':{'classification':'malicious','stats':{'malicious':3}}})
    monkeypatch.setattr(ai_technician,'is_ai_available',lambda:False)
    result=asyncio.run(intel.explain_hash(SHA))
    assert result['status']=='unavailable' and 'No' not in result.get('classification','')


# Regressions for the 2026-11-16 review findings.

def test_disabled_provider_jobs_never_starve_an_enabled_one(transport):
    enable('virustotal')
    for index in range(25):
        jobs.enqueue('hybrid_analysis', f'{index:064x}')
    with store.connect() as db:
        db.execute("UPDATE intelligence_jobs SET due=0 WHERE provider='hybrid_analysis'")
    identity = jobs.enqueue('virustotal', SHA)
    jobs.tick()
    assert jobs.job(identity)['state'] == 'completed'
    with store.connect() as db:
        assert db.execute("SELECT COUNT(*) FROM intelligence_jobs WHERE provider='hybrid_analysis' AND state='queued'").fetchone()[0] == 25


def submitted(provider='hybrid_analysis', token='t'*32):
    store.state_set('submission:'+token, {'provider': provider, 'sha256': FILE_SHA, 'state': 'submitted', 'analysis_id': 'b'*24,
                                          'approved_at': time.time(), 'next_poll': 0, 'source': 'browser',
                                          'key_generation': intel.policy(provider).get('key_generation')})
    with store.connect() as db:
        db.execute('INSERT INTO intelligence_submissions VALUES (?,?,?,?)', (provider, FILE_SHA, token, 'submitted'))
    return token


def submission_state(token):
    with store.connect() as db:
        return db.execute('SELECT state FROM intelligence_submissions WHERE token=?', (token,)).fetchone()[0]


def test_sandbox_error_marks_submission_failed_and_allows_resubmit(monkeypatch):
    enable('hybrid_analysis'); store.state_set('capabilities:hybrid_analysis', {'verified': True})
    token = submitted()
    monkeypatch.setattr(intel, 'request', lambda *a, **kw: {'sha256': FILE_SHA, 'state': 'ERROR', 'verdict': 'unknown'})
    samples.maintain()
    assert samples.analysis('hybrid_analysis', token)['status'] == 'failed' and submission_state(token) == 'failed'
    monkeypatch.setattr(intel, 'lookup', lambda p, s: {'found': False, 'sha256': s, 'status': 'unknown'})
    assert samples.stage('hybrid_analysis', CONTENT)['upload_token']


def test_polling_deadline_updates_the_duplicate_guard(monkeypatch):
    enable('virustotal'); token = submitted('virustotal')
    record = store.state_get('submission:'+token); record['approved_at'] = time.time() - 7200; store.state_set('submission:'+token, record)
    monkeypatch.setattr(intel, 'request', lambda *a, **kw: pytest.fail('deadline reached; must not poll'))
    samples.poll_due()
    assert submission_state(token) == 'outcome_unknown'


def test_a_submitted_file_can_still_be_looked_up(monkeypatch):
    enable(); submitted('virustotal')
    monkeypatch.setattr(intel, 'lookup', lambda p, s: {'found': True, 'sha256': s, 'status': 'known', 'classification': 'malicious'})
    assert samples.stage('virustotal', CONTENT)['classification'] == 'malicious'
    monkeypatch.setattr(intel, 'lookup', lambda p, s: {'found': False, 'sha256': s, 'status': 'unknown'})
    with pytest.raises(HTTPException) as error:
        samples.stage('virustotal', CONTENT)
    assert error.value.status_code == 409  # still never uploaded twice


def test_malformed_agent_hashes_are_skipped_not_raised():
    jobs.observe('dev', [{'sha256': 'not-a-hash'}, 'junk', {'sha256': SHA, 'path': 'ok.exe'}])
    with store.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM intelligence_observations').fetchone()[0] == 1


def test_key_change_requeues_completed_lookups(transport):
    enable(); identity = jobs.enqueue('virustotal', SHA); jobs.tick()
    assert jobs.job(identity)['state'] == 'completed'
    intel.configure('virustotal', {'api_key': 'n'*64})
    with store.connect() as db:
        db.execute('DELETE FROM intelligence_usage')
    assert intel.get_file('virustotal', SHA)['state'] == 'queued'
    calls, _ = transport
    jobs.tick()
    assert jobs.job(identity)['state'] == 'completed' and calls[-1].headers['x-apikey'] == 'n'*64


def test_hybrid_object_response_is_accepted(transport):
    enable('hybrid_analysis'); calls, response = transport
    response['json'] = {'sha256s': [SHA], 'reports': [{'sha256': SHA, 'job_id': 'b'*24, 'verdict': 'malicious'}]}
    assert intel.lookup('hybrid_analysis', SHA)['classification'] == 'malicious'
    response['json'] = 'unexpected'
    with pytest.raises(HTTPException):
        intel.lookup('hybrid_analysis', 'c'*64)


def test_budget_only_change_keeps_cache_and_staged_samples(monkeypatch):
    token = stage(monkeypatch)['upload_token']
    generation = intel.policy('virustotal')['generation']
    store.state_set('report:virustotal:'+SHA, {'expires': time.time()+100, 'report': {'found': True}})
    intel.configure('virustotal', {'per_minute': 2})
    assert intel.policy('virustotal')['per_minute'] == 2 and intel.policy('virustotal')['generation'] == generation
    assert token in samples._stages and store.state_get('report:virustotal:'+SHA)
    intel.configure('virustotal', {'upload_authorized': False})
    assert token not in samples._stages and intel.policy('virustotal')['generation'] != generation


def test_upload_does_not_hold_the_configuration_lock_during_network(monkeypatch):
    token = stage(monkeypatch)['upload_token']
    seen = []
    def network(*a, **kw):
        # Another thread must be able to take the configuration lock while the upload is in flight.
        acquired = []
        thread = threading.Thread(target=lambda: acquired.append(intel._lock.acquire(timeout=2)) or intel._lock.release())
        thread.start(); thread.join()
        seen.append(acquired == [True])
        return {'data': {'id': 'analysis-id'}}
    monkeypatch.setattr(intel, 'request', network)
    samples.upload('virustotal', token, {'approved': True}, request())
    assert seen == [True]


# Regressions for the QA-team findings (second round).

@pytest.mark.parametrize('change', [{'api_key': 'n'*64}, {'upload_authorized': False}])
def test_upload_refused_when_configuration_changes_between_claim_and_send(monkeypatch, transport, change):
    token = stage(monkeypatch)['upload_token']
    calls, _ = transport
    submit = samples._submit
    def changed_then_submit(*args):
        intel.configure('virustotal', change)  # another operator edits settings right after the claim
        return submit(*args)
    monkeypatch.setattr(samples, '_submit', changed_then_submit)
    with pytest.raises(HTTPException) as error:
        samples.upload('virustotal', token, {'approved': True}, request())
    assert error.value.status_code == 409 and not calls
    assert samples.analysis('virustotal', token)['status'] == 'failed' and submission_state(token) == 'failed'


def test_key_change_clears_the_previous_accounts_backoff(transport):
    enable(); rules = intel.policy('virustotal'); rules['retry_at'] = time.time() + 86400
    store.state_set('provider:virustotal', rules)
    with pytest.raises(HTTPException): intel.lookup('virustotal', SHA)
    intel.configure('virustotal', {'api_key': 'n'*64})
    assert intel.lookup('virustotal', SHA)['found']


def test_analyses_of_a_previous_key_are_not_polled_with_the_new_one(monkeypatch):
    enable(); token = submitted('virustotal')
    intel.configure('virustotal', {'api_key': 'n'*64})
    monkeypatch.setattr(intel, 'request', lambda *a, **kw: pytest.fail('must not poll with another account key'))
    samples.poll_due()
    assert submission_state(token) == 'outcome_unknown'


def test_polling_is_capped_per_pass(monkeypatch):
    enable()
    for index in range(5):
        token = f'{index}'*32; submitted('virustotal', token)
        with store.connect() as db:
            db.execute('UPDATE intelligence_submissions SET hash=? WHERE token=?', (f'{index:064x}', token))
    calls = []
    monkeypatch.setattr(intel, 'request', lambda *a, **kw: calls.append(a) or {'data': {'attributes': {'status': 'queued'}}})
    samples.poll_due()
    assert len(calls) == samples.POLLS_PER_PASS


def test_unreadable_credential_never_overwrites_an_unclaimed_job(monkeypatch):
    enable(); identity = jobs.enqueue('virustotal', SHA)
    calls = iter([True])
    def allowed(provider):
        if next(calls, False):
            return True
        raise HTTPException(503, 'credential unreadable')
    monkeypatch.setattr(intel, 'allowed', allowed)
    jobs.tick()
    job = jobs.job(identity)
    assert job['state'] == 'queued' and job['result'] == {}


def test_observe_ignores_non_list_input():
    for files in ({'sha256': SHA}, 7, None, 'text'):
        jobs.observe('dev', files)
    with store.connect() as db:
        assert db.execute('SELECT COUNT(*) FROM intelligence_observations').fetchone()[0] == 0


def test_settings_page_reports_a_bad_master_key_instead_of_failing(monkeypatch):
    monkeypatch.setenv('SENTINEL_INTELLIGENCE_MASTER_KEY', 'not-a-valid-fernet-key')
    result = intel.status('virustotal')
    assert result['configured'] is False and result['credential_error'] and result['storage'] == 'unavailable'


# Regressions for the round-2 re-check.

def test_a_poll_is_refused_if_the_key_rotates_mid_pass(monkeypatch, transport):
    enable(); token = submitted('virustotal')
    calls, _ = transport
    reserve = intel._reserve
    def rotate_then_reserve(provider, expect=None):
        intel.configure('virustotal', {'api_key': 'n'*64})  # rotated after the pass read the key generation
        return reserve(provider, expect)
    monkeypatch.setattr(intel, '_reserve', rotate_then_reserve)
    samples.poll_due()
    monkeypatch.setattr(intel, '_reserve', reserve)
    assert not calls and submission_state(token) == 'submitted'  # refused (409), marked on the next pass
    record = store.state_get('submission:'+token); record['next_poll'] = 0; store.state_set('submission:'+token, record)
    samples.poll_due()
    assert submission_state(token) == 'outcome_unknown' and not calls


def test_a_late_429_for_a_replaced_key_does_not_block_the_new_key(monkeypatch, transport):
    enable(); calls, response = transport
    response.update(status=429, headers={'Retry-After': '86400'})
    reserve = intel._reserve
    def reserve_then_rotate(provider, expect=None):
        result = reserve(provider, expect)
        intel.configure('virustotal', {'api_key': 'n'*64})  # the key is replaced while the request is in flight
        return result
    monkeypatch.setattr(intel, '_reserve', reserve_then_rotate)
    with pytest.raises(HTTPException): intel.request('virustotal', 'GET', '/files/' + SHA)
    assert intel.policy('virustotal')['retry_at'] == 0


def test_polling_stops_for_a_provider_that_is_rate_limited(monkeypatch):
    enable()
    for index in range(3):
        token = f'{index}'*32; submitted('virustotal', token)
        with store.connect() as db:
            db.execute('UPDATE intelligence_submissions SET hash=? WHERE token=?', (f'{index:064x}', token))
    calls = []
    def limited(*a, **kw):
        calls.append(a); raise HTTPException(429, 'Provider rate limit reached')
    monkeypatch.setattr(intel, 'request', limited)
    samples.poll_due()
    assert len(calls) == 1


def test_key_change_requeues_retrying_jobs():
    enable(); identity = jobs.enqueue('virustotal', SHA)
    with store.connect() as db:
        db.execute("UPDATE intelligence_jobs SET state='retry',due=? WHERE id=?", (time.time() + 3600, identity))
    intel.configure('virustotal', {'api_key': 'n'*64})
    assert jobs.job(identity)['due'] == 0


def test_a_database_replaced_at_the_same_path_gets_its_schema_again():
    import os
    store.state_set('first', 1)
    os.remove(store.DB_PATH)
    assert store.state_get('first') is None
    store.state_set('second', 2)
    assert store.state_get('second') == 2
