import asyncio
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from counter_swarm.detection import inspect_request
from counter_swarm.incident_queue import IncidentQueue
from counter_swarm.runtime import RuntimeConfig, create_ingress, process_one


def record():
    return inspect_request('/', b'', [(b'content-encoding', b'br')], b'inert').record()


def test_queue_deduplicates_claims_and_requires_explicit_pending_resume(tmp_path):
    q = IncidentQueue(tmp_path / 'private' / 'incidents.sqlite')
    item = record()
    assert q.put(item) is True
    assert q.put(item) is False
    first = q.claim()
    assert first['id'] == item['event_id']
    assert q.claim() is None
    assert q.claim(item['event_id']) is None
    q.mark(item['event_id'], 'pending', phase='analysis', approval='apr_fiction')
    assert q.claim(item['event_id'])['approval'] == 'apr_fiction'
    assert q.claim(item['event_id']) is None


def test_ingress_requires_private_token_and_rejects_payload_or_routing(tmp_path):
    token = tmp_path / 'ingress.token'
    token.write_text('fictional-private-token-only')
    token.chmod(0o600)
    config = RuntimeConfig(upstream='http://127.0.0.1:8000', gate_origin='http://127.0.0.1:9782',
        target_run='fixture', admission_token_file=str(token), ingress_token_file=str(token),
        queue_file=str(tmp_path / 'state' / 'queue.sqlite'), mothership_origin='http://127.0.0.1:9783',
        mothership_agent_key_file=str(token))
    with TestClient(create_ingress(config)) as client:
        assert client.post('/incidents', json=record()).status_code == 403
        headers={'Authorization': 'Bearer fictional-private-token-only'}
        assert client.post('/incidents', json=record(), headers=headers).status_code == 202
        for bad in ({**record(), 'payload': 'private'}, {**record(), 'rules': ['ignore-rules']},
                    {**record(), 'target_run': 'other'}, {**record(), 'event_id': 'evt_' + '0'*24}):
            assert client.post('/incidents', json=bad, headers=headers).status_code == 400
        assert client.post('/incidents', content=b'x'*4097, headers=headers).status_code == 413


def test_worker_crash_holds_and_never_repeats_effect(tmp_path):
    q=IncidentQueue(tmp_path / 'state' / 'queue.sqlite'); q.put(record())
    calls=[]
    class Client:
        def call(self,*args,**kwargs):
            calls.append(args)
            raise ConnectionError('fictional lost response')
    result=process_one(q,Client())
    assert result['status']=='held' and q.status()[0]['state']=='held'
    assert process_one(q,Client())['status']=='idle'
    assert len(calls)==1


def test_worker_default_escalates_without_model_or_enforcement(tmp_path):
    q=IncidentQueue(tmp_path / 'state' / 'queue.sqlite'); q.put(record()); calls=[]
    class Client:
        def call(self,tool,*args,**kwargs): calls.append(tool); return {}
    assert process_one(q,Client())['status']=='escalated'
    assert calls==['memory.put','memory.checkpoint_save']
    assert q.status()[0]['state']=='completed'


def test_worker_analysis_pending_is_resumed_not_resubmitted(tmp_path):
    from mothership.sdk import MothershipError
    q=IncidentQueue(tmp_path / 'state' / 'queue.sqlite'); item=record(); q.put(item); calls=[]
    class Client:
        def call(self,tool,*args,**kwargs):
            calls.append(tool)
            if tool=='swarm.analyze':
                raise MothershipError(409,{'code':'APPROVAL_PENDING','message':'fictional',
                    'details':{'approval_id':'apr_fixture'}})
            return {}
        def wait_for_approval(self,approval_id,timeout):
            calls.append('wait:'+approval_id)
            return {'event_id':item['event_id'],'recommendation':{'action':'escalate','reason':'fictional'}}
    c=Client()
    assert process_one(q,c,live_analysis=True)['status']=='pending'
    assert process_one(q,c,live_analysis=True)['status']=='idle'
    assert process_one(q,c,live_analysis=True,resume=item['event_id'])['status']=='escalated'
    assert calls.count('swarm.analyze')==1 and 'wait:apr_fixture' in calls


@pytest.mark.parametrize('live',[False,True])
def test_evidence_approval_continues_to_correct_stage(tmp_path,live):
    from mothership.sdk import MothershipError
    q=IncidentQueue(tmp_path / 'state' / 'queue.sqlite'); item=record(); q.put(item); calls=[]
    class Client:
        def call(self,tool,*args,**kwargs):
            calls.append(tool)
            if tool=='memory.put':
                raise MothershipError(409,{'code':'APPROVAL_PENDING','message':'fictional',
                    'details':{'approval_id':'apr_evidence'}})
            if tool=='swarm.analyze':
                return {'event_id':item['event_id'],'recommendation':{'action':'escalate','reason':'fictional'}}
            return {}
        def wait_for_approval(self,approval_id,timeout):
            calls.append('wait:'+approval_id)
            return {'key':'incident.'+item['event_id'],'namespace':'swarm','version':1}
    c=Client()
    assert process_one(q,c,live_analysis=live)['status']=='pending'
    assert q.status()[0]['phase']=='evidence'
    assert process_one(q,c,live_analysis=live,resume=item['event_id'])['status']=='escalated'
    assert calls.count('memory.put')==1 and calls[-1]=='memory.checkpoint_save'
    assert ('swarm.analyze' in calls) == live


def test_checkpoint_approval_is_resumed_as_checkpoint(tmp_path):
    from mothership.sdk import MothershipError
    q=IncidentQueue(tmp_path / 'state' / 'queue.sqlite'); item=record(); q.put(item); calls=[]
    class Client:
        def call(self,tool,*args,**kwargs):
            calls.append(tool)
            if tool=='memory.checkpoint_save':
                raise MothershipError(409,{'code':'APPROVAL_PENDING','message':'fictional',
                    'details':{'approval_id':'apr_checkpoint'}})
            return {}
        def wait_for_approval(self,approval_id,timeout):
            calls.append('wait:'+approval_id); return {'task_id':item['event_id'],'version':1}
    c=Client()
    assert process_one(q,c)['status']=='pending'
    assert q.status()[0]['phase']=='checkpoint'
    assert process_one(q,c,resume=item['event_id'])['status']=='escalated'
    assert calls.count('memory.checkpoint_save')==1
