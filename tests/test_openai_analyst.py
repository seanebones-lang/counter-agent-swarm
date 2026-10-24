import json
import pytest
import httpx
from counter_swarm.openai_analyst import OpenAIAnalyst
from counter_swarm.detection import inspect_request


@pytest.mark.asyncio
async def test_model_is_bounded_projected_and_call_budget_survives_restart(tmp_path,monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY','fictional-test-only')
    calls=[]
    def handler(request):
        data=json.loads(request.content); calls.append(data)
        assert request.url == 'https://api.openai.com/v1/responses'
        assert data['store'] is False and data['max_output_tokens'] == 600 and 'tools' not in data
        assert 'secret-body' not in data['input']
        return httpx.Response(200,json={'status':'completed','output':[{'type':'message','content':[{
            'type':'output_text','text':json.dumps({'action':'escalate','reason':'Fictional finding requires human investigation'})}]}]})
    transport=httpx.MockTransport(handler)
    event=inspect_request('/',b'',[(b'content-encoding',b'br')],b'secret-body').record()
    analyst=OpenAIAnalyst('fictional-model',tmp_path/'budget.sqlite',1,transport)
    assert (await analyst.analyze(event)).action == 'escalate'
    restarted=OpenAIAnalyst('fictional-model',tmp_path/'budget.sqlite',1,transport)
    with pytest.raises(RuntimeError,match='exhausted'): await restarted.analyze(event)
    assert len(calls)==1


@pytest.mark.asyncio
async def test_zero_budget_does_not_call_api(tmp_path,monkeypatch):
    monkeypatch.setenv('OPENAI_API_KEY','fictional-test-only')
    def handler(request): raise AssertionError('No call permitted')
    analyst=OpenAIAnalyst('fictional-model',tmp_path/'budget.sqlite',0,httpx.MockTransport(handler))
    event=inspect_request('/',b'',[(b'content-encoding',b'br')],b'inert').record()
    with pytest.raises(RuntimeError,match='disabled'): await analyst.analyze(event)
