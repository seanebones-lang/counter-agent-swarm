import httpx
import pytest
from counter_swarm.proxy import create_proxy


class Allow:
    async def admitted(self): return True


@pytest.mark.asyncio
async def test_proxy_preserves_raw_path_duplicate_cookies_and_hop_removal(monkeypatch):
    real_client=httpx.AsyncClient
    seen=[]
    def upstream(request):
        seen.append(request)
        return httpx.Response(200, headers=[('set-cookie','a=1'),('set-cookie','b=2'),
            ('connection','x-hop'),('x-hop','remove')], stream=httpx.ByteStream(b'hello'))
    def upstream_client(**kwargs):
        return real_client(transport=httpx.MockTransport(upstream),**kwargs)
    monkeypatch.setattr('counter_swarm.proxy.httpx.AsyncClient',upstream_client)
    async def sink(_): raise AssertionError('benign')
    app=create_proxy('http://origin.test',Allow(),sink)
    async with real_client(transport=httpx.ASGITransport(app),base_url='http://proxy.test') as client:
        result=await client.get('/files/a%2Fb?q=%2F',headers=[('connection','x-one'),('connection','x-two'),
            ('x-one','remove'),('x-two','remove'),('x-forwarded-for','forged')])
    assert seen[0].url.raw_path==b'/files/a%2Fb?q=%2F'
    assert seen[0].url.host=='origin.test'
    assert all(x not in seen[0].headers for x in ('x-one','x-two','x-forwarded-for'))
    assert result.headers.get_list('set-cookie')==['a=1','b=2']
    assert 'x-hop' not in result.headers and result.content==b'hello'


@pytest.mark.asyncio
@pytest.mark.parametrize('method,status,length',[('HEAD',200,'500'),('GET',204,None),('GET',304,'500')])
async def test_proxy_head_and_no_body_statuses(monkeypatch,method,status,length):
    real_client=httpx.AsyncClient
    def upstream(request): return httpx.Response(status,headers={'content-length':'500'},stream=httpx.ByteStream(b''))
    monkeypatch.setattr('counter_swarm.proxy.httpx.AsyncClient',lambda **kw: real_client(transport=httpx.MockTransport(upstream),**kw))
    async def sink(_): pass
    async with real_client(transport=httpx.ASGITransport(create_proxy('http://origin.test',Allow(),sink)),base_url='http://proxy.test') as client:
        result=await client.request(method,'/status')
    assert result.content==b'' and result.headers.get('content-length')==length
