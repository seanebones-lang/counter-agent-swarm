import asyncio
import json
import os
from pathlib import Path
import pytest
import httpx
from counter_swarm.detection import inspect_request, MAX_BODY
from counter_swarm.gate import Gate
from counter_swarm.config import private_file
from counter_swarm.response import Gateway, Recommendation


@pytest.mark.parametrize('body', [b'<?php system(marker)', b'%3C%3FPHP%20SYSTEM(marker)',
                                  b'%253c%253fphp%2520SyStEm(marker)'])
def test_encoded_inert_indicators(body):
    f = inspect_request('/', b'', [], body)
    assert 'php-execution-indicator' in f.rules
    assert 'marker' not in json.dumps(f.record())


def test_budgets_and_compression_reject_before_decoder():
    assert inspect_request('/', b'', [(b'content-encoding', b'br')], b'inert').rules == ('unsupported-compressed-body',)
    assert inspect_request('/', b'', [], b'x'*(MAX_BODY+1)).rules == ('request-budget',)
    assert inspect_request('/', b'', [(b'next-action', b'normal')], b'ordinary form') is None
    assert inspect_request('/', b'', [], b'ordinary text') is None


def test_private_files_fail_closed(tmp_path):
    p=tmp_path/'token'; p.write_text('fiction'); p.chmod(0o644)
    with pytest.raises(ValueError): private_file(p)
    p.chmod(0o600); assert private_file(p) == p
    link=tmp_path/'link'; link.symlink_to(p)
    with pytest.raises(ValueError): private_file(link)


@pytest.mark.asyncio
async def test_gate_down_and_missing_binding_deny(tmp_path):
    assert not await Gate('http://127.0.0.1:1', 'fiction', tmp_path/'missing').admitted()
    for url in ['http://localhost:123', 'https://127.0.0.1:123', 'http://127.0.0.1:123/path']:
        with pytest.raises(ValueError): Gate(url, 'fiction', tmp_path/'x')


@pytest.mark.asyncio
async def test_cache_is_exact_not_similarity_and_bounded():
    class Count:
        calls=0
        async def analyze(self, data):
            self.calls+=1
            return Recommendation(action='escalate', reason='fiction')
    count=Count(); gateway=Gateway(count,'system-a')
    one=inspect_request('/',b'',[(b'content-encoding',b'br')],b'a')
    two=inspect_request('/',b'',[(b'content-encoding',b'br')],b'b')
    await gateway.analyze(one); await gateway.analyze(one); await gateway.analyze(two)
    assert count.calls == 2
