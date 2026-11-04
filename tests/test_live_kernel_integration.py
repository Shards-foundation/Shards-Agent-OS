"""Real, isolated loopback integration: scheduled job -> MCP -> signed operator.

The trusted signing fixture exists ONLY in this test and holds ephemeral keys.
Production agents never receive signers, policy keys or operator API secrets.
"""
from __future__ import annotations

import importlib.util
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from shards_agent_os.scheduler import enqueue, run_once

DEPENDENCIES = all(importlib.util.find_spec(name) is not None for name in
                   ('shards_kernel', 'cryptography', 'mcp'))


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


@unittest.skipUnless(os.name == 'posix' and DEPENDENCIES, 'POSIX + kernel crypto and MCP extras required')
class LiveOperatorIntegration(unittest.TestCase):
    def test_real_signed_mcp_allow_then_replay_denial(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from shards_kernel.integrations.auth import agent_token_kdf
        from shards_kernel.integrations.wire import permit_to_mapping
        from shards_kernel.issuer import sign_operator_policy, sign_v2_permit
        from shards_kernel.permits import PermitBuilder

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            issuer = Ed25519PrivateKey.generate()
            policy_issuer = Ed25519PrivateKey.generate()
            pepper = secrets.token_urlsafe(48)
            alpha = 'agent-alpha.' + secrets.token_urlsafe(48)
            beta = 'agent-beta.' + secrets.token_urlsafe(48)
            port = free_port()
            config = {
                'version': 2,
                'kernel_id': 'agent-os-ci-local',
                'tools': ['echo', 'add'],
                'agents': [
                    {'actor':'agent-alpha','token_scrypt':agent_token_kdf(alpha,pepper.encode()),'allowed_tools':['echo']},
                    {'actor':'agent-beta','token_scrypt':agent_token_kdf(beta,pepper.encode()),'allowed_tools':['add']},
                ],
                'issuer_keys': [{
                    'key_id':'permit-issuer','issuer':'operator',
                    'public_key_hex':issuer.public_key().public_bytes_raw().hex(),
                    'revoked':False,
                }],
                'audit_db':str(root/'kernel_audit.sqlite3'),
                'port':port,
            }
            now = int(time.time()*1000)
            policy = sign_operator_policy(config, policy_issuer, revision=1,
                                          issued_at_ms=now-60000, expires_at_ms=now+600000)
            policy_file=root/'signed-operator.json'
            policy_file.write_text(json.dumps(policy))
            permit = (
                PermitBuilder().issuer('operator').subject('agent-alpha')
                .jurisdiction('default').action('echo').params({'text':'scheduled-hello'})
                .max_executions(1).valid_from_ms(now-30000).valid_until_ms(now+120000)
                .proposal_hash('independent-approval-agent-alpha')
                .build_unsigned_v2(key_id='permit-issuer',audience='agent-os-ci-local')
            )
            signed = permit_to_mapping(sign_v2_permit(permit, issuer))
            permit_file=root/'private-permit.json'
            fd=os.open(permit_file,os.O_CREAT|os.O_WRONLY|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as stream:
                json.dump(signed,stream)

            operator_env=os.environ.copy()
            operator_env.update({
                'SHARDS_KERNEL_API_KEY':secrets.token_urlsafe(48),
                'SHARDS_KERNEL_AGENT_AUTH_PEPPER':pepper,
                'SHARDS_KERNEL_POLICY_PUBLIC_KEY_HEX':policy_issuer.public_key().public_bytes_raw().hex(),
            })
            proc = subprocess.Popen(
                [sys.executable,'-m','shards_kernel','serve','--config',str(policy_file)],
                env=operator_env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            )
            try:
                healthy=False
                for _ in range(120):
                    if proc.poll() is not None:
                        break
                    try:
                        with urllib.request.urlopen(f'http://127.0.0.1:{port}/health',timeout=0.3) as resp:
                            if resp.status == 200 and json.loads(resp.read()).get('status') == 'healthy':
                                healthy=True
                                break
                    except (OSError, ValueError, urllib.error.URLError):
                        pass
                    time.sleep(0.1)
                self.assertTrue(healthy,'Signed kernel operator did not reach healthy state')

                db=root/'jobs.sqlite3'
                def add():
                    return enqueue(db,run_at_ms=now-1000,port=port,tool='echo',
                                   arguments={'text':'scheduled-hello'},permit_file=str(permit_file),now_ms=now)
                with patch.dict(os.environ, {'SHARDS_KERNEL_AGENT_TOKEN': alpha}):
                    first_id=add()
                    first=run_once(db,now_ms=now,timeout_s=20)
                    self.assertEqual(first['job_id'],first_id)
                    self.assertEqual(first['status'],'SUCCEEDED',first)
                    self.assertEqual(first['receipt']['result'],'scheduled-hello')
                    # The second operation is a distinct job reusing the first
                    # permit. It MUST fail because the kernel consumed the nonce.
                    add()
                    replay=run_once(db,now_ms=now,timeout_s=20)
                    self.assertEqual(replay['status'],'DENIED',replay)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=8)


if __name__=='__main__':
    unittest.main()
