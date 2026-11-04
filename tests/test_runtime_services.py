"""Regression tests for durable runtime state and fail-closed control."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from shards_agent_os.daemon import serve
from shards_agent_os.directory import enroll_agent, inventory, register_capability
from shards_agent_os.interrupts import control_state, halt, resume
from shards_agent_os.memory import delete, purge_expired, recall, store
from shards_agent_os.scheduler import enqueue, list_jobs, run_once

REQUEST_ID = 'mcp-relay-' + 'c'*32


class RuntimeServicesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / 'agent-os.sqlite'

    def queue(self, label='foo', run_at=0):
        return enqueue(self.db, run_at_ms=run_at, port=8765, tool='echo',
                       arguments={'text':label},permit_file='/private/permit.json',now_ms=0)

    @staticmethod
    def allowed(job, _timeout):
        return 0, json.dumps({'decision':'ALLOW','request_id':REQUEST_ID,'result':job.arguments['text']})

    def test_operator_halt_blocks_due_jobs_without_cancelling(self):
        job_id = self.queue()
        self.assertTrue(halt(self.db,'Operator shutdown'))
        self.assertFalse(halt(self.db,'duplicate'))
        self.assertIsNone(run_once(self.db,now_ms=100,runner=self.allowed))
        self.assertEqual(list_jobs(self.db)[0]['status'],'PENDING')
        self.assertTrue(control_state(self.db)['halted'])
        self.assertTrue(resume(self.db))
        result = run_once(self.db,now_ms=100,runner=self.allowed)
        self.assertEqual(result['status'],'SUCCEEDED')
        self.assertEqual(result['job_id'],job_id)

    def test_invalid_halt_reasons(self):
        for reason in ('', 'x'*257, None):
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                halt(self.db,reason)

    def test_running_capacity_fails_closed_after_crash(self):
        self.queue('one')
        self.queue('two')
        start = threading.Event()
        finish = threading.Event()
        completed=[]
        def blocking(job, timeout):
            start.set()
            self.assertTrue(finish.wait(5))
            return self.allowed(job,timeout)
        worker=threading.Thread(target=lambda:completed.append(run_once(self.db,now_ms=100,runner=blocking)))
        worker.start()
        try:
            self.assertTrue(start.wait(5))
            self.assertIsNone(run_once(self.db,now_ms=100,runner=self.allowed,max_running=1))
        finally:
            finish.set()
            worker.join(timeout=5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(completed[0]['status'],'SUCCEEDED')
        self.assertEqual(run_once(self.db,now_ms=100,runner=self.allowed)['status'],'SUCCEEDED')

    def test_daemon_executes_due_task_and_stops_on_halt(self):
        self.queue()
        self.assertEqual(serve(self.db,runner=self.allowed,max_ticks=1),1)
        self.assertEqual(list_jobs(self.db)[0]['status'],'SUCCEEDED')
        halt(self.db,'stop')
        self.assertEqual(serve(self.db,runner=self.allowed,max_ticks=1),0)

    def test_memory_version_ttl_provenance_and_namespaces(self):
        first=store(self.db,namespace='agent-a',kind='episodic',key='event1',value={'n':1},
                    provenance='operator-log',expected_version=0,ttl_ms=100,now_ms=1000)
        self.assertEqual(first['version'],1)
        self.assertEqual(recall(self.db,namespace='agent-a',kind='episodic',key='event1',now_ms=1099)['value'],{'n':1})
        self.assertIsNone(recall(self.db,namespace='agent-b',kind='episodic',key='event1',now_ms=1099))
        with self.assertRaisesRegex(ValueError,'MEMORY_VERSION_CONFLICT'):
            store(self.db,namespace='agent-a',kind='episodic',key='event1',value=2,
                  provenance='operator-log',expected_version=0,now_ms=1010)
        self.assertIsNone(recall(self.db,namespace='agent-a',kind='episodic',key='event1',now_ms=1100))
        self.assertEqual(purge_expired(self.db,now_ms=1100),1)
        self.assertFalse(delete(self.db,namespace='agent-a',kind='episodic',key='event1'))

    def test_memory_explicit_delete_and_optimistic_version(self):
        store(self.db,namespace='ops',kind='procedural',key='policy1',value=['approved'],
              provenance='human-operator',expected_version=0)
        self.assertFalse(delete(self.db,namespace='ops',kind='procedural',key='policy1',expected_version=2))
        self.assertTrue(delete(self.db,namespace='ops',kind='procedural',key='policy1',expected_version=1))

    def test_memory_rejects_unbounded_or_ambiguous_values(self):
        for kwargs in ({'value':'x'*70000}, {'ttl_ms':0}, {'namespace':'../escape'},
                       {'provenance':''}, {'value':float('nan')}, {'expected_version':True}):
            args=dict(namespace='local',kind='working',key='key1',value={'ok':True},provenance='test')
            args.update(kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises((ValueError,TypeError)):
                store(self.db,**args)

    def test_capabilities_are_never_executable(self):
        enroll_agent(self.db,'alpha','Registered only',['echo'])
        register_capability(self.db,'camera.front','camera','No access',[])
        values=inventory(self.db)
        self.assertFalse(values['agents'][0]['kernel_authenticated'])
        self.assertFalse(values['capabilities'][0]['executable'])
        self.assertEqual(values['capabilities'][0]['enabled'],0)
        with self.assertRaises(ValueError):
            register_capability(self.db,'shell','api','Forbidden',['shell'])

    def test_cli_denies_duplicate_json_keys(self):
        env=os.environ.copy()
        path=str(Path(__file__).resolve().parents[1] / 'src')
        env['PYTHONPATH']=path
        command=[sys.executable,'-m','shards_agent_os','--db',str(self.db),
                 'enqueue','--port','8765','--tool','echo','--permit-file','/p/permit.json',
                 '--arguments-json','{"text":"safe","text":"override"}']
        result=subprocess.run(command,env=env,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,2)
        self.assertEqual(json.loads(result.stdout)['status'],'ERROR')

    def test_cli_memory_and_status(self):
        env=os.environ.copy()
        env['PYTHONPATH']=str(Path(__file__).resolve().parents[1] / 'src')
        base=[sys.executable,'-m','shards_agent_os','--db',str(self.db)]
        def command(*parts):
            result=subprocess.run(base+list(parts),env=env,capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode,0, result.stderr+' '+result.stdout)
            return json.loads(result.stdout)
        self.assertEqual(command('memory-put','--namespace','ops','--kind','working','--key','plan',
                                 '--value-json','{"step":1}','--provenance','operator')['version'],1)
        self.assertEqual(command('memory-get','--namespace','ops','--kind','working','--key','plan')['value'],{'step':1})
        self.assertEqual(command('status')['memory_records'],1)
        self.assertTrue(command('halt','--reason','stop')['halted'])
        self.assertEqual(command('run-once')['status'],'HALTED')
        self.assertFalse(command('resume')['halted'])


if __name__ == '__main__':
    unittest.main()
