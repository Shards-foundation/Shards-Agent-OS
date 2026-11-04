"""Recurring intent tests: templates cannot mint authorisation or replay permits."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from shards_agent_os.interrupts import halt, resume
from shards_agent_os.recurrence import (
    create_schedule, due_schedules, list_schedules, release_occurrence,
    set_schedule_enabled, skip_missed,
)
from shards_agent_os.scheduler import list_jobs, run_once

RECEIPT = 'mcp-relay-' + 'e' * 32


class RecurrenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / 'jobs.sqlite'

    def schedule(self, *, name='hourly', start=1000, every=60_000, window=5000):
        return create_schedule(
            self.db, name=name, interval_ms=every, start_at_ms=start,
            window_ms=window, port=8765, tool='echo', arguments={'text':'ping'},
        )

    @staticmethod
    def receipt(_job, _timeout):
        return 0, json.dumps({'decision':'ALLOW', 'request_id':RECEIPT, 'result':'ping'})

    def test_template_does_not_execute_without_independent_permit(self):
        ident = self.schedule()
        self.assertEqual(list_jobs(self.db), [])
        self.assertEqual(due_schedules(self.db, now_ms=999), [])
        self.assertEqual(due_schedules(self.db, now_ms=1000)[0]['schedule_id'], ident)
        self.assertIsNone(run_once(self.db,now_ms=1000,runner=self.receipt))
        self.assertEqual(release_occurrence(self.db,schedule_id=ident,permit_file='/issued/permit1',now_ms=1000)['status'],'RELEASED')
        self.assertEqual(run_once(self.db, now_ms=1000,runner=self.receipt)['status'],'SUCCEEDED')
        self.assertEqual(len(list_jobs(self.db)),1)

    def test_repetition_requires_different_permit_file(self):
        ident=self.schedule()
        first=release_occurrence(self.db,schedule_id=ident,permit_file='/issued/permit1',now_ms=1000)
        self.assertEqual(first['next_due_ms'],61000)
        self.assertEqual(release_occurrence(self.db,schedule_id=ident,permit_file='/issued/permit2',now_ms=2000)['status'],'NOT_DUE')
        with self.assertRaisesRegex(ValueError,'PERMIT_PATH_ALREADY_USED'):
            release_occurrence(self.db,schedule_id=ident,permit_file='/issued/permit1',now_ms=61000)
        self.assertEqual(list_schedules(self.db)[0]['next_due_ms'],61000)
        second=release_occurrence(self.db,schedule_id=ident,permit_file='/issued/permit2',now_ms=61000)
        self.assertNotEqual(first['job_id'],second['job_id'])
        self.assertEqual(len(list_jobs(self.db)),2)

    def test_missed_intervals_are_skipped_never_backfilled(self):
        ident=self.schedule()
        result=release_occurrence(self.db,schedule_id=ident,permit_file='/issued/a',now_ms=1000+3*60000+7000)
        self.assertEqual(result['status'],'MISSED')
        self.assertEqual(result['skipped'],4)
        self.assertEqual(result['next_due_ms'],1000+4*60000)
        self.assertEqual(list_jobs(self.db),[])
        self.assertEqual(release_occurrence(self.db,schedule_id=ident,permit_file='/issued/b',now_ms=1000+4*60000)['status'],'RELEASED')

    def test_current_window_after_outage_issues_one_and_only_one(self):
        ident=self.schedule()
        result=release_occurrence(self.db,schedule_id=ident,permit_file='/issued/b',now_ms=1000+2*60000+3000)
        self.assertEqual(result['status'],'RELEASED')
        self.assertEqual(result['skipped'],2)
        self.assertEqual(len(list_jobs(self.db)),1)
        self.assertEqual(list_schedules(self.db)[0]['skipped_intervals'],2)

    def test_skip_missed_requires_no_permit_and_never_issues_job(self):
        ident=self.schedule()
        self.assertEqual(skip_missed(self.db,ident,now_ms=1000+60000+6000)['skipped'],2)
        self.assertEqual(list_jobs(self.db),[])
        self.assertEqual(skip_missed(self.db,ident,now_ms=1000+2*60000)['status'],'CURRENT_WINDOW')
        self.assertEqual(release_occurrence(self.db,schedule_id=ident,permit_file='/issued/c',now_ms=1000+2*60000)['status'],'RELEASED')

    def test_halt_pause_disable_and_clock_rollback(self):
        ident=self.schedule()
        self.assertTrue(halt(self.db,'Operator stop'))
        with self.assertRaisesRegex(ValueError,'DISPATCH_HALTED'):
            release_occurrence(self.db,schedule_id=ident,permit_file='/issued/a',now_ms=2000)
        self.assertEqual(list_jobs(self.db),[])
        self.assertTrue(resume(self.db))
        self.assertTrue(set_schedule_enabled(self.db,ident,False))
        with self.assertRaisesRegex(ValueError,'SCHEDULE_NOT_AVAILABLE'):
            release_occurrence(self.db,schedule_id=ident,permit_file='/issued/a',now_ms=2000)
        self.assertTrue(set_schedule_enabled(self.db,ident,True))
        self.assertEqual(release_occurrence(self.db,schedule_id=ident,permit_file='/issued/a',now_ms=2000)['status'],'RELEASED')
        with self.assertRaisesRegex(ValueError,'SCHEDULE_CLOCK_ROLLBACK'):
            release_occurrence(self.db,schedule_id=ident,permit_file='/issued/b',now_ms=1999)

    def test_two_releasers_cannot_duplicate_an_occurrence(self):
        ident=self.schedule()
        barrier=threading.Barrier(3)
        results=[]
        def run(idx):
            barrier.wait(timeout=5)
            results.append(release_occurrence(self.db,schedule_id=ident,
                                              permit_file=f'/issued/{idx}',now_ms=1000))
        a=threading.Thread(target=run,args=(1,));b=threading.Thread(target=run,args=(2,))
        a.start();b.start();barrier.wait(timeout=5)
        a.join(timeout=10);b.join(timeout=10)
        self.assertFalse(a.is_alive());self.assertFalse(b.is_alive())
        self.assertEqual(sorted(r['status'] for r in results),['NOT_DUE','RELEASED'])
        self.assertEqual(len(list_jobs(self.db)),1)

    def test_reject_invalid_or_ambiguous_inputs(self):
        invalid=[{'name':'../bad'}, {'every':0}, {'every':True}, {'window':0},
                 {'window':60001}, {'start':True}]
        for case in invalid:
            with self.subTest(case=case),self.assertRaises(ValueError):
                self.schedule(**case)
        ident=self.schedule()
        for invalid_path in ('relative/file','',None):
            with self.subTest(path=invalid_path),self.assertRaises(ValueError):
                release_occurrence(self.db,schedule_id=ident,permit_file=invalid_path,now_ms=1000)

    def test_private_parent_directory_enforced(self):
        parent=Path(self.temp.name)
        os.chmod(parent,0o755)
        self.addCleanup(os.chmod,parent,0o700)
        with self.assertRaises(PermissionError):
            self.schedule()

    def test_cli_create_list_and_skip(self):
        env=os.environ.copy()
        env['PYTHONPATH']=str(Path(__file__).resolve().parents[1]/'src')
        base=[sys.executable,'-m','shards_agent_os','--db',str(self.db)]
        def cmd(*args):
            response=subprocess.run(base+list(args),env=env,text=True,capture_output=True,timeout=10)
            self.assertEqual(response.returncode,0,response.stderr+' '+response.stdout)
            return json.loads(response.stdout)
        created=cmd('schedule-add','--name','test','--every-ms','60000',
                    '--start-at-ms','9999999999999','--window-ms','5000',
                    '--port','8765','--tool','echo','--arguments-json','{"text":"ping"}')
        self.assertEqual(created['status'],'SCHEDULED_UNAUTHORISED')
        self.assertEqual(len(cmd('schedule-list')['schedules']),1)
        self.assertEqual(cmd('schedule-due')['due'],[])
        self.assertFalse(cmd('schedule-disable',created['schedule_id'])['enabled'])
        self.assertTrue(cmd('schedule-enable',created['schedule_id'])['enabled'])


if __name__ == '__main__':
    unittest.main()
